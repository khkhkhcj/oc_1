#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <pthread.h>
#include <errno.h>
#include <algorithm>
#include <functional>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include "lib.h"

#ifndef WORKERS_COUNT
#define WORKERS_COUNT 4
#endif

// ─── Secure key (mmap + mprotect) ────────────────────────────────────────────

static void *g_key_page = MAP_FAILED;
static size_t g_key_len  = 0;
static pthread_mutex_t g_key_mutex = PTHREAD_MUTEX_INITIALIZER;

static void sigsegv_handler(int, siginfo_t *, void *) {
    const char *m = "\n[SECURITY] Illegal write to protected key memory. Aborting.\n";
    write(STDERR_FILENO, m, strlen(m));
    _exit(2);
}

static void key_init(const char *key) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigsegv_handler;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, nullptr);

    long pgsz = sysconf(_SC_PAGESIZE);
    g_key_len  = strlen(key);
    g_key_page = mmap(nullptr, pgsz, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_key_page == MAP_FAILED) { perror("mmap"); exit(1); }
    memcpy(g_key_page, key, g_key_len);
    mprotect(g_key_page, pgsz, PROT_NONE);
}

static void key_use(std::function<void(const unsigned char *, size_t)> fn) {
    long pgsz = sysconf(_SC_PAGESIZE);
    pthread_mutex_lock(&g_key_mutex);
    mprotect(g_key_page, pgsz, PROT_READ);
    fn(static_cast<const unsigned char *>(g_key_page), g_key_len);
    mprotect(g_key_page, pgsz, PROT_NONE);
    pthread_mutex_unlock(&g_key_mutex);
}

static void key_destroy() {
    if (g_key_page == MAP_FAILED) return;
    long pgsz = sysconf(_SC_PAGESIZE);
    mprotect(g_key_page, pgsz, PROT_READ | PROT_WRITE);
    memset(g_key_page, 0, pgsz);
    munmap(g_key_page, pgsz);
    g_key_page = MAP_FAILED;
}

// ─── Logging ─────────────────────────────────────────────────────────────────

static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;
static FILE *g_log_file = nullptr;

static void log_msg(const char *msg) {
    time_t now = time(nullptr);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    pthread_mutex_lock(&g_log_mutex);
    if (g_log_file) fprintf(g_log_file, "[%s] %s\n", ts, msg);
    fprintf(stdout, "[%s] %s\n", ts, msg);
    pthread_mutex_unlock(&g_log_mutex);
}

// ─── Mutex with timeout ───────────────────────────────────────────────────────

static pthread_mutex_t g_copy_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool mutex_lock_timeout(pthread_mutex_t *m, int sec) {
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += sec;
    while (true) {
        if (pthread_mutex_trylock(m) == 0) return true;
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec > deadline.tv_sec ||
            (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec))
            return false;
        struct timespec sl = {0, 5000000};
        nanosleep(&sl, nullptr);
    }
}

// ─── File helpers ─────────────────────────────────────────────────────────────

static bool read_file(const std::string &path, std::vector<unsigned char> &buf) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    buf.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return true;
}

static bool write_file(const std::string &path, const std::vector<unsigned char> &buf) {
    std::ofstream f(path, std::ios::binary);
    if (!f) return false;
    f.write(reinterpret_cast<const char *>(buf.data()), buf.size());
    return true;
}

// ─── CopyTask ─────────────────────────────────────────────────────────────────

struct CopyTask {
    std::string src;
    std::string dst;
    int result;
    double duration_ms;
};

static void process_task(CopyTask *task) {
    char msg[512];
    snprintf(msg, sizeof(msg), "START  %s -> %s", task->src.c_str(), task->dst.c_str());
    log_msg(msg);

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    std::vector<unsigned char> buf;
    if (!read_file(task->src, buf)) {
        snprintf(msg, sizeof(msg), "ERROR  cannot read %s", task->src.c_str());
        log_msg(msg);
        task->result = -1;
        return;
    }

    std::vector<unsigned char> enc(buf.size());
    key_use([&](const unsigned char *k, size_t klen) {
        xor_cipher(buf.data(), enc.data(), buf.size(), k[0]);
        (void)klen;
    });

    if (!mutex_lock_timeout(&g_copy_mutex, 5)) {
        snprintf(msg, sizeof(msg), "ERROR  mutex timeout %s", task->src.c_str());
        log_msg(msg);
        task->result = -1;
        return;
    }
    bool ok = write_file(task->dst, enc);
    pthread_mutex_unlock(&g_copy_mutex);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    task->duration_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6;

    if (!ok) {
        snprintf(msg, sizeof(msg), "ERROR  cannot write %s", task->dst.c_str());
        log_msg(msg);
        task->result = -1;
        return;
    }

    snprintf(msg, sizeof(msg), "DONE   %s (%.1f ms, %zu bytes)",
             task->src.c_str(), task->duration_ms, buf.size());
    log_msg(msg);
    task->result = 0;
}

// ─── Sequential mode ──────────────────────────────────────────────────────────

static void run_sequential(std::vector<CopyTask> &tasks) {
    for (auto &t : tasks) process_task(&t);
}

// ─── Parallel mode (thread pool) ─────────────────────────────────────────────

struct Queue {
    std::vector<CopyTask *> items;
    size_t head = 0;
    pthread_mutex_t mu;
    pthread_cond_t  cv;
    bool done = false;
};

static void *pool_worker(void *arg) {
    Queue *q = static_cast<Queue *>(arg);
    while (true) {
        pthread_mutex_lock(&q->mu);
        while (q->head >= q->items.size() && !q->done)
            pthread_cond_wait(&q->cv, &q->mu);
        if (q->head >= q->items.size()) {
            pthread_mutex_unlock(&q->mu);
            break;
        }
        CopyTask *task = q->items[q->head++];
        pthread_mutex_unlock(&q->mu);
        process_task(task);
    }
    return nullptr;
}

static void run_parallel(std::vector<CopyTask> &tasks) {
    Queue q;
    pthread_mutex_init(&q.mu, nullptr);
    pthread_cond_init(&q.cv, nullptr);
    for (auto &t : tasks) q.items.push_back(&t);

    int n = (int)tasks.size() < WORKERS_COUNT ? (int)tasks.size() : WORKERS_COUNT;
    std::vector<pthread_t> workers(n);
    for (int i = 0; i < n; i++)
        pthread_create(&workers[i], nullptr, pool_worker, &q);

    pthread_mutex_lock(&q.mu);
    q.done = true;
    pthread_cond_broadcast(&q.cv);
    pthread_mutex_unlock(&q.mu);

    for (int i = 0; i < n; i++) pthread_join(workers[i], nullptr);
    pthread_mutex_destroy(&q.mu);
    pthread_cond_destroy(&q.cv);
}

// ─── Statistics ───────────────────────────────────────────────────────────────

static void print_stats(const char *mode, const std::vector<CopyTask> &tasks, double total_ms) {
    double sum = 0;
    int ok = 0;
    for (auto &t : tasks) { if (t.result == 0) { sum += t.duration_ms; ok++; } }
    printf("\n=== Statistics [%s] ===\n", mode);
    printf("  Files processed : %d / %zu\n", ok, tasks.size());
    printf("  Total time      : %.3f ms\n", total_ms);
    printf("  Avg per file    : %.3f ms\n", ok > 0 ? sum / ok : 0.0);
    printf("========================\n\n");
}

// ─── Image (practice 6) ───────────────────────────────────────────────────────

#pragma pack(push, 1)
struct ImageRecord {
    uint32_t file_len;
    uint32_t name_len;
    uint8_t  salt[16];
};
#pragma pack(pop)

static void gen_salt(uint8_t *salt, size_t n) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t seed = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec
                  + (uint64_t)(uintptr_t)salt;
    for (size_t i = 0; i < n; i++) {
        seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17;
        salt[i] = (uint8_t)(seed & 0xFF);
    }
}

static void collect_files(const std::string &real, const std::string &virt,
                           std::vector<std::pair<std::string,std::string>> &out) {
    struct stat st;
    if (stat(real.c_str(), &st) != 0) { perror(real.c_str()); return; }
    if (S_ISREG(st.st_mode)) { out.push_back({real, virt}); return; }
    if (!S_ISDIR(st.st_mode)) return;
    DIR *d = opendir(real.c_str());
    if (!d) { perror(real.c_str()); return; }
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name,".") == 0 || strcmp(e->d_name,"..") == 0) continue;
        collect_files(real + "/" + e->d_name, virt + "/" + e->d_name, out);
    }
    closedir(d);
}

struct AddTask {
    std::string real_path;
    std::string virt_name;
    std::vector<unsigned char> encrypted;
    uint8_t salt[16];
    int result;
};

static void *add_worker(void *arg) {
    AddTask *t = static_cast<AddTask *>(arg);
    std::vector<unsigned char> buf;
    if (!read_file(t->real_path, buf)) { t->result = -1; return nullptr; }

    gen_salt(t->salt, 16);

    std::vector<unsigned char> composed;
    key_use([&](const unsigned char *k, size_t klen) {
        composed.insert(composed.end(), k, k + klen);
    });
    composed.insert(composed.end(), t->salt, t->salt + 16);

    t->encrypted.resize(buf.size());
    rc4_cipher(buf.data(), t->encrypted.data(), buf.size(),
               composed.data(), composed.size());
    t->result = 0;
    return nullptr;
}

static int cmd_add(const std::string &img_path, const std::vector<std::string> &inputs) {
    std::vector<std::pair<std::string,std::string>> files;
    for (auto &inp : inputs) {
        struct stat st;
        if (stat(inp.c_str(), &st) != 0) { perror(inp.c_str()); continue; }
        std::string base = inp;
        if (base.back() == '/') base.pop_back();
        size_t p = base.find_last_of("/\\");
        std::string bname = (p == std::string::npos) ? base : base.substr(p+1);
        if (S_ISDIR(st.st_mode)) collect_files(inp, "/" + bname, files);
        else files.push_back({inp, "/" + bname});
    }
    if (files.empty()) { fprintf(stderr, "No files to add\n"); return 1; }

    std::vector<AddTask> tasks(files.size());
    for (size_t i = 0; i < files.size(); i++) {
        tasks[i].real_path = files[i].first;
        tasks[i].virt_name = files[i].second;
        tasks[i].result    = 0;
    }

    // parallel encrypt, max 5 threads
    size_t idx = 0;
    while (idx < tasks.size()) {
        int batch = (int)(tasks.size() - idx) < 5 ? (int)(tasks.size() - idx) : 5;
        std::vector<pthread_t> th(batch);
        for (int i = 0; i < batch; i++)
            pthread_create(&th[i], nullptr, add_worker, &tasks[idx+i]);
        for (int i = 0; i < batch; i++) pthread_join(th[i], nullptr);
        idx += batch;
    }

    FILE *img = fopen(img_path.c_str(), "ab");
    if (!img) { perror(img_path.c_str()); return 1; }
    for (auto &t : tasks) {
        if (t.result != 0) { fprintf(stderr, "Skip: %s\n", t.real_path.c_str()); continue; }
        ImageRecord rec;
        rec.file_len = (uint32_t)t.encrypted.size();
        rec.name_len = (uint32_t)t.virt_name.size();
        memcpy(rec.salt, t.salt, 16);
        fwrite(&rec, sizeof(rec), 1, img);
        fwrite(t.virt_name.c_str(), 1, rec.name_len, img);
        fwrite(t.encrypted.data(), 1, rec.file_len, img);
        printf("  added: %s (%u bytes)\n", t.virt_name.c_str(), rec.file_len);
    }
    fclose(img);
    return 0;
}

static int cmd_list(const std::string &img_path) {
    FILE *img = fopen(img_path.c_str(), "rb");
    if (!img) { perror(img_path.c_str()); return 1; }
    struct Entry { std::string name; uint32_t size; };
    std::vector<Entry> entries;
    ImageRecord rec;
    while (fread(&rec, sizeof(rec), 1, img) == 1) {
        std::string name(rec.name_len, '\0');
        if (fread(&name[0], 1, rec.name_len, img) != rec.name_len) break;
        fseek(img, rec.file_len, SEEK_CUR);
        entries.push_back({name, rec.file_len});
    }
    fclose(img);
    std::sort(entries.begin(), entries.end(),
              [](const Entry &a, const Entry &b){ return a.name < b.name; });
    printf("%-50s  %10s\n", "Name", "Size");
    printf("%-50s  %10s\n", std::string(50,'-').c_str(), "----------");
    for (auto &e : entries) printf("%-50s  %10u\n", e.name.c_str(), e.size);
    return 0;
}

static int cmd_get(const std::string &img_path, const std::string &file_name,
                   const std::string &out_path) {
    FILE *img = fopen(img_path.c_str(), "rb");
    if (!img) { perror(img_path.c_str()); return 1; }
    ImageRecord rec;
    while (fread(&rec, sizeof(rec), 1, img) == 1) {
        std::string name(rec.name_len, '\0');
        if (fread(&name[0], 1, rec.name_len, img) != rec.name_len) break;
        if (name != file_name) { fseek(img, rec.file_len, SEEK_CUR); continue; }
        std::vector<unsigned char> enc(rec.file_len);
        if (fread(enc.data(), 1, rec.file_len, img) != rec.file_len) break;
        fclose(img);

        std::vector<unsigned char> composed;
        key_use([&](const unsigned char *k, size_t klen) {
            composed.insert(composed.end(), k, k + klen);
        });
        composed.insert(composed.end(), rec.salt, rec.salt + 16);

        std::vector<unsigned char> dec(rec.file_len);
        rc4_cipher(enc.data(), dec.data(), rec.file_len,
                   composed.data(), composed.size());
        if (!write_file(out_path, dec)) { perror(out_path.c_str()); return 1; }
        printf("Saved to %s\n", out_path.c_str());
        return 0;
    }
    fclose(img);
    fprintf(stderr, "File '%s' not found in image\n", file_name.c_str());
    return 1;
}

static std::string get_arg(int argc, char *argv[], const char *name) {
    for (int i = 1; i < argc - 1; i++)
        if (strcmp(argv[i], name) == 0) return argv[i+1];
    return "";
}

static bool has_flag(int argc, char *argv[], const char *name) {
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], name) == 0) return true;
    return false;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char *argv[]) {
    // image mode
    if (has_flag(argc, argv, "-add") || has_flag(argc, argv, "-list") ||
        has_flag(argc, argv, "-get")) {
        std::string img_path = get_arg(argc, argv, "-image");
        if (img_path.empty()) { fprintf(stderr, "-image required\n"); return 1; }

        if (has_flag(argc, argv, "-list")) return cmd_list(img_path);

        std::string key_str = get_arg(argc, argv, "-key");
        if (key_str.empty()) { fprintf(stderr, "-key required\n"); return 1; }
        key_init(key_str.c_str());

        int rc = 0;
        if (has_flag(argc, argv, "-add")) {
            std::vector<std::string> inputs;
            for (int i = 1; i < argc; i++) {
                if (strcmp(argv[i],"-add")==0 || strcmp(argv[i],"-list")==0 ||
                    strcmp(argv[i],"-get")==0) continue;
                if (strcmp(argv[i],"-image")==0 || strcmp(argv[i],"-key")==0 ||
                    strcmp(argv[i],"-out")==0) { i++; continue; }
                inputs.push_back(argv[i]);
            }
            rc = cmd_add(img_path, inputs);
        } else {
            std::string out_path = get_arg(argc, argv, "-out");
            std::string fname    = argv[argc-1];
            if (out_path.empty() || fname.empty()) {
                fprintf(stderr, "Usage: -get -image img -key k -out result filename\n");
                key_destroy(); return 1;
            }
            rc = cmd_get(img_path, fname, out_path);
        }
        key_destroy();
        return rc;
    }

    // copy mode
    if (argc < 4) {
        fprintf(stderr,
            "Usage: %s [--mode=sequential|parallel|auto] <key> <out_dir> <file> ...\n",
            argv[0]);
        return 1;
    }

    int file_start = 1;
    enum Mode { AUTO, SEQ, PAR } mode = AUTO;
    if (strncmp(argv[1], "--mode=", 7) == 0) {
        const char *m = argv[1] + 7;
        if      (strcmp(m, "sequential") == 0) mode = SEQ;
        else if (strcmp(m, "parallel")   == 0) mode = PAR;
        else                                    mode = AUTO;
        file_start = 2;
    }

    if (argc < file_start + 3) {
        fprintf(stderr, "Need <key> <out_dir> <file> ...\n"); return 1;
    }

    const char *key_str = argv[file_start];
    std::string out_dir = argv[file_start + 1];
    int nfiles = argc - file_start - 2;

    key_init(key_str);
    g_log_file = fopen("secure_copy.log", "a");

    std::vector<CopyTask> tasks(nfiles);
    for (int i = 0; i < nfiles; i++) {
        std::string src = argv[file_start + 2 + i];
        std::string fname = src.substr(src.find_last_of("/\\") + 1);
        tasks[i] = {src, out_dir + "/" + fname + ".enc", 0, 0.0};
    }

    // auto-select: <5 files -> sequential, >=5 -> parallel
    if (mode == AUTO) mode = (nfiles < 5) ? SEQ : PAR;

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    bool is_seq = (mode == SEQ);
    log_msg(is_seq ? "Mode: sequential" : "Mode: parallel");

    if (is_seq) run_sequential(tasks);
    else        run_parallel(tasks);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double total_ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6;

    print_stats(is_seq ? "sequential" : "parallel", tasks, total_ms);

    // comparison estimate for auto mode
    {
        const char *alt = is_seq ? "parallel (estimate)" : "sequential (estimate)";
        double alt_ms  = is_seq ? total_ms / WORKERS_COUNT : total_ms * WORKERS_COUNT;
        printf("=== Alternative [%s] ===\n", alt);
        printf("  Estimated time  : %.3f ms\n\n", alt_ms);
    }

    int errors = 0;
    for (auto &t : tasks) if (t.result != 0) errors++;
    char msg[64];
    snprintf(msg, sizeof(msg), "FINISH %d/%d OK", nfiles - errors, nfiles);
    log_msg(msg);

    if (g_log_file) fclose(g_log_file);
    key_destroy();
    return errors > 0 ? 1 : 0;
}
