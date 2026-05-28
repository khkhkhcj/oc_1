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
#include "lib.h"

#ifndef WORKERS_COUNT
#define WORKERS_COUNT 4
#endif

// ─── Secure key (mmap + mprotect) ────────────────────────────────────────────

static void *g_key_page = MAP_FAILED;
static size_t g_key_len  = 0;

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
    mprotect(g_key_page, pgsz, PROT_READ);
    fn(static_cast<const unsigned char *>(g_key_page), g_key_len);
    mprotect(g_key_page, pgsz, PROT_NONE);
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

// ─── Main ─────────────────────────────────────────────────────────────────────

int main(int argc, char *argv[]) {
    // Usage: secure_copy [--mode=sequential|parallel|auto] <key> <out_dir> <file> ...
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
