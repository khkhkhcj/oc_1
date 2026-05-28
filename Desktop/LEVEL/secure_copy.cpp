#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <pthread.h>
#include <errno.h>
#include "lib.h"

// ─── Logging ────────────────────────────────────────────────────────────────

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

// ─── Shared resource (output directory mutex) ────────────────────────────────

static pthread_mutex_t g_copy_mutex = PTHREAD_MUTEX_INITIALIZER;

// ─── Per-task data ───────────────────────────────────────────────────────────

struct CopyTask {
    std::string src;
    std::string dst;
    unsigned char key;
    int result;   // 0 = ok, -1 = error
};

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

// ─── Worker thread ───────────────────────────────────────────────────────────

static void *worker(void *arg) {
    CopyTask *task = static_cast<CopyTask *>(arg);

    char msg[512];
    snprintf(msg, sizeof(msg), "START  %s -> %s", task->src.c_str(), task->dst.c_str());
    log_msg(msg);

    std::vector<unsigned char> buf;
    if (!read_file(task->src, buf)) {
        snprintf(msg, sizeof(msg), "ERROR  cannot read %s", task->src.c_str());
        log_msg(msg);
        task->result = -1;
        return nullptr;
    }

    std::vector<unsigned char> enc(buf.size());
    xor_cipher(buf.data(), enc.data(), buf.size(), task->key);

    // mutex with timeout (trylock loop) to prevent deadlock
    {
        struct timespec deadline;
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec += 5;

        bool locked = false;
        while (true) {
            if (pthread_mutex_trylock(&g_copy_mutex) == 0) { locked = true; break; }
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > deadline.tv_sec ||
                (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) break;
            struct timespec sl = {0, 5000000}; // 5ms
            nanosleep(&sl, nullptr);
        }
        if (!locked) {
            snprintf(msg, sizeof(msg), "ERROR  mutex timeout for %s", task->src.c_str());
            log_msg(msg);
            task->result = -1;
            return nullptr;
        }
    }

    bool ok = write_file(task->dst, enc);
    pthread_mutex_unlock(&g_copy_mutex);

    if (!ok) {
        snprintf(msg, sizeof(msg), "ERROR  cannot write %s", task->dst.c_str());
        log_msg(msg);
        task->result = -1;
        return nullptr;
    }

    snprintf(msg, sizeof(msg), "DONE   %s -> %s (%zu bytes)", task->src.c_str(), task->dst.c_str(), buf.size());
    log_msg(msg);
    task->result = 0;
    return nullptr;
}

// ─── Practice 3 entry point ──────────────────────────────────────────────────

static int run_practice3(int argc, char *argv[]) {
    // Usage: secure_copy <key_char> <out_dir> <file1> [file2 ...]
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <key_char> <out_dir> <file1> [file2 ...]\n";
        return 1;
    }

    unsigned char key = (unsigned char)argv[1][0];
    std::string out_dir = argv[2];

    g_log_file = fopen("secure_copy.log", "a");

    int nfiles = argc - 3;
    std::vector<CopyTask> tasks(nfiles);
    std::vector<pthread_t> threads(nfiles);

    for (int i = 0; i < nfiles; i++) {
        std::string src = argv[3 + i];
        std::string fname = src.substr(src.find_last_of("/\\") + 1);
        tasks[i] = {src, out_dir + "/" + fname + ".enc", key, 0};
        pthread_create(&threads[i], nullptr, worker, &tasks[i]);
    }

    for (int i = 0; i < nfiles; i++) {
        pthread_join(threads[i], nullptr);
    }

    int errors = 0;
    for (int i = 0; i < nfiles; i++) {
        if (tasks[i].result != 0) errors++;
    }

    char msg[128];
    snprintf(msg, sizeof(msg), "FINISH  %d/%d files OK", nfiles - errors, nfiles);
    log_msg(msg);

    if (g_log_file) fclose(g_log_file);
    return errors > 0 ? 1 : 0;
}

int main(int argc, char *argv[]) {
    return run_practice3(argc, argv);
}
