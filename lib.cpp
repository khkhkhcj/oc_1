#include "lib.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <sys/mman.h>
#include <unistd.h>

// XOR encrypt/decrypt buffer with key
void xor_cipher(const unsigned char *src, unsigned char *dst, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        dst[i] = src[i] ^ key;
    }
}

// RC4 KSA — инициализация S-блока
static void rc4_init(unsigned char *S, const unsigned char *key, size_t keylen) {
    for (int i = 0; i < 256; i++) S[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) & 0xFF;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
}

// RC4 PRGA — шифрование с защищённым S-блоком
void rc4_cipher(const unsigned char *src, unsigned char *dst, size_t len,
                const unsigned char *key, size_t keylen) {
    long pgsz = sysconf(_SC_PAGESIZE);

    // Выделяем S-блок через mmap — не на стеке
    unsigned char *S = (unsigned char *)mmap(nullptr, pgsz,
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (S == MAP_FAILED) { perror("mmap S-block"); exit(1); }

    // Инициализируем S-блок (KSA)
    rc4_init(S, key, keylen);

    // Шифруем (PRGA)
    int i = 0, j = 0;
    for (size_t n = 0; n < len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        dst[n] = src[n] ^ S[(S[i] + S[j]) & 0xFF];
    }

    // Затираем S-блок нулями перед освобождением
    memset(S, 0, pgsz);
    munmap(S, pgsz);
}
