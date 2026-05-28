#include "lib.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>

// XOR encrypt/decrypt buffer with key
void xor_cipher(const unsigned char *src, unsigned char *dst, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        dst[i] = src[i] ^ key;
    }
}

// RC4 KSA+PRGA
static void rc4_init(unsigned char *S, const unsigned char *key, size_t keylen) {
    for (int i = 0; i < 256; i++) S[i] = (unsigned char)i;
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) & 0xFF;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
}

void rc4_cipher(const unsigned char *src, unsigned char *dst, size_t len,
                const unsigned char *key, size_t keylen) {
    unsigned char S[256];
    rc4_init(S, key, keylen);
    int i = 0, j = 0;
    for (size_t n = 0; n < len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        dst[n] = src[n] ^ S[(S[i] + S[j]) & 0xFF];
    }
}
