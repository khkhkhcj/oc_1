#pragma once
#include <stddef.h>

void xor_cipher(const unsigned char *src, unsigned char *dst, size_t len, unsigned char key);
void rc4_cipher(const unsigned char *src, unsigned char *dst, size_t len,
                const unsigned char *key, size_t keylen);
