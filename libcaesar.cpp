#include "libcaesar.h"

static char g_key = 0;


void set_key(char key) {
    g_key = key;
}


void caesar(void* src, void* dst, int len) {
    unsigned char* s = static_cast<unsigned char*>(src);
    unsigned char* d = static_cast<unsigned char*>(dst);

    for (int i = 0; i < len; i++) {
        d[i] = s[i] ^ g_key;  
    }
}
