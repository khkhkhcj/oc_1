#ifndef LIBCAESAR_H
#define LIBCAESAR_H

extern "C" {   
    void set_key(char key);
    void caesar(void* src, void* dst, int len);
}

#endif 