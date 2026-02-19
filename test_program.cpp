#include <iostream>
#include <fstream>
#include <dlfcn.h> 
#include <vector>

typedef void (*set_key_func)(char);
typedef void (*caesar_func)(void*, void*, int);

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <lib_path> <key> <input_file> <output_file>\n";
        return 1;
    }

    const char* lib_path = argv[1];
    char key = argv[2][0];
    const char* input_file = argv[3];
    const char* output_file = argv[4];


    void* handle = dlopen(lib_path, RTLD_LAZY);
    if (!handle) {
        std::cerr << "Cannot open library: " << dlerror() << '\n';
        return 1;
    }

    set_key_func set_key = (set_key_func)dlsym(handle, "set_key");
    caesar_func caesar = (caesar_func)dlsym(handle, "caesar");

    if (!set_key || !caesar) {
        std::cerr << "Cannot load functions: " << dlerror() << '\n';
        dlclose(handle);
        return 1;
    }

    std::ifstream fin(input_file, std::ios::binary);
    if (!fin) {
        std::cerr << "Cannot open input file\n";
        dlclose(handle);
        return 1;
    }
    std::vector<unsigned char> buffer((std::istreambuf_iterator<char>(fin)),
                                      std::istreambuf_iterator<char>());
    fin.close();

    set_key(key);

    caesar(buffer.data(), buffer.data(), buffer.size());

    std::ofstream fout(output_file, std::ios::binary);
    fout.write(reinterpret_cast<char*>(buffer.data()), buffer.size());
    fout.close();

    dlclose(handle);
    std::cout << "Done! Output saved to " << output_file << '\n';
    return 0;
}
