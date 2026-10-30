#define _GNU_SOURCE
#include <dlfcn.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char exe[PATH_MAX];
    ssize_t length = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (length <= 0) {
        fprintf(stderr, "libmeowcore: cannot resolve executable path\n");
        return 127;
    }
    exe[length] = '\0';
    char *slash = strrchr(exe, '/');
    if (slash == NULL) {
        fprintf(stderr, "libmeowcore: invalid executable path\n");
        return 127;
    }
    strcpy(slash + 1, "libmeow.so");

    void *library = dlopen(exe, RTLD_NOW | RTLD_GLOBAL);
    if (library == NULL) {
        library = dlopen("libmeow.so", RTLD_NOW | RTLD_GLOBAL);
    }
    if (library == NULL) {
        fprintf(stderr, "libmeowcore: cannot load libmeow.so: %s\n", dlerror());
        return 127;
    }
    int (*entry)(int, char **) = (int (*)(int, char **))dlsym(library, "meow_cli_main");
    if (entry == NULL) {
        fprintf(stderr, "libmeowcore: libmeow.so has no meow_cli_main\n");
        return 127;
    }
    return entry(argc, argv);
}
