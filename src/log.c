#include "log.h"

static FILE* log_file = NULL;
__thread char __log_str[65536];

void __log_func(const char* name, const char* fname, int line, const char* func, const char* msg) {
    if (!log_file)
        return;

    fprintf(log_file, "%s:   %s:%d %s()  %s\n", name, fname, line, func, msg);
    fflush(log_file);
}

void __log_set_file(FILE* file) {
    log_file = file;
}

int __log_enabled() {
    return !!log_file;
}
