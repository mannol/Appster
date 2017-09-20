#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <string.h>

#undef DLOG
#undef ELOG
#undef FLOG

void __log_func(const char* name, const char* fname, int line, const char* func, const char* msg);
void __log_set_file(FILE* file);
int __log_enabled();

extern __thread char __log_str[65536];

#define lassert(expr) \
    do { \
        if (!(expr)) { \
            ELOG("Assert (%s) failed!", #expr); \
            abort(); \
        } \
    } while(0)

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

#define DLOG(args...) \
    do { \
        if (!__log_enabled()) \
            break; \
        snprintf(__log_str, 65535, args); \
        __log_str[65535] = 0; \
        __log_func("DEBUG", __FILENAME__, __LINE__, __func__, __log_str); \
    } while(0)
#define ELOG(args...) \
    do { \
        if (!__log_enabled()) \
            break; \
        snprintf(__log_str, 65535, args); \
        __log_str[65535] = 0; \
        __log_func("ERROR", __FILENAME__, __LINE__, __func__, __log_str); \
    } while(0)
#define FLOG(args...) \
    do { \
        fprintf (stderr, "FATAL ERROR on %s:%d IN %s()  ", __func__, \
                    __LINE__,  __func__); \
        fprintf (stderr, args); \
        fprintf (stderr, "\n"); \
        if (__log_enabled()) { \
            snprintf(__log_str, 65535, args); \
            __log_str[65535] = 0; \
            __log_func("FATAL", __FILENAME__, __LINE__, __func__, __log_str); \
        } \
        exit(1); \
    } while(0)

#endif /* LOG_H */
