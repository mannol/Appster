#ifndef APPSTER_STUCT_H
#define APPSTER_STUCT_H

#include "vector.h"
#include "hashmap.h"

struct error_cb_s;

struct appster_s {
    hashmap_t* routes;
    hashmap_t* error_cbs;
    vector_t loops;
    struct error_cb_s* general_error_cb;
    vector_t modules;
#ifdef HAS_CRYPTO
    const char* cert_chain_file;
    const char* key_file;
#endif
};

#endif
