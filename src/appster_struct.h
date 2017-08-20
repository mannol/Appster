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
#ifndef DISABLE_REDIS
    vector_t redises;
#endif
};

#endif
