#ifndef SHEMA_H
#define SHEMA_H

#include "appster.h"

#define MAX(a,b) \
   ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _a : _b; })

#define MIN(a,b) \
   ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

typedef struct shema_s shema_t;
typedef struct value_s value_t;

shema_t* sh_alloc(const char* path, const appster_shema_entry_t* entries, as_route_cb_t cb, void* user_data);
void sh_free(shema_t* s);

value_t** sh_parse(shema_t* sh, char* args);
void sh_free_values(shema_t* sh, value_t** val);
int sh_call_cb(shema_t* sh);
const char* sh_get_path(shema_t* sh);

int sh_arg_flag(shema_t* sh, value_t** vals, uint32_t idx);
uint64_t sh_arg_integer(shema_t* sh, value_t** vals, uint32_t idx);
double sh_arg_number(shema_t* sh, value_t** vals, uint32_t idx);
const char* sh_arg_string(shema_t* sh, value_t** vals, uint32_t idx);
uint32_t sh_arg_string_length(shema_t* sh, value_t** vals, uint32_t idx);

uint32_t sh_arg_list_length(shema_t* sh, value_t** vals, uint32_t idx);
uint64_t sh_arg_list_integer(shema_t* sh, value_t** vals, uint32_t idx, uint32_t list_idx);
double sh_arg_list_number(shema_t* sh, value_t** vals, uint32_t idx, uint32_t list_idx);
const char* sh_arg_list_string(shema_t* sh, value_t** vals, uint32_t idx, uint32_t list_idx);
uint32_t sh_arg_list_string_length(shema_t* sh, value_t** vals, uint32_t idx, uint32_t list_idx);

#endif // SHEMA_H
