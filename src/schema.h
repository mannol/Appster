#ifndef SCHEMA_H
#define SCHEMA_H

#include "appster.h"

#define MAX(a,b) \
   ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a > _b ? _a : _b; })

#define MIN(a,b) \
   ({ __typeof__ (a) _a = (a); __typeof__ (b) _b = (b); _a < _b ? _a : _b; })

typedef struct schema_s schema_t;
typedef struct value_s value_t;

schema_t* sh_alloc(const char* path, const appster_schema_entry_t* entries, as_route_cb_t cb, void* user_data);
void sh_free(schema_t* s);

value_t** sh_parse(schema_t* sh, char* args);
void sh_free_values(schema_t* sh, value_t** val);
int sh_call_cb(schema_t* sh);
const char* sh_get_path(schema_t* sh);

int sh_arg_exists(schema_t* sh, value_t** vals, uint32_t idx);
int sh_arg_flag(schema_t* sh, value_t** vals, uint32_t idx);
uint64_t sh_arg_integer(schema_t* sh, value_t** vals, uint32_t idx);
double sh_arg_number(schema_t* sh, value_t** vals, uint32_t idx);
const char* sh_arg_string(schema_t* sh, value_t** vals, uint32_t idx);
uint32_t sh_arg_string_length(schema_t* sh, value_t** vals, uint32_t idx);

uint32_t sh_arg_list_length(schema_t* sh, value_t** vals, uint32_t idx);
uint64_t sh_arg_list_integer(schema_t* sh, value_t** vals, uint32_t idx, uint32_t list_idx);
double sh_arg_list_number(schema_t* sh, value_t** vals, uint32_t idx, uint32_t list_idx);
const char* sh_arg_list_string(schema_t* sh, value_t** vals, uint32_t idx, uint32_t list_idx);
uint32_t sh_arg_list_string_length(schema_t* sh, value_t** vals, uint32_t idx, uint32_t list_idx);

#endif /* schema_H */
