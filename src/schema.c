#include "schema.h"
#include "hashmap.h"
#include "log.h"
#include "format.h"

typedef value_t* (*parse_cb_t) (const char* raw);

typedef struct string_list_s {
    uint32_t len;
    char* string;
} string_list_t;

struct value_s {
    appster_value_type_t type;
    uint32_t len; // for strings and lists

    union {
        int flag;
        uint64_t integer;
        double number;
        struct {
            int ___;
            char string[];
        };
        struct {
            int ____;
            uint64_t integer_list[];
        };
        struct {
            int _____;
            double number_list[];
        };
        struct {
            string_list_t* string_list;
            char __container[];
        };
    } value;
};

typedef struct argument_s {
    parse_cb_t parse_function;
    uint32_t index;
    uint32_t is_required:1;
} argument_t;

struct schema_s {
    hashmap_t* args;
    uint32_t max_index;
    char* path;
    as_route_cb_t cb;
    void* user_data;
};

static int free_arguments(const void* key, void* value, void* context);
static void free_value(value_t* val);
static int check_arguments(const void* key, void* value, void* context);
static value_t* parse_flag(const char* raw);
static value_t* parse_integer(const char* raw);
static value_t* parse_number(const char* raw);
static value_t* parse_string(const char* raw);
static value_t* parse_encoded_string(const char* raw);
static value_t* parse_integer_list(const char* raw);
static value_t* parse_number_list(const char* raw);
static value_t* parse_string_list(const char* raw);
static value_t* parse_encoded_string_list(const char* raw);

static parse_cb_t p_parse_function[] = {
    parse_flag,
    parse_integer,
    parse_number,
    parse_string,
    parse_encoded_string,
    parse_integer_list,
    parse_number_list,
    parse_string_list,
    parse_encoded_string_list
};

schema_t* sh_alloc(const char* path, const appster_schema_entry_t* entries, as_route_cb_t cb, void* user_data) {
    schema_t* rc;
    argument_t* arg;

    rc = calloc(1, sizeof(schema_t));

    rc->args = hm_alloc(10, NULL, NULL);

    for (unsigned i = 0; entries[i].key; i++) {
        rc->max_index = MAX(entries[i].index, rc->max_index);

        arg = malloc(sizeof(argument_t));
        arg->index = entries[i].index;
        arg->parse_function = p_parse_function[entries[i].type];
        arg->is_required = !!entries[i].is_required;

        free(hm_put(rc->args, entries[i].key, arg));
    }

    rc->max_index ++;
    rc->cb = cb;
    rc->user_data = user_data;
    rc->path = strdup(path);
    return rc;
}
void sh_free(schema_t* s) {
    if (!s) {
        return;
    }

    hm_foreach(s->args, free_arguments, NULL);
    hm_free(s->args);

    free(s->path);
    free(s);
}
value_t** sh_parse(schema_t* sh, char* args) {
    char* it,* s,* t;
    value_t** rc,* value;
    argument_t* arg;

    rc = calloc(sh->max_index, sizeof(value_t*));

    if (args) {
        for (it = strtok_r(args, "&", &s); it; it = strtok_r(NULL, "&", &s)) {
            arg = hm_get(sh->args, strtok_r(it, "=", &t));
            if (!arg) {
                continue;
            }

            value = arg->parse_function(strtok_r(NULL, "", &t));
            if (!value && arg->is_required) {
                DLOG("Missing required value %d", arg->index);
                goto fail;
            }

            free_value(rc[arg->index]); // no duplicates!
            rc[arg->index] = value;
        }
    }

    // check required items
    if (!hm_foreach(sh->args, check_arguments, rc))
        goto fail;

    return rc;

fail:
    sh_free_values(sh, rc);
    return NULL;
}
void sh_free_values(schema_t* sh, value_t** val) {
    if (!val) {
        return;
    }

    for (uint32_t i = 0; i < sh->max_index; i++) {
        free_value(val[i]);
    }

    free(val);
}
int sh_call_cb(schema_t* sh) {
    return sh->cb(sh->user_data);
}
const char* sh_get_path(schema_t* sh) {
    return sh->path;
}
int sh_arg_flag(schema_t* sh, value_t** vals, uint32_t idx) {
    lassert(sh->max_index >= idx);
    if (vals[idx]) {
        lassert(vals[idx]->type == AVT_FLAG);
        return vals[idx]->value.flag;
    }
    return 0;
}
uint64_t sh_arg_integer(schema_t* sh, value_t** vals, uint32_t idx) {
    lassert(sh->max_index >= idx);
    if (vals[idx]) {
        lassert(vals[idx]->type == AVT_INTEGER);
        return vals[idx]->value.integer;
    }
    return 0;
}
double sh_arg_number(schema_t* sh, value_t** vals, uint32_t idx) {
    lassert(sh->max_index >= idx);
    if (vals[idx]) {
        lassert(vals[idx]->type == AVT_NUMBER);
        return vals[idx]->value.number;
    }
    return 0;
}
const char* sh_arg_string(schema_t* sh, value_t** vals, uint32_t idx) {
    lassert(sh->max_index >= idx);
    if (vals[idx]) {
        lassert(vals[idx]->type == AVT_STRING);
        return vals[idx]->value.string;
    }
    return 0;
}
uint32_t sh_arg_string_length(schema_t* sh, value_t** vals, uint32_t idx) {
    lassert(sh->max_index >= idx);
    if (vals[idx]) {
        lassert(vals[idx]->type == AVT_STRING);
        return vals[idx]->len;
    }
    return 0;
}
uint32_t sh_arg_list_length(schema_t* sh, value_t** vals, uint32_t idx) {
    lassert(sh->max_index >= idx);
    if (vals[idx]) {
        lassert(vals[idx]->type > AVT_STRING);
        return vals[idx]->len;
    }
    return 0;
}
uint64_t sh_arg_list_integer(schema_t* sh, value_t** vals, uint32_t idx, uint32_t list_idx) {
    lassert(sh->max_index >= idx);
    if (vals[idx]) {
        lassert(vals[idx]->type == AVT_INTEGER_LIST);
        lassert(vals[idx]->len > list_idx);
        return vals[idx]->value.integer_list[list_idx];
    }
    return 0;
}
double sh_arg_list_number(schema_t* sh, value_t** vals, uint32_t idx, uint32_t list_idx) {
    lassert(sh->max_index >= idx);
    if (vals[idx]) {
        lassert(vals[idx]->type == AVT_NUMBER_LIST);
        lassert(vals[idx]->len > list_idx);
        return vals[idx]->value.number_list[list_idx];
    }
    return 0;
}
const char* sh_arg_list_string(schema_t* sh, value_t** vals, uint32_t idx, uint32_t list_idx) {
    lassert(sh->max_index >= idx);
    if (vals[idx]) {
        lassert(vals[idx]->type == AVT_STRING_LIST);
        lassert(vals[idx]->len > list_idx);
        return vals[idx]->value.string_list[list_idx].string;
    }
    return 0;
}
uint32_t sh_arg_list_string_length(schema_t* sh, value_t** vals, uint32_t idx, uint32_t list_idx) {
    lassert(sh->max_index >= idx);
    if (vals[idx]) {
        lassert(vals[idx]->type == AVT_STRING_LIST);
        lassert(vals[idx]->len > list_idx);
        return vals[idx]->value.string_list[list_idx].len;
    }
    return 0;
}

int free_arguments(const void* key, void* value, void* context) {
    free(value);
    return 1;
}
void free_value(value_t* val) {
    if (!val) {
        return;
    }

    if (val->type == AVT_STRING_LIST)
        free(val->value.string_list);
    free(val);
}
int check_arguments(const void* key, void* value, void* context) {
    value_t** vals;
    argument_t* arg;

    vals = context;
    arg = value;

    if (arg->is_required && !vals[arg->index]) {
        return 0;
    }
    return 1;
}
value_t* parse_flag(const char* raw) {
    int is = 0, len;
    value_t* rc;

    if (!raw || !(len = strlen(raw))) {
        is = 1;
    } else if (len == 2) {
        is = strncasecmp(raw, "on", 2) == 0;
    } else if (len == 3) {
        is = strncasecmp(raw, "off", 3) == 0;
    } else {
        return NULL;
    }

    rc = malloc(sizeof(value_t));
    rc->value.flag = is;
    rc->len = 0;
    rc->type = AVT_FLAG;
    return rc;
}
value_t* parse_integer(const char* raw) {
    uint64_t i = 0;
    value_t* rc;
    char* end;

    if (!raw || !strlen(raw)) {
        return NULL;
    }

    i = strtoull(raw, &end, 10);

    if (end && *end) {
        return NULL;
    }

    rc = malloc(sizeof(value_t));
    rc->value.integer = i;
    rc->len = 0;
    rc->type = AVT_INTEGER;
    return rc;
}
value_t* parse_number(const char* raw) {
    double n = 0;
    value_t* rc;
    char* end;

    if (!raw || !strlen(raw)) {
        return NULL;
    }

    n = strtod(raw, &end);

    if (end && *end) {
        return NULL;
    }

    rc = malloc(sizeof(value_t));
    rc->value.number = n;
    rc->len = 0;
    rc->type = AVT_NUMBER;
    return rc;
}
value_t* parse_string(const char* raw) {
    int len;
    value_t* rc;

    if (!raw || !(len = strlen(raw))) {
        return NULL;
    }

    len ++; // \0

    rc = malloc(sizeof(value_t) + len);
    rc->len = len;
    rc->type = AVT_STRING;
    memcpy(rc->value.string, raw, len);
    return rc;
}
value_t* parse_encoded_string(const char* raw) {
    int len;
    value_t* rc;

    if (!raw || !(len = strlen(raw))) {
        return NULL;
    }

    len = base64_decoded_len(raw, len) + 1;

    rc = malloc(sizeof(value_t) + len);
    rc->len = len;
    rc->type = AVT_STRING;
    from_base64(raw, rc->value.string);
    return rc;
}
value_t* parse_integer_list(const char* raw) {
    int len, total = 0;
    value_t* rc;
    uint64_t i[4096];
    const char *r = raw;
    char* end;

    if (!raw || !(len = strlen(raw))) {
        return NULL;
    }

    do {
        i[total++] = strtoull(r, &end, 10);

        if (end && *end && *end != ';') {
            return NULL;
        }

        r = end;
    } while (r && *(r++));

    rc = malloc(sizeof(value_t) + (total * sizeof(uint64_t)));
    rc->len = total;
    rc->type = AVT_INTEGER_LIST;
    memcpy(rc->value.integer_list, i, total * sizeof(uint64_t));
    return rc;
}
value_t* parse_number_list(const char* raw) {
    int len, total = 0;
    value_t* rc;
    double n[4096];
    const char *r = raw;
    char* end;

    if (!raw || !(len = strlen(raw))) {
        return NULL;
    }

    do {
        n[total++] = strtod(r, &end);

        if (end && *end && *end != ';') {
            return NULL;
        }

        r = end;
    } while (r && *(r++));

    rc = malloc(sizeof(value_t) + (total * sizeof(double)));
    rc->len = total;
    rc->type = AVT_NUMBER_LIST;
    memcpy(rc->value.number_list, n, total * sizeof(double));
    return rc;
}
value_t* parse_string_list(const char* raw) {
    // TODO verify if this works nicely
    int len, total = 0, count = 0;
    value_t* rc;
    char dec[8192];
    uint32_t lens[4096];

    if (!raw || !(len = strlen(raw))) {
        return NULL;
    }

    memcpy(dec, raw, len);

    do {
        len = 0;
        while(raw[len] && raw[len] != ';') ++len;

        if (!len) {
            return NULL;
        }

        lens[count] = len;
        total += lens[count] + 1;
        dec[total - 1] = 0;
        count ++;

        if (*raw)
            raw += len + (raw[len] == ';' ? 1 : 0);
    } while (raw && *raw);

    if (!count) { // shouldn't happen?
        return NULL;
    }

    rc = malloc(sizeof(value_t) + total);
    rc->len = count;
    rc->type = AVT_STRING_LIST;
    rc->value.string_list = malloc(sizeof(string_list_t) * count);
    memcpy(rc->value.__container, dec, total);

    rc->value.string_list[0].len = lens[0];
    rc->value.string_list[0].string = rc->value.__container;
    for (int i = 1; i < count; i++) {
        rc->value.string_list[i].len = lens[i];
        rc->value.string_list[i].string =
                rc->value.string_list[i - 1].string +
                rc->value.string_list[i - 1].len + 1;
    }

    return rc;
}
value_t* parse_encoded_string_list(const char* raw) {
    int len, total = 0, count = 0;
    value_t* rc;
    char dec[8192];
    uint32_t lens[4096];

    if (!raw || !(len = strlen(raw))) {
        return NULL;
    }

    do {
        len = 0;
        while(raw[len] && raw[len] != ';') ++len;

        if (!len) {
            return NULL;
        }

        lens[count] = from_base64(raw, dec + total);
        total += lens[count] + 1;
        count ++;

        if (*raw)
            raw += len + (raw[len] == ';' ? 1 : 0);
    } while (raw && *raw);

    if (!count) { // shouldn't happen?
        return NULL;
    }

    rc = malloc(sizeof(value_t) + total);
    rc->len = count;
    rc->type = AVT_STRING_LIST;
    rc->value.string_list = malloc(sizeof(string_list_t) * count);
    memcpy(rc->value.__container, dec, total);

    rc->value.string_list[0].len = lens[0];
    rc->value.string_list[0].string = rc->value.__container;
    for (int i = 1; i < count; i++) {
        rc->value.string_list[i].len = lens[i];
        rc->value.string_list[i].string =
                rc->value.string_list[i - 1].string +
                rc->value.string_list[i - 1].len + 1;
    }

    return rc;
}
