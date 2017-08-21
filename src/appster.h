#ifndef APPSTER_H
#define APPSTER_H

#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>

#define AS_REQUIRED 1
#define AS_OPTIONAL 0

typedef struct appster_s appster_t;
typedef int (*as_route_cb_t) ();

#ifndef DISABLE_REDIS
typedef struct redis_reply_s {
    uint32_t is_integer:1;
    uint32_t is_string:1;
    uint32_t is_array:1;
    uint32_t is_error:1;
    uint32_t is_status:1;
    uint32_t is_nil:1;

    union {
        int64_t integer;
        struct {
            uint32_t len;
            struct {
                char *str; // for string, status and error types
                struct redis_reply_s **element;
            };
        };
    };
} redis_reply_t;
#endif

typedef enum appster_value_type_e {
    AVT_FLAG,
    AVT_INTEGER,
    AVT_NUMBER,
    AVT_STRING,
    AVT_ENCODED_STRING,
    AVT_INTEGER_LIST,
    AVT_NUMBER_LIST,
    AVT_STRING_LIST,
    AVT_ENCODED_STRING_LIST,
} appster_value_type_t;

typedef struct appster_schema_entry_s {
    const char* key;
    uint32_t index;
    appster_value_type_t type;
    int is_required;
} appster_schema_entry_t;

appster_t* as_alloc(unsigned threads);
void as_free(appster_t* a);

// NOTE: once added, route cannot be romoved!
int as_add_route(appster_t* a, const char* path, as_route_cb_t cb, appster_schema_entry_t* schema, void* user_data);
int as_add_route_error(appster_t* a, const char* path, as_route_cb_t cb, void* user_data);

int as_bind(appster_t* a, const char* addr, uint16_t port, int backlog);
int as_loop(appster_t* a);

//
// Check to see if argument exists. Returns 1 if argument is present or 0
// if the argument is missing.
int as_arg_exists(uint32_t idx);
// Accessors
int as_arg_flag(uint32_t idx);
uint64_t as_arg_integer(uint32_t idx);
double as_arg_number(uint32_t idx);
const char* as_arg_string(uint32_t idx);
uint32_t as_arg_string_length(uint32_t idx);
uint32_t as_arg_list_length(uint32_t idx);
uint64_t as_arg_list_integer(uint32_t idx, uint32_t list_idx);
double as_arg_list_number(uint32_t idx, uint32_t list_idx);
const char* as_arg_list_string(uint32_t idx, uint32_t list_idx);
uint32_t as_arg_list_string_length(uint32_t idx, uint32_t list_idx);

//
// Sending body in reply. These functions queue the reply body. Once added data
// is not removed until it's written to the wire. The file sending may use mmap
// or sendfile() api's. Content-Length header is added automatically.
//
int as_write(const char* data, int64_t len);
int as_write_f(const char* format, ...);
int as_write_fd(int fd, int64_t offset, int64_t len);
int as_write_file(const char* path, int64_t offset, int64_t len);

#ifndef DISABLE_REDIS
void as_add_redis(appster_t* a, const char* ip, uint16_t port);
void as_add_redis_shard(appster_t* a, const char* ns, const char* ip, uint16_t port);
//
// Async redis bindings. They mimic hiredis's blocking functions except that,
// these are executed in route callbacks as non-blocking functions. Executing
// these outside route callback is undefined behaviour. Reply returned by these
// functions must be destroyed with as_redis_destroy() function to free up the
// memory.
//
// Appster adds an extra sharding functionality for users of redis versions
// prior intoruction of redis cluster. To use it, one must register shards using
// as_add_redis_shard. Otherwise, commads are executed on redis remotes added
// with as_add_redis. To use shard, prepend shard name to your command like so:
//
// MY_SHARD_NAMESPACE SET key value
//
// Sharding is done by using crc16 hashing algorithm on the whole key value. If
// you wish to use only a part of a key for sharding you can use the new redis
// hash tags format (NOTE: you don't have to use redis cluster for this to work)
// like so:
//
// MY_SHARD_NAMESPACE SET {key}.users value
// MY_SHARD_NAMESPACE SET {key}.computers value
//
// Both of those keys will hash to the same shard. More info at:
// https://redis.io/topics/cluster-spec#keys-hash-tags
//
// NOTE: redis remotes added with as_add_redis() are not sharded and commands
// are balanced on each remote by using round-robin. Each
//
redis_reply_t as_redis(const char *format, ...);
redis_reply_t as_redisv(const char *format, va_list ap);
redis_reply_t as_redisargv(int argc, const char **argv, const size_t *argvlen);
void as_free_redis_reply(redis_reply_t* reply);
#endif

#endif // APPSTER_H
