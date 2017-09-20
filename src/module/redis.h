#ifndef MODULE_REDIS_H
#define MODULE_REDIS_H

#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>

struct appster_module_s;

typedef struct redis_reply_s {
    unsigned is_integer:1;
    unsigned is_string:1;
    unsigned is_array:1;
    unsigned is_error:1;
    unsigned is_status:1;
    unsigned is_nil:1;

    union {
        int64_t integer;
        struct {
            uint32_t len;
            struct {
                char *str; /* for string, status and error types */
                struct redis_reply_s **element;
            };
        };
    };
} redis_reply_t;

int as_redis_module_init(struct appster_module_s* m);

void as_add_redis(const char* ip, uint16_t port);
void as_add_redis_shard(const char* ns, const char* ip, uint16_t port);

/*
 Async redis bindings. They mimic hiredis's blocking functions except that,
 these are executed in route callbacks as non-blocking functions. Executing
 these outside route callback is undefined behaviour. Reply returned by these
 functions must be destroyed with as_redis_destroy() function to free up the
 memory.

 Appster adds an extra sharding functionality for users of redis versions
 prior intoruction of redis cluster. To use it, one must register shards using
 as_add_redis_shard. Otherwise, COMMANDS ARE EXECUTED ON REDIS REMOTES ADDED
 WITH as_add_redis. To use shard, prepend shard name to your command like so:

 MY_SHARD_NAME.SET key value

 Sharding is done by using crc16 hashing algorithm on the whole key value. If
 you wish to use only a part of a key for sharding you can use the new redis
 hash tags format (NOTE: you don't have to use redis cluster for this to work)
 like so:

 MY_SHARD_NAME.SET {key}.users value
 MY_SHARD_NAME.SET {key}.computers value

 Both of those keys will hash to the same shard. More info at:
 https://redis.io/topics/cluster-spec#keys-hash-tags

 NOTE: redis remotes added with as_add_redis() are not sharded and commands
 are balanced on each remote by using round-robin.
 */
redis_reply_t as_redis(const char *format, ...);
redis_reply_t as_redisv(const char *format, va_list ap);
redis_reply_t as_redisargv(int argc, const char **argv, const size_t *argvlen);
/* WARNING: The 'cmd' can be modified! */
redis_reply_t as_redisfmt(char* cmd, size_t len);
void as_redis_free(redis_reply_t* reply);

#endif /* MODULE_REDIS_H */
