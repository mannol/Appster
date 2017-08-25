#include "appster.h"
#include "appster_struct.h"

#include "channel.h"
#include "log.h"

#ifndef DISABLE_REDIS
#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <hiredis/adapters/libuv.h>
#endif

typedef struct redis_remote_s {
    char* ns;
    char* ip;
    uint16_t port;
} redis_remote_t;

typedef struct {
    channel_t channel;
    redis_reply_t* reply;
} redis_cb_arg_t;

struct context_s;

__thread vector_t basic_ctxs;
__thread uint32_t basic_ctxs_round = 0;
__thread hashmap_t* ctxs;
__thread uv_loop_t* loop = NULL;

extern __thread struct context_s* __current_ctx;

static redisAsyncContext* get_shard(const char* key, uint32_t len);
static void redis_steal(redisReply* what, redis_reply_t* to);
static void redis_connect_cb(const redisAsyncContext *c, int status);
static void redis_disconnect_cb(const redisAsyncContext *c, int status);
static void redis_postponed_connect_cb(uv_timer_t* handle);
static void redis_cb(redisAsyncContext* ctx, void* rp, void* ptr);

void as_add_redis(appster_t* a, const char* ip, uint16_t port) {
    as_add_redis_shard(a, NULL, ip, port);
}
void as_add_redis_shard(appster_t* a, const char* ns, const char* ip, uint16_t port) {
    redis_remote_t* r = malloc(sizeof(redis_remote_t));
    if (!ns) {
        r->ns = NULL;
    } else {
        r->ns = strdup(ns);
    }
    r->ip = strdup(ip);
    r->port = port;
    vector_push_back(a->redises, &r);
}
redis_reply_t as_redis(const char *format, ...) {
    va_list ap;
    redis_reply_t rc;
    va_start(ap, format);
    rc = as_redisv(format, ap);
    va_end(ap);
    return rc;
}
redis_reply_t as_redisv(const char *format, va_list ap) {
    // TODO calculate shard
    redisAsyncContext* rctx;
    redis_reply_t rc = {0};
    redis_cb_arg_t arg;
    struct context_s* ctx = __current_ctx;

    rctx = get_shard(NULL, 0);
    if (!rctx) {
        rc.is_error = 1;
        rc.str = strdup("No active shards");
        rc.len = strlen(rc.str);
        return rc;
    }

    if (redisvAsyncCommand(rctx, redis_cb, &arg, format, ap) != 0) {
        rc.is_error = 1;
        rc.str = strdup("Error issuing redis command");
        rc.len = strlen(rc.str);
        return rc;
    }

    arg.reply = &rc;
    arg.channel = ch_make();

    ch_recv(arg.channel); // wait for async command to finish
    __current_ctx = ctx;

    return rc;
}
redis_reply_t as_redisargv(int argc, const char **argv, const size_t *argvlen) {
    // TODO implement this
    redis_reply_t rc = {0};
    return rc;
}
void as_free_redis_reply(redis_reply_t* reply) {
    if (!reply) {
        return;
    }

    if (reply->is_string || reply->is_status || reply->is_error) {
        free(reply->str);
    } else if (reply->is_array && reply->element) {
        for (uint32_t i = 0; i < reply->len; i++) {
            as_free_redis_reply(reply->element[i]);
        }
        free(reply->element);
    }
}

void redis_remote_initialize_for_this_thread(uv_loop_t* l) {
    appster_t* a;
    redis_remote_t* r;
    redisAsyncContext* ctx;

    loop = l;
    a = loop->data;

    vector_setup(basic_ctxs, 10, sizeof(redisAsyncContext*));
    ctxs = hm_alloc(10, NULL, NULL);

    VECTOR_FOR_EACH(a->redises, redis) {
        r = ITERATOR_GET_AS(redis_remote_t*, &redis);
        ctx = redisAsyncConnect(r->ip, r->port);
        ctx->data = (void*) vector_size(basic_ctxs);

        redisLibuvAttach(ctx, loop);
        redisAsyncSetConnectCallback(ctx, redis_connect_cb);
        redisAsyncSetDisconnectCallback(ctx, redis_disconnect_cb);

        if (r->ns) {
//            hm_put(ctxs, r->ns, ctx);
        } else {
            vector_push_back(basic_ctxs, &ctx);
        }
    }
}
void redis_remote_cleanup_for_this_thread() {
    loop = NULL;

    VECTOR_FOR_EACH(basic_ctxs, ctx) {
        redisAsyncFree(ITERATOR_GET_AS(redisAsyncContext*, &ctx));
    }
    vector_destroy(basic_ctxs);

    // TODO shards
}
void free_redis_remote(void* value) {
    redis_remote_t* r;

    r = value;
    free(r->ns);
    free(r->ip);
    free(r);
}
redisAsyncContext* get_shard(const char* key, uint32_t len) {
    /* Half of the code in here is taken from
     * https://redis.io/topics/cluster-spec#keys-hash-tags */

//    int s, e; /* start-end indexes of { and } */

    if (!key || !len) { /* Get the shard by round-robin */
        if (vector_is_empty(basic_ctxs)) {
            return NULL;
        }
        return VECTOR_GET_AS(void*, basic_ctxs, basic_ctxs_round++ % vector_size(basic_ctxs));
    }

    return NULL;

    // TODO
//    /* Search the first occurrence of '{'. */
//    for (s = 0; s < keylen; s++)
//        if (key[s] == '{') break;

//    /* No '{' ? Hash the whole key. This is the base case. */
//    if (s == keylen) return crc16(key,keylen) & 16383;

//    /* '{' found? Check if we have the corresponding '}'. */
//    for (e = s+1; e < keylen; e++)
//        if (key[e] == '}') break;

//    /* No '}' or nothing between {} ? Hash the whole key. */
//    if (e == keylen || e == s+1) return crc16(key,keylen) & 16383;

//    /* If we are here there is both a { and a } on its right. Hash
//     * what is in the middle between { and }. */
//    return crc16(key+s+1,e-s-1) & 16383;
}
void redis_steal(redisReply* what, redis_reply_t* to) {
    switch (what->type) {
    case REDIS_REPLY_STRING:
        to->is_string = 1;
        to->str = what->str;
        to->len = what->len;
        break;
    case REDIS_REPLY_ARRAY:
        to->is_array = 1;
        to->len = what->elements;
        to->element = calloc(to->len, sizeof(redis_reply_t*));
        for (uint32_t i = 0; i < to->len; i++) {
            redis_steal(what->element[i], to->element[i]);
        }
        break;
    case REDIS_REPLY_INTEGER:
        to->is_integer = 1;
        to->integer = what->integer;
        break;
    case REDIS_REPLY_NIL:
        to->is_nil = 1;
        break;
    case REDIS_REPLY_STATUS:
        to->is_status = 1;
        to->str = what->str;
        to->len = what->len;
        break;
    case REDIS_REPLY_ERROR:
        to->is_error = 1;
        to->str = what->str;
        to->len = what->len;
        break;
    }

    if (what->type != REDIS_REPLY_ARRAY) // arrays should be freed
        what->type = REDIS_REPLY_INTEGER; // steal it!
}
void redis_connect_cb(const redisAsyncContext *c, int status)
{
    uintptr_t idx;
    uv_timer_t* timer;

    idx = (uintptr_t) c->data;

    if (status != REDIS_OK) {
        ELOG("Error: %s", c->errstr);

//        timer = malloc(sizeof(timer_t));
//        uv_timer_init(loop, timer);
//        timer->data = c->data;
//        uv_timer_start(timer, redis_postponed_connect_cb, 500, 0);

//        c = NULL;
    } else {
        DLOG("Connected on shard: %s:%d", c->c.tcp.host, c->c.tcp.port);
    }

    vector_assign(basic_ctxs, idx, &c);
}
void redis_disconnect_cb(const redisAsyncContext *c, int status)
{
//    if (status != REDIS_OK)
//        ELOG("Error: %s\n", c->errstr);

//    DLOG("Disconnected from shard: %s:%d", c->c.tcp.host, c->c.tcp.port);

//    if (!(c->c.flags & REDIS_FREEING))
//    {
//        redis_connect_data_t* rcd = c->data;
//        backenger_t* b = rcd->b;
//        b->shards[rcd->type][rcd->index] = NULL;

//        event_base_once(b->base, -1, EV_TIMEOUT, redis_postponed_connect_cb,
//                        rcd, &tv_500_ms);
//    }
}
void redis_postponed_connect_cb(uv_timer_t* handle)
{
    free(handle);

//    UNUSED(handle);
//    UNUSED(ev);

//    redis_connect_data_t* rcd = ctx;
//    backenger_t* b = rcd->b;

//    redisAsyncContext* shard = redisAsyncConnect(rcd->ip, rcd->port);
//    shard->data = rcd;
//    b->shards[rcd->type][rcd->index] = shard;

//    redisLibeventAttach(shard, b->base);
//    redisAsyncSetConnectCallback(shard, redis_connect_cb);
//    redisAsyncSetDisconnectCallback(shard, redis_disconnect_cb);

//    DLOG("Reconnecting on redis shard: %s:%d", rcd->ip, rcd->port);
}
void redis_cb(redisAsyncContext* ctx, void* rp, void* ptr) {
    redis_cb_arg_t* arg;

    (void) ctx;

    arg = ptr;

    redis_steal(rp, arg->reply);
    ch_send(arg->channel, NULL);
}
