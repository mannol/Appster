#include "redis.h"

#include "../appster.h"
#include "../log.h"

#include "vector.h"
#include "hashmap.h"

#include <hiredis/hiredis.h>
#include <hiredis/async.h>
#include <hiredis/adapters/libuv.h>

#include <ctype.h>

typedef struct redis_remote_s {
    char* ns;
    char* ip;
    uint16_t port;
} redis_remote_t;

typedef struct {
    appster_channel_t channel;
    redis_reply_t* reply;
} redis_cb_arg_t;

typedef struct {
    vector_t ctxs;
    uint32_t round;
} redis_namespace_t;

typedef struct {
    uv_timer_t timer;
    redis_remote_t* r;
    redis_namespace_t* ns;
    uint32_t idx;
} redis_context_data_t;

static vector_t remotes;
static __thread redis_namespace_t global;
static __thread hashmap_t* namespaces = NULL;
static __thread uv_loop_t* loop = NULL;

static void module_free();
static void module_init_loop(void* l);
static void module_free_loop();

static redis_namespace_t* get_namespace(const char* key, uint32_t len);
static redisAsyncContext* get_namespace_shard(redis_namespace_t* ns, int fac);
static redisAsyncContext* get_shard_fix_format(char* cmd, size_t* plen);
static redisAsyncContext* get_shard_by_key(redis_namespace_t* ns, const char* key, uint32_t len);
static redis_reply_t redis_reply_error(const char* error);
static void redis_steal(redisReply* what, redis_reply_t* to);
static void redis_connect_cb(const redisAsyncContext *ctx, int status);
static void redis_disconnect_cb(const redisAsyncContext *ctx, int status);
static void redis_postponed_connect_cb(uv_timer_t* handle);
static void redis_cb(redisAsyncContext* ctx, void* rp, void* ptr);
static int free_namespace(const void*_, void* nsp, void*__);
static redisAsyncContext* connect_to_shard(const char* ip, uint16_t port);
static const char* strnpbrk(const char* s, const char* accept, size_t n);
static uint32_t crc16(const void *pbuf, size_t len);

int as_redis_module_init(struct appster_module_s* m) {
    vector_setup(remotes, 10, sizeof(void*));
    m->free_cb = module_free;
    m->init_loop_cb = module_init_loop;
    m->free_loop_cb = module_free_loop;
    return 0;
}
void as_add_redis(const char* ip, uint16_t port) {
    as_add_redis_shard(NULL, ip, port);
}
void as_add_redis_shard(const char* ns, const char* ip, uint16_t port) {
    redis_remote_t* r = malloc(sizeof(redis_remote_t));
    if (!ns) {
        r->ns = NULL;
    } else {
        r->ns = strdup(ns);
        for(int i = 0; r->ns[i]; i++) {
            r->ns[i] = tolower(r->ns[i]);
        }
    }
    r->ip = strdup(ip);
    r->port = port;
    vector_push_back(remotes, &r);
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
    char* com;
    int len;

    len = redisvFormatCommand(&com, format, ap);
    if (len == -1) {
        return redis_reply_error("Invalid redis format");
    }

    return as_redisfmt(com, len);
}
redis_reply_t as_redisargv(int argc, const char **argv, const size_t *argvlen) {
    char* com;
    int len;

    len = redisFormatCommandArgv(&com, argc, argv, argvlen);
    if (len == -1) {
        return redis_reply_error("Invalid redis format");
    }

    return as_redisfmt(com, len);
}
redis_reply_t as_redisfmt(char *cmd, size_t len) {
    redisAsyncContext* rctx;
    redis_reply_t rc = {0};
    redis_cb_arg_t arg;

    rctx = get_shard_fix_format(cmd, &len);
    if (!rctx) {
        return redis_reply_error("No active shards or format error");
    }

    if (redisAsyncFormattedCommand(rctx, redis_cb, &arg, cmd, len) != 0) {
        return redis_reply_error("Error issuing redis command");
    }

    arg.reply = &rc;
    arg.channel = as_channel_alloc();
    as_channel_recv(arg.channel); /* wait for async command to finish */

    return rc;
}
void as_redis_free(redis_reply_t* reply) {
    if (!reply) {
        return;
    }

    if (reply->is_string || reply->is_status || reply->is_error) {
        free(reply->str);
    } else if (reply->is_array && reply->element) {
        for (uint32_t i = 0; i < reply->len; i++) {
            as_redis_free(reply->element[i]);
        }
        free(reply->element);
    }
}

void module_free() {
    redis_remote_t* r;

    VECTOR_FOR_EACH(remotes, redis) {
        r = ITERATOR_GET_AS(redis_remote_t*, &redis);
        free(r->ns);
        free(r->ip);
        free(r);
    }

    vector_destroy(remotes);
}
void module_init_loop(void* l) {
    redis_remote_t* r;
    redisAsyncContext* ctx;
    redis_context_data_t* rcd;

    loop = l;

    vector_setup(global.ctxs, 10, sizeof(redisAsyncContext*));
    global.round = 0;

    namespaces = hm_alloc(10, NULL, NULL);

    VECTOR_FOR_EACH(remotes, redis) {
        r = ITERATOR_GET_AS(redis_remote_t*, &redis);

        ctx = connect_to_shard(r->ip, r->port);
        lassert(ctx != NULL);

        rcd = malloc(sizeof(redis_context_data_t));

        if (r->ns) {
            rcd->ns = hm_get(namespaces, r->ns);

            if (!rcd->ns) {
                rcd->ns = calloc(1, sizeof(redis_namespace_t));
                vector_setup(rcd->ns->ctxs, 10, sizeof(redisAsyncContext*));
                hm_put(namespaces, r->ns, rcd->ns);
            }
        } else {
            rcd->ns = &global;
        }

        uv_timer_init(loop, &rcd->timer);
        rcd->timer.data = rcd;
        rcd->r = r;
        rcd->idx = vector_size(rcd->ns->ctxs);
        vector_push_back(rcd->ns->ctxs, &ctx);
        ctx->data = rcd;
    }
}
void module_free_loop() {
    loop = NULL;

    free_namespace(NULL, &global, NULL);
    hm_foreach(namespaces, free_namespace, NULL);
}

redis_namespace_t* get_namespace(const char* key, uint32_t len) {
    const char* f;

    if (!namespaces) {
        return &global;
    }

    f = strnpbrk(key, ". ", len);

    if (!f) {
        return &global;
    }

    f++;

    {
        char copy[f - key];
        for(int i = 0; i < sizeof(copy); i++) {
            copy[i] = tolower(key[i]);
        }
        copy[sizeof(copy) - 1] = 0;

        return hm_get(namespaces, copy);
    }
}
redisAsyncContext* get_namespace_shard(redis_namespace_t* ns, int fac) {
    return VECTOR_GET_AS(void*, ns->ctxs, fac % vector_size(ns->ctxs));
}
redisAsyncContext* get_shard_fix_format(char* cmd, size_t* plen) {
    char* line = cmd,* eol, *klen,* fx,* dot;
    redis_namespace_t* ns;
    redisAsyncContext* ctx;
    int coml = 0;
    size_t len = *plen;

    line = memchr(line + 1, '\n', len - (line - cmd) - 1);

    if (!line) {
        return NULL;
    }

    klen = line + 2; /* klen is now set to key len */

    line = memchr(line + 1, '\n', len - (line - cmd) - 1);

    if (!line) {
        return NULL;
    }

    /* now, 'line + 1' is set at the begining of the command */
    eol = memchr(line + 1, '\n', len - (line - cmd) - 1);
    if (!eol) {
        return NULL;
    }

    coml = eol - line - 1;
    ns = get_namespace(line + 1, coml); /* get namespace */

    if (!ns || ns == &global) {
        return get_shard_by_key(ns, NULL, 0);
    }

    fx = line + 1; /* set the marker at which point to do memmove */

    line = memchr(eol + 1, '\n', len - (eol - cmd) - 1);
    if (!line) {
        return NULL;
    }

    /* now, 'line + 1' is set at the begining of the key */
    eol = memchr(line + 1, '\n', len - (line - cmd) - 1);
    if (!eol) {
        return NULL;
    }

    /* pick up the context */
    ctx = get_shard_by_key(ns, line + 1, eol - line - 1);

    dot = strchr(fx, '.');
    fx = strchr(fx, '\n');
    if (!dot) { /* very unlikely, but it can happen with binary input mistake */
        return NULL;
    }

    klen += sprintf(klen, "%d", (int) (fx - dot - 2));
    klen[0] = '\r';
    klen[1] = '\n';

    coml = len - (dot - cmd) - 1;
    fx = memmove(klen + 2, dot + 1, coml) + coml + 1;
    *fx = 0;

    *plen = fx - cmd - 1;

    return ctx;
}
redisAsyncContext* get_shard_by_key(redis_namespace_t* ns, const char* key, uint32_t len) {
    /* Half of the code in here is taken from
     * https://redis.io/topics/cluster-spec#keys-hash-tags */

    uint32_t s, e; /* start-end indexes of { and } */

    if (!ns || vector_is_empty(ns->ctxs)) {
        return NULL;
    }

    if (ns == &global || !key || !len) { /* Get the shard by round-robin */
        return get_namespace_shard(ns, ns->round++);
    }

    /* Search the first occurrence of '{'. */
    for (s = 0; s < len; s++) {
        if (key[s] == '{') {
            break;
        }
    }

    /* No '{' ? Hash the whole key. This is the base case. */
    if (s == len) {
        return get_namespace_shard(ns, crc16(key, len) & 16383);
    }

    /* '{' found? Check if we have the corresponding '}'. */
    for (e = s + 1; e < len; e++) {
        if (key[e] == '}') {
            break;
        }
    }

    /* No '}' or nothing between {} ? Hash the whole key. */
    if (e == len || e == s + 1) {
        return get_namespace_shard(ns, crc16(key, len) & 16383);
    }

    /* If we are here there is both a { and a } on its right. Hash
     * what is in the middle between { and }. */
    return get_namespace_shard(ns, crc16(key + s + 1, e - s - 1) & 16383);
}
redis_reply_t redis_reply_error(const char* error) {
    redis_reply_t rc;

    rc.is_error = 1;
    rc.str = strdup(error);
    rc.len = strlen(rc.str);
    return rc;
}
void redis_steal(redisReply* what, redis_reply_t* to) {
    if (!what) {
        *to = redis_reply_error("Invalid reply");
        return;
    }

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

    if (what->type != REDIS_REPLY_ARRAY) /* arrays should be freed */
        what->type = REDIS_REPLY_INTEGER; /* steal it! */
}
void redis_connect_cb(const redisAsyncContext *ctx, int status) {
    redis_context_data_t* rcd;

    rcd = ctx->data;

    if (status != REDIS_OK) {
        ELOG("Connection error: %s", ctx->errstr);

        uv_timer_start(&rcd->timer, redis_postponed_connect_cb, 500, 0);
        ctx = NULL;
    } else {
        DLOG("Connected on shard: %s:%d", ctx->c.tcp.host, ctx->c.tcp.port);
    }

    vector_assign(rcd->ns->ctxs, rcd->idx, &ctx);
}
void redis_disconnect_cb(const redisAsyncContext *ctx, int status) {
    redis_context_data_t* rcd;

    if (status != REDIS_OK) {
        ELOG("Connection error: %s", ctx->errstr);
    }

    DLOG("Disconnected from shard: %s:%d", ctx->c.tcp.host, ctx->c.tcp.port);

    if (!(ctx->c.flags & REDIS_FREEING)) {
        rcd = ctx->data;
        ctx = NULL;

        vector_assign(rcd->ns->ctxs, rcd->idx, &ctx);
        uv_timer_start(&rcd->timer, redis_postponed_connect_cb, 500, 0);
    }
}
void redis_postponed_connect_cb(uv_timer_t* handle) {
    redis_context_data_t* rcd;
    redisAsyncContext* ctx;

    rcd = handle->data;

    DLOG("Reconnecting to: %s:%d", rcd->r->ip, rcd->r->port);

    ctx = connect_to_shard(rcd->r->ip, rcd->r->port);
    if (!ctx) {
        uv_timer_start(&rcd->timer, redis_postponed_connect_cb, 500, 0);
        return;
    }

    ctx->data = rcd;
    vector_assign(rcd->ns->ctxs, rcd->idx, &ctx);
}
void redis_cb(redisAsyncContext* ctx, void* rp, void* ptr) {
    redis_cb_arg_t* arg;

    (void) ctx;

    arg = ptr;

    redis_steal(rp, arg->reply);
    as_channel_send(arg->channel, NULL);
}
int free_namespace(const void* _, void* nsp, void* __) {
    redis_namespace_t* ns;

    ns = nsp;

    VECTOR_FOR_EACH(ns->ctxs, ctx) {
        redisAsyncFree(ITERATOR_GET_AS(redisAsyncContext*, &ctx));
    }
    vector_destroy(ns->ctxs);

    return 1;
}
redisAsyncContext* connect_to_shard(const char* ip, uint16_t port)
{
    redisAsyncContext* ctx;

    ctx = redisAsyncConnect(ip, port);
    if (!ctx) {
        return NULL;
    }

    redisLibuvAttach(ctx, loop);
    redisAsyncSetConnectCallback(ctx, redis_connect_cb);
    redisAsyncSetDisconnectCallback(ctx, redis_disconnect_cb);

    /*
     In the cases of which the connection could not be established on a local
     interface, or on a remote in case of an interface error, the adapter
     doesn't invoke an error callback. To deal with that, we safely reissue a
     connect on an fd after the attach and the error will be reported.

     A somewhat relevant issue: https://github.com/redis/hiredis/issues/450
     */
    char strport[6];
    struct addrinfo *servinfo;

    snprintf(strport, 6, "%d", port);

    if (getaddrinfo(ip, strport, NULL, &servinfo) != 0) {
        redisAsyncFree(ctx);
        return NULL;
    }

    connect(ctx->c.fd, servinfo->ai_addr, servinfo->ai_addrlen);
    freeaddrinfo(servinfo);
    return ctx;
}
const char* strnpbrk(const char* s, const char* accept, size_t n) {
    /* Taken from: https://github.com/jwtowner/upcaste/blob/master/src/upcore/src/cstring/strnpbrk.cpp
     * LICENSE at the time of copying: MIT */

    if (!(s || !n) || !accept) {
        return NULL;
    }

    const char* end = s + n;
    for (const char* cur = s; cur < end; ++cur) {
        for (const char* a = accept; *a; ++a) {
            if (*a == *cur) {
                return cur;
            }
        }
    }

    return NULL;
}
uint32_t crc16(const void *pbuf, size_t len)
{
    static const uint16_t crc16tab[256]= {
        0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,
        0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
        0x1231,0x0210,0x3273,0x2252,0x52b5,0x4294,0x72f7,0x62d6,
        0x9339,0x8318,0xb37b,0xa35a,0xd3bd,0xc39c,0xf3ff,0xe3de,
        0x2462,0x3443,0x0420,0x1401,0x64e6,0x74c7,0x44a4,0x5485,
        0xa56a,0xb54b,0x8528,0x9509,0xe5ee,0xf5cf,0xc5ac,0xd58d,
        0x3653,0x2672,0x1611,0x0630,0x76d7,0x66f6,0x5695,0x46b4,
        0xb75b,0xa77a,0x9719,0x8738,0xf7df,0xe7fe,0xd79d,0xc7bc,
        0x48c4,0x58e5,0x6886,0x78a7,0x0840,0x1861,0x2802,0x3823,
        0xc9cc,0xd9ed,0xe98e,0xf9af,0x8948,0x9969,0xa90a,0xb92b,
        0x5af5,0x4ad4,0x7ab7,0x6a96,0x1a71,0x0a50,0x3a33,0x2a12,
        0xdbfd,0xcbdc,0xfbbf,0xeb9e,0x9b79,0x8b58,0xbb3b,0xab1a,
        0x6ca6,0x7c87,0x4ce4,0x5cc5,0x2c22,0x3c03,0x0c60,0x1c41,
        0xedae,0xfd8f,0xcdec,0xddcd,0xad2a,0xbd0b,0x8d68,0x9d49,
        0x7e97,0x6eb6,0x5ed5,0x4ef4,0x3e13,0x2e32,0x1e51,0x0e70,
        0xff9f,0xefbe,0xdfdd,0xcffc,0xbf1b,0xaf3a,0x9f59,0x8f78,
        0x9188,0x81a9,0xb1ca,0xa1eb,0xd10c,0xc12d,0xf14e,0xe16f,
        0x1080,0x00a1,0x30c2,0x20e3,0x5004,0x4025,0x7046,0x6067,
        0x83b9,0x9398,0xa3fb,0xb3da,0xc33d,0xd31c,0xe37f,0xf35e,
        0x02b1,0x1290,0x22f3,0x32d2,0x4235,0x5214,0x6277,0x7256,
        0xb5ea,0xa5cb,0x95a8,0x8589,0xf56e,0xe54f,0xd52c,0xc50d,
        0x34e2,0x24c3,0x14a0,0x0481,0x7466,0x6447,0x5424,0x4405,
        0xa7db,0xb7fa,0x8799,0x97b8,0xe75f,0xf77e,0xc71d,0xd73c,
        0x26d3,0x36f2,0x0691,0x16b0,0x6657,0x7676,0x4615,0x5634,
        0xd94c,0xc96d,0xf90e,0xe92f,0x99c8,0x89e9,0xb98a,0xa9ab,
        0x5844,0x4865,0x7806,0x6827,0x18c0,0x08e1,0x3882,0x28a3,
        0xcb7d,0xdb5c,0xeb3f,0xfb1e,0x8bf9,0x9bd8,0xabbb,0xbb9a,
        0x4a75,0x5a54,0x6a37,0x7a16,0x0af1,0x1ad0,0x2ab3,0x3a92,
        0xfd2e,0xed0f,0xdd6c,0xcd4d,0xbdaa,0xad8b,0x9de8,0x8dc9,
        0x7c26,0x6c07,0x5c64,0x4c45,0x3ca2,0x2c83,0x1ce0,0x0cc1,
        0xef1f,0xff3e,0xcf5d,0xdf7c,0xaf9b,0xbfba,0x8fd9,0x9ff8,
        0x6e17,0x7e36,0x4e55,0x5e74,0x2e93,0x3eb2,0x0ed1,0x1ef0
    };

    int counter;
    const char* buf = pbuf;
    uint16_t crc = 0;

    for (counter = 0; counter < len; counter++) {
        crc = (crc<<8) ^ crc16tab[((crc>>8) ^ *buf++)&0x00FF];
    }
    return crc;
}
