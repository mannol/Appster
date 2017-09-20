#include "sql.h"

#include "../appster.h"
#include "../log.h"

#include "vector.h"

#include <stdlib.h>
#include <libpq-fe.h>
#include <uv.h>

typedef struct pq_resp_handler_s {
    unsigned drop;
    appster_channel_t chan;
    struct pq_resp_handler_s* next;
    char* querystr;
} pq_query_t;

typedef struct {
    uv_poll_t handle;
    uv_timer_t timer;
    PGconn* ctx;
    const char* remote;
    pq_query_t* rh_head,* rh_tail;
    int is_conn;
} pq_conn_t;

struct sql_reply_s {
    PGresult* res;
    pq_query_t* query;
};

static vector_t remotes;
static __thread vector_t conns;
static __thread uint32_t conns_round;
static __thread uv_loop_t* loop = NULL;
static __thread const char* error = NULL;
static __thread char* error_copy = NULL;

static void module_free();
static void module_init_loop(void* l);
static void module_free_loop();

static void conn_free(uv_handle_t* handle);
static void conn_poll(uv_poll_t* handle, int status, int events);
static pq_conn_t* get_next_conn();
static pq_query_t* queue_query(pq_conn_t* conn, char* querystr, int copy);
static void unqueue_query(pq_conn_t* conn, pq_query_t* query);
static sql_reply_t* wait_reply(pq_query_t* query);
static void postponed_connect_cb(uv_timer_t* handle);
static void set_error(const char* err, int copy);
static int vasprintf(char **strp, const char *fmt, va_list ap);

int as_sql_module_init(struct appster_module_s* m) {
    vector_setup(remotes, 10, sizeof(void*));
    m->free_cb = module_free;
    m->init_loop_cb = module_init_loop;
    m->free_loop_cb = module_free_loop;
    return 0;
}
const char* as_sql_errorstr() {
    return error ? error : (error_copy ? error_copy : "no error");
}
void as_add_sql(const char* connstr) {
    char* r;

    r = strdup(connstr);
    vector_push_back(remotes, &r);
}
sql_reply_t* as_sql(const char* query) {
    pq_conn_t* conn;

    conn = get_next_conn();
    if (!conn || !conn->ctx) {
        ELOG("Invalid context");
        set_error("Invalid context", 0);
        return NULL;
    }

    set_error(NULL, 0);

    return wait_reply(queue_query(conn, (char*) query, 1));
}
sql_reply_t* as_sqlf(const char* query, ...) {
    pq_conn_t* conn;
    char* str = NULL,* escquery = NULL;
    int rc;
    va_list ap;

    conn = get_next_conn();
    if (!conn || !conn->ctx) {
        ELOG("Invalid context");
        set_error("Invalid context", 0);
        return NULL;
    }

    va_start(ap, query);
    rc = vasprintf(&str, query, ap);
    va_end(ap);

    if (rc == -1 || !rc) {
        set_error(strerror(errno), 0);
        free(str);
        return NULL;
    }

    escquery = malloc(rc * 2 + 1);
    rc = PQescapeStringConn(conn->ctx, escquery, str, rc, NULL);
    free(str);

    if (rc == -1 || !rc) {
        set_error(PQerrorMessage(conn->ctx), 1);
        free(escquery);
        return NULL;
    }

    return wait_reply(queue_query(conn, escquery, 0));
}
sql_reply_t* as_sql_next(sql_reply_t* prev) {
    if (!prev || !prev->res) {
        as_sql_stop(prev);
        return NULL;
    }

    prev->res = as_channel_pass(prev->query->chan);
    if (!prev->res || PQresultStatus(prev->res) == PGRES_TUPLES_OK) {
        as_sql_stop(prev);
        return NULL;
    }
    return prev;
}
char* as_sql_esc(const unsigned char* binary, size_t len) {
    pq_conn_t* conn;
    size_t to_len;

    /* Get currently scheduled connection */
    conn = VECTOR_GET_AS(pq_conn_t*, conns, conns_round % vector_size(conns));

    if (!conn || !conn->ctx) {
        ELOG("Invalid context");
        set_error("Invalid context", 0);
        return NULL;
    }

    return (char*) PQescapeByteaConn(conn->ctx, binary, len, &to_len);
}
unsigned char* as_sql_unesc(const char* str, size_t* unesclen) {
    return PQunescapeBytea((const unsigned char*) str, unesclen);
}
void as_sql_stop(sql_reply_t* reply) {
    if (!reply) {
        return;
    }

    reply->query->drop = 1;
    free(reply);
}
const char* as_sql_string(sql_reply_t* reply, int field) {
    if (!reply || !reply->res) {
        return NULL;
    }
    return PQgetvalue(reply->res, 0, field);
}
size_t as_sql_length(sql_reply_t* reply, int field) {
    if (!reply || !reply->res) {
        return 0;
    }
    return PQgetlength(reply->res, 0, field);
}
double as_sql_number(sql_reply_t* reply, int field) {
    double rc = 0;
    const char* str;
    char* endp = NULL;

    if (!reply || !reply->res) {
        return rc;
    }

    str = PQgetvalue(reply->res, 0, field);
    rc = strtod(str, &endp);

    if (!endp || !*endp) {
        return rc;
    }

    return 0;
}
long long as_sql_integer(sql_reply_t* reply, int field) {
    long long rc = 0;
    const char* str;
    char* endp = NULL;

    if (!reply || !reply->res) {
        return rc;
    }

    str = PQgetvalue(reply->res, 0, field);
    rc = strtoll(str, &endp, 10);

    if (!endp || !*endp) {
        return rc;
    }

    return 0;
}
unsigned long long as_sql_unsigned(sql_reply_t* reply, int field) {
    unsigned long long rc = 0;
    const char* str;
    char* endp = NULL;

    if (!reply || !reply->res) {
        return rc;
    }

    str = PQgetvalue(reply->res, 0, field);
    rc = strtoull(str, &endp, 10);

    if (!endp || !*endp) {
        return rc;
    }

    return 0;
}
int as_sql_is_null(sql_reply_t* reply, int field) {
    if (!reply || !reply->res) {
        return 0;
    }
    return PQgetisnull(reply->res, 0, field);
}
int as_sql_field(sql_reply_t* reply, const char* field_name) {
    if (!reply || !reply->res) {
        return -1;
    }
    return PQfnumber(reply->res, field_name);
}

void module_free() {
    char* r;

    VECTOR_FOR_EACH(remotes, sql) {
        r = ITERATOR_GET_AS(char*, &sql);
        free(r);
    }

    vector_destroy(remotes);
}
void module_init_loop(void* l) {
    char* r;
    pq_conn_t* conn;

    vector_setup(conns, 10, sizeof(pq_conn_t*));
    conns_round = 0;

    loop = l;

    VECTOR_FOR_EACH(remotes, sql) {
        r = ITERATOR_GET_AS(char*, &sql);

        conn = calloc(1, sizeof(pq_conn_t));
        conn->ctx = PQconnectStart(r);

        if (!conn->ctx) {
            ELOG("Connection to DB failed, %p", (void*) conn->ctx);
        failure:
            if (conn->ctx) {
                PQfinish(conn->ctx);
            }
            free(conn);
            continue;
        }

        PQsetnonblocking(conn->ctx, 1);

        if (uv_poll_init(loop, &conn->handle, PQsocket(conn->ctx)) != 0 ||
                uv_poll_start(&conn->handle, UV_WRITABLE, conn_poll)) {
            goto failure;
        }

        uv_timer_init(loop, &conn->timer);
        conn->timer.data = conn;

        conn->handle.data = conn;
        conn->remote = r;

        vector_push_back(conns, &conn);
    }
}
void module_free_loop() {
    pq_conn_t* c;

    loop = NULL;

    VECTOR_FOR_EACH(conns, conn) {
        c = ITERATOR_GET_AS(pq_conn_t*, &conn);
        uv_close((uv_handle_t*)&c->handle, conn_free);
    }
}

void conn_free(uv_handle_t* handle) {
    pq_conn_t* conn = handle->data;

    PQfinish(conn->ctx);
    free(conn);
}
void conn_poll(uv_poll_t* handle, int status, int events) {
    pq_conn_t* conn = handle->data;
    pq_query_t* rh;
    PGresult* result;

    if (status != 0) {
        return;
    }

    if (!conn->is_conn) {
        if (events & UV_WRITABLE) {
            switch (PQconnectPoll(conn->ctx)) {
            case PGRES_POLLING_OK:
                conn->is_conn = 1;
            case PGRES_POLLING_READING:
                uv_poll_start(&conn->handle, UV_READABLE, conn_poll);
            case PGRES_POLLING_WRITING:
            case PGRES_POLLING_ACTIVE:
                return;
            case PGRES_POLLING_FAILED:
                DLOG("Connection failed: %s", PQerrorMessage(conn->ctx));
                goto reconnect;
            }
        }

        if (events & UV_READABLE) {
            switch (PQconnectPoll(conn->ctx)) {
            case PGRES_POLLING_OK:
                conn->is_conn = 1;
            case PGRES_POLLING_READING:
            case PGRES_POLLING_ACTIVE:
                return;
            case PGRES_POLLING_WRITING:
                uv_poll_start(&conn->handle, UV_WRITABLE, conn_poll);
                return;
            case PGRES_POLLING_FAILED:
                DLOG("Connection failed: %s", PQerrorMessage(conn->ctx));
                goto reconnect;
            }
        }

        return;
    }

    if (events & UV_READABLE) {
        if (PQconsumeInput(conn->ctx)) {
            while (!PQisBusy(conn->ctx)) {
                result = PQgetResult(conn->ctx);
                rh = conn->rh_head;

                if (!result) {
                    /* It's over. Move onto the next request */
                    unqueue_query(conn, rh);
                    break;
                }

                if (rh && !rh->drop) {
                    /* NOTE: control is moved to the handler */
                    as_channel_send(rh->chan, result);
                }

                PQclear(result);
            }
        } else if (PQstatus(conn->ctx) != CONNECTION_OK) {
            DLOG("Connection to postgres server closed");
        reconnect:
            /*
             * Connection closed. Notify all the channels of this misfortune
             * and try to reconnect straight away.
             */
            while ((rh = conn->rh_head)) {
                as_channel_send(rh->chan, NULL);
                conn->rh_head = rh->next;
                if (!conn->rh_head) {
                    conn->rh_tail = NULL;
                }
                free(rh);
            }

            uv_timer_start(&conn->timer, postponed_connect_cb, 500, 0);
            uv_close((uv_handle_t*)&conn->handle, NULL);
        } else {
            ELOG("PQ error: %s", PQerrorMessage(conn->ctx));
        }
    }
}
pq_conn_t* get_next_conn() {
    return VECTOR_GET_AS(pq_conn_t*, conns, conns_round++ % vector_size(conns));
}
pq_query_t* queue_query(pq_conn_t* conn, char* querystr, int copy) {
    pq_query_t* rc;

    rc = malloc(sizeof(pq_query_t));

    if (conn->rh_head) {
        rc->querystr = copy ? strdup(querystr) : querystr;
        conn->rh_tail->next = rc;
        conn->rh_tail = rc;
    } else {
        if (!PQsendQuery(conn->ctx, querystr)) {
            ELOG("Error sending query: %s", PQerrorMessage(conn->ctx));
            free(rc);
            if (!copy) {
                free(querystr);
            }
            return NULL;
        }

        PQsetSingleRowMode(conn->ctx);

        rc->querystr = NULL;
        conn->rh_head = rc;
        conn->rh_tail = rc;
    }

    rc->chan = as_channel_alloc();
    rc->next = NULL;
    rc->drop = 0;

    return rc;
}
void unqueue_query(pq_conn_t* conn, pq_query_t* query) {
again:
    conn->rh_head = query->next;
    free(query->querystr);
    as_channel_free(query->chan);
    free(query);

    if (!conn->rh_head) {
        DLOG("No more requests");
        conn->rh_tail = NULL;
    } else {
        /* issue a next query */
        DLOG("Issuing next request");
        query = conn->rh_head;
        if (!PQsendQuery(conn->ctx, query->querystr)) {
            ELOG("Error sending query: %s", PQerrorMessage(conn->ctx));
            /* Free the query now to leave more space available */
            free(query->querystr);
            query->querystr = NULL;
            as_channel_send(query->chan, NULL);
            /*
             I'm personally against recursive functions, specially in the case
             where stack size is tight which can lead to wierd issues.
             */
            goto again;
        }

        PQsetSingleRowMode(conn->ctx);
    }
}
sql_reply_t* wait_reply(pq_query_t* query) {
    sql_reply_t* rc;
    PGresult* res;

    if (!query) {
        return NULL;
    }

    res = as_channel_pass(query->chan);
    if (!res) {
        return NULL;
    }

    rc = malloc(sizeof(sql_reply_t));
    rc->query = query;
    rc->res = res;
    return rc;
}
void postponed_connect_cb(uv_timer_t* handle) {
    pq_conn_t* conn;

    conn = handle->data;

    DLOG("Reconnecting to server");

    PQresetStart(conn->ctx);

    uv_poll_init(loop, &conn->handle, PQsocket(conn->ctx));
    uv_poll_start(&conn->handle, UV_WRITABLE, conn_poll);
}
void set_error(const char* err, int copy) {
    free(error_copy);
    error_copy = NULL;
    error = NULL;

    if (err) {
        if (copy) {
            error_copy = strdup(err);
        } else {
            error = err;
        }
    }
}
int vasprintf(char **strp, const char *fmt, va_list ap)
{
    va_list cp;
    va_copy(cp, ap);
    int nb = vsnprintf(NULL, 0, fmt, cp);
    va_end(cp);

    if (nb < 0)
        return nb;

    nb ++;

    *strp = malloc(nb);

    if (!*strp)
    {
        errno = ENOMEM;
        return -1;
    }

    return vsnprintf(*strp, nb, fmt, ap);
}
