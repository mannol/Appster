//
// This example shows how to use redis module.
//
// Standard C redis interface, hiredis, provides async interface but,
// it's not so easy to use. The problem is that for every issued command,
// there must exist appropriate redis callback. This adds complexity to the
// code.
//
// With Appster, however, one executes the redis commands using as_redis*()
// interfaces and suspends the execution of the route. While the command is
// executed on the redis, Appster handles other requrests. When the command
// finishes and the reply is received, the control is resumed to the route and
// as_redis* returns the reply from the redis.
//

#include <stdio.h>
#include "../appster.h"

int exec_route(void* data) {
    redis_reply_t rp; // declare a repply storage

    rp = as_redis("SET hello %s", as_arg_string(0)); // execute the command
    // ... handle reply
    as_free_redis_reply(&rp); // destroy the reply once no longer needed

    rp = as_redis("GET hello");  // execute another command
    printf("hello %.*s\n", rp.len, rp.str); // << prints 'hello world'
    fflush(stdout);

    as_free_redis_reply(&rp); // destroy the reply

    // repeat ...

    // once done, send the status
    return 200;
}

int main() {
    appster_schema_entry_t schema[] = {
        {"hello", 0, AVT_STRING, 1},
        {NULL}
    };

    appster_t* a = as_alloc(1);

    as_add_route(a, "/", exec_route, schema, NULL);
    as_add_redis(a, "127.0.0.1", 6379);

    as_bind(a, "0.0.0.0", 8080, 2048);
    as_loop(a); // after this point, 'a' should not be tampered with!
    as_free(a);
    return 0;
}
