# Appster asynchronous web framework

Appster brings the async/await pattern to C http API and enables writing __fast__, __asynchronous__ and __simple__ servers or server applets. Appster utilizes the combination of very tiny and powerful [libdill](http://libdill.org/) and [libuv](http://libuv.org/) libraries which enable efficient and simple concurrency.

Basic features:
- Tiny
- Utilizes [structured concurrency](http://libdill.org/structured-concurrency.html)
- Full http 1.0 and 1.1 support.
- Scalable (You can say that for every http server...)
- Can use all processor cores without locking overhead
- Supports modules. Currently, built in modules are:
 - redis
 - postgresql (TODO)
 - HTTP client (TODO)
 - XMPP client (TODO)

## Example

This is an example of a small applet that receives HTTP request on path `/` along with a single string argument and preforms 2 __asynchronous__ redis operations:

```C
#include <appster/appster.h>
#include <appster/module/redis.h>

int exec_route(void* data) {
    redis_reply_t rp;

    /* Execute redis operation using received url parameter value */
    rp = as_redis("SET hello %s", as_arg_string(0));

    /* Destroy the object */
    as_redis_free(&rp);

    /* Now get the stored value */
    rp = as_redis("GET hello");

    /* Prints out 'hello world' */
    printf("hello %.*s\n", rp.len, rp.str);

    /* Destroy the object */
    as_redis_free(&rp);

    /* Return code is taken as a status code http reply */
    return 200;
}

int main() {
    /* Define a shema for url parameters.
       You can specify the name, type and if the parameter is required */
    appster_schema_entry_t schema[] = {
        {"hello", 0, AVT_STRING, 1},
        {NULL} /* END OF PARAMETERS */
    };

    /* Allocate appster handle. You specify the number of scheduler threads as an argument.
       THESE THREADS ARE NOT YOUR EVERYDAY WORKER THREADS! These threads only handle
       HTTP connections, parsing and scheduling. The real concurrency is done
       by libdill coroutines.
     */
    appster_t* a = as_alloc(1);
    as_module_init(a, as_redis_module_init);

    /* Add route to handle HTTP requests with. */
    as_add_route(a, "/", exec_route, schema, NULL);

    /* Add redis remotes */
    as_add_redis("127.0.0.1", 6379);

    /* Start working! */
    as_listen_and_serve(a, "0.0.0.0", 8080, 2048);

    /* ... */
    as_free(a);
    return 0;
}

// to run the example, run in terminal: curl http://127.0.0.1:8080/?hello=world
```


## Installation
First, compile and install the dependencies:

#### libdill
```bash
$ wget http://libdill.org/libdill-1.6.tar.gz
$ tar xf libdill-1.6.tar.gz
$ cd libdill-1.6/
$ ./configure
$ make
$ sudo make install
```

#### libuv
You can grab libuv from your distribution packages:
```bash
$ sudo apt install libuv-dev
```

Or install from source:
```bash
$ wget https://github.com/libuv/libuv/archive/v1.14.0.tar.gz
$ tar xf v1.14.0.tar.gz
$ cd libuv-1.14.0/
$ sh autogen.sh
$ ./configure
$ make
$ make check
$ make install
```

#### libhiredis (optional)
You can grab libhiredis from your distribution packages:
```bash
$ sudo apt install libhiredis-dev
```

Or install from source:
```bash
$ wget https://github.com/redis/hiredis/archive/v0.13.3.tar.gz
$ tar xf v0.13.3.tar.gz
$ cd hiredis-0.13.3/
$ make
$ sudo make install
```

#### Appster
```bash
$ wget https://github.com/mannol/Appster/archive/v0.2.tar.gz
$ tar xf v0.2.tar.gz
$ cd Appster-0.2/
$ mkdir -p build && cd build/
$ cmake ..
$ make
$ sudo make install
```

Now, to link with appster, either use `-lshared_appster` or `-lstatic_appster` for __shared__ or __static__ linking.

Current version: __0.2__. License: check `LICENSE` file
