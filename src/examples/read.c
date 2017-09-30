/*
 In this example, we cover the reading of the request body by the application.
 While using HTTP you are likely to send body along with your HTTP message:
 sending arbirary file or some json data for example. To read the body,
 appster offers 2 functionalities: 1) read the body or part of the body into
 the memory or 2) read the body or part of the body directly to the file.

 The functions used for reading the body are:
 as_read() - read into the memory
 as_read_fd() - read to the fd
 as_read_file() - like as_read_fd() but opens the file at destination

 Each of the three are non-blocking by default.
 */


#include <stdio.h>
#include "../appster.h"
#include "../log.h"

int exec_read(void* data) {
    char buf[256] = {0};
    int rc;

    rc = as_read(buf, 2);
    if (rc != -1) {
        printf("Received: %s\n", buf);
    }

    rc = as_read_to_file("some_file.txt", 200);

    /* the file should now contain 'me data' */

    return 200;
}

int main() {
    appster_t* a = as_alloc(1);

    as_add_route(a, "/read", exec_read, NULL, NULL);

    as_listen_and_serve(a, "0.0.0.0", 8080, 2048);
    as_free(a);
    return 0;
}

/*
 To execute the example, run the following into terminal window:
 curl -X POST -d 'some data' http://127.0.0.1:8080/read
 */
