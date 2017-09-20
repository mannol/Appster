/*
 This example shows how to use built-in interface for sending body in HTTP
 response. All the data is queued for sending and is sent once the route
 returns the status code. The as_write() function is used to send any amount
 of data of any kind (you are not limited to null-terminated strings).
 as_write_f() is printf()-like interface for sending formatted strings.
 To add a data from file, you should use as_write_fd() or as_write_file()
 functions instead of reading files yourself. They are optimized for sending
 files and will probably use mmap or sendfile() api's if system supports them.
 There is no limitation on how many times these functions can be sent.
*/


#include <stdio.h>
#include "../appster.h"

int exec_write(void* data) {
    char binary[] = {'W', 'o', 'r', 'l', 'd', '\n'};

    as_write("Hello ", -1); /* pass -1 to use strlen() to calculate len */
    as_write(binary, 6); /* send binary data */
    as_write_f("This is an example of sending %s output\n", "formatted");
    as_write_file("../example.txt", 0, -1);
    as_write("Files are not loaded into memory while sending!!!\n", -1);

    return 200;
}

int main() {
    appster_schema_entry_t schema[] = {
        {"hello", 0, AVT_STRING, 1},
        {NULL}
    };

    appster_t* a = as_alloc(1);

    as_add_route(a, "/write", exec_write, schema, NULL);

    as_listen_and_serve(a, "0.0.0.0", 8080, 2048);
    as_free(a);
    return 0;
}

/*
 To execute the example, type the following into terminal window:
 curl http://127.0.0.1:8080/write?hello=world
 */
