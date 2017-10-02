#ifndef APPSTER_H
#define APPSTER_H

#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>

#define AS_REQUIRED 1
#define AS_OPTIONAL 0

typedef struct appster_s appster_t;
typedef int (*as_route_cb_t) ();

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

typedef union appster_channel_u
{
    uintptr_t ptr;
    int id;
} appster_channel_t;

appster_t* as_alloc(unsigned threads);
void as_free(appster_t* a);
/*
 The global cleanup function is used to free some global contexts that are
 allocated at some point during run cycle. Usually this function is not required
 to be called but it can serve to help diagnose memory leaks as it frees,
 normally, non-free'd data. Example is: deallocation of OpenSSL library globals
 */
void as_global_cleanup();
#ifdef HAS_CRYPTO
/*
 To enable SSL/TLS, each appster instance requires 2 file paths. First file path
 is the path to the, prefferably full, chain in PEM format. The second file path
 is the path to the private key, also, in PEM format. If the files are not valid
 the appster will fail with fatal error on next as_listen_and_serve. Setting any
 of these values to NULL disables crypto for this instace.
 */
void as_load_ssl_cert_and_key(appster_t* a, const char* certificate_chain_path, const char* private_key_file_path);
#endif


/* NOTE: once added, route cannot be romoved! */
int as_add_route(appster_t* a, const char* path, as_route_cb_t cb, appster_schema_entry_t* schema, void* user_data);
int as_add_route_error(appster_t* a, const char* path, as_route_cb_t cb, void* user_data);

int as_listen_and_serve(appster_t* a, const char* addr, uint16_t port, int backlog);

/*
 Check to see if argument exists. Returns 1 if argument is present or 0
 if the argument is missing.
 */
int as_arg_exists(uint32_t idx);
/* Accessors */
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

/*
 Sending body in reply. These functions queue the reply body. Once added data
 is not removed until it's written to the wire. The file sending may use mmap
 or sendfile() api's. Content-Length header is added automatically.
 */
int as_write(const char* data, int64_t len);
int as_write_f(const char* format, ...);
int as_write_fd(int fd, int64_t offset, int64_t len);
int as_write_file(const char* path, int64_t offset, int64_t len);

/*
 Read the request body if present. Returns the amount of bytes read or -1
 if error occured. Reads up to max amount of bytes. The functions do not
 return until either the whole body is read, the max bytes is read or the
 error occurs.
 */
int64_t as_read(char* where, int64_t max);
/*
 Read from the wire directly to the fd,
 */
int64_t as_read_to_fd(int fd, int64_t max);
/*
 Read from the wire directly to the file
 */
int64_t as_read_to_file(const char* path, int64_t max);


/*
 MODULES
 */

/*
 Initialization and destruction
 */
typedef void (*as_module_free_cb_t) ();
typedef void (*as_module_init_loop_cb_t) (void* loop);
typedef void (*as_module_free_loop_cb_t) ();

typedef struct appster_module_s {
    as_module_free_cb_t free_cb;
    as_module_init_loop_cb_t init_loop_cb;
    as_module_free_loop_cb_t free_loop_cb;
} appster_module_t;

typedef int (*as_module_init_cb_t) (appster_module_t* m);
int as_module_init(appster_t* a, as_module_init_cb_t cb);

/*
 Communication

 Create a channel handle. Never modify returned handle manually. Casting
 should be done using as_channel_from_*() functions. Once created channel
 should be freed. as_channel_recv() function frees the channel automatically,
 as_channel_pass() does not. They are both used to receive data from the
 channel. as_channel_send() is used to send data via channel.
 as_channel_good() can be used to check if the channel WAS allocated at some
 point; it does not check if the channel was freed!
 */
appster_channel_t as_channel_alloc();
void as_channel_free(appster_channel_t ch);
appster_channel_t as_channel_from_ptr(void* ptr);
appster_channel_t as_channel_from_int(int i);
void as_channel_send(appster_channel_t ch, void* what);
void* as_channel_recv(appster_channel_t ch);
void* as_channel_pass(appster_channel_t ch);
int as_channel_good(appster_channel_t ch); /* returns non-zero if good */


#endif /* APPSTER_H */
