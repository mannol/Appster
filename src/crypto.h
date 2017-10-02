#ifndef CRYPTO_H
#define CRYPTO_H

typedef struct ssl_ctx_st ssl_ctx_t;
typedef struct ssl_st ssl_t;

typedef enum {
    CM_SERVER,
    CM_CLIENT
} crypto_mode_t;

void crypto_alloc();
void crypto_free();

ssl_ctx_t* crypto_alloc_ctx(crypto_mode_t mode, const char* cert_chain_file, const char* key_file);
ssl_t* crypto_alloc_ssl(ssl_ctx_t* ctx, int fd, crypto_mode_t mode);
void crypto_free_ssl(ssl_t* ssl);
int crypto_read(ssl_t* ssl, void* to, int max);
int crypto_write(ssl_t* ssl, const void* data, int size);
int crypto_error_needs_data_only(ssl_t* ssl, int err); /* Returns 1 if true */

#endif /* CRYPTO_H */
