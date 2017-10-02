#include "crypto.h"
#include "log.h"

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

void crypto_alloc() {
    RAND_poll();
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}
void crypto_free() {
    EVP_cleanup();
}

ssl_ctx_t* crypto_alloc_ctx(crypto_mode_t mode, const char* cert_chain_file, const char* key_file) {
    const SSL_METHOD *method;
    ssl_ctx_t *ctx;

    if (mode == CM_SERVER) {
        if (!cert_chain_file || !key_file) {
            ELOG("Missing chain or key file for server method");
            return NULL;
        }

        method = SSLv23_server_method();
    } else {
        method = SSLv23_client_method();
    }

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        ELOG("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    SSL_CTX_set_mode(ctx,
                     SSL_MODE_RELEASE_BUFFERS | SSL_MODE_ENABLE_PARTIAL_WRITE);

    SSL_CTX_set_options(ctx,
                        SSL_OP_SINGLE_DH_USE | SSL_OP_SINGLE_ECDH_USE |
                        SSL_OP_NO_SSLv2 | SSL_OP_NO_COMPRESSION);

    SSL_CTX_set_ecdh_auto(ctx, 1);

    if (mode == CM_SERVER) {
        if (SSL_CTX_use_certificate_chain_file(ctx, cert_chain_file) <= 0) {
            ELOG("Failed to use certificate chain file: %s", cert_chain_file);
            goto failure;
        }

        if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
            ELOG("Failed to use private key file: %s", key_file);
            goto failure;
        }
    }

    return ctx;
failure:
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return NULL;
}
ssl_t* crypto_alloc_ssl(ssl_ctx_t* ctx, int fd, crypto_mode_t mode) {
    ssl_t* rc = NULL;

    rc = SSL_new(ctx);
    if (rc) {
        SSL_set_fd(rc, fd);

        if (mode == CM_SERVER) {
            SSL_set_accept_state(rc);
        } else {
            SSL_set_connect_state(rc);
        }
    }

    return rc;
}
void crypto_free_ssl(ssl_t* ssl) {
    if (ssl) {
        SSL_free(ssl);
    }
}
int crypto_accept(ssl_t* ssl) {
    if (!ssl) {
        return -1;
    }
    SSL_set_accept_state(ssl);
    return 0;
//    return SSL_accept(ssl);
}
int crypto_read(ssl_t* ssl, void* to, int max) {
    return SSL_read(ssl, to, max);
}
int crypto_write(ssl_t* ssl, const void* data, int size) {
    return SSL_write(ssl, data, size);
}
int crypto_error_needs_data_only(ssl_t* ssl, int err) {
    if (!ssl) {
        errno = EINVAL;
        return 0;
    }
    err = SSL_get_error(ssl, err);
    if (err == SSL_ERROR_WANT_READ) {
        errno = EAGAIN;
        return 1;
    } else if (err == SSL_ERROR_WANT_WRITE) {
        errno = EAGAIN;
        return 2;
    }
    errno = EINVAL;
    return 0;
}
