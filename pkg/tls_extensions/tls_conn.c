#include "atls_extensions.h"
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <ifaddrs.h>

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

int load_certificates_from_memory(SSL_CTX* ctx, const char* cert, int cert_len, const char* key, int key_len) {
    BIO* cert_bio = BIO_new_mem_buf(cert, cert_len);
    if (cert_bio == NULL) {
        ERR_print_errors_fp(stderr);
        return 0;
    }

    BIO* key_bio = BIO_new_mem_buf(key, key_len);
    if (key_bio == NULL) {
        BIO_free(cert_bio);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    X509* x509_cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
    if (x509_cert == NULL) {
        BIO_free(cert_bio);
        BIO_free(key_bio);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(key_bio, NULL, 0, NULL);
    if (pkey == NULL) {
        X509_free(x509_cert);
        BIO_free(cert_bio);
        BIO_free(key_bio);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if (SSL_CTX_use_certificate(ctx, x509_cert) <= 0) {
        X509_free(x509_cert);
        EVP_PKEY_free(pkey);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        X509_free(x509_cert);
        EVP_PKEY_free(pkey);
        ERR_print_errors_fp(stderr);
        return 0;
    }

    X509_free(x509_cert);
    EVP_PKEY_free(pkey);
    BIO_free(cert_bio);
    BIO_free(key_bio);

    return 1;
}

SSL_CTX *create_context(int is_server) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    if (is_server) {
        method = TLS_server_method();
    } else {
        method = TLS_client_method();
    }
    
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    return ctx;
}

int configure_context(SSL_CTX *ctx, char *cert_file, char *key_file) {
    printf("Cert file: %s\n", cert_file);
    printf("Key file: %s\n", key_file);
    // Load server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 ||
        SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        perror("could not configure context");
        return EXIT_FAILURE;
    }
    return 0;
}

void sprint_string_hex(char* dst, const unsigned char* s, int len){ 
    for(int i = 0; i < len; i++){
        sprintf(dst, "%02x", (unsigned int) *s++);
        dst+=2;
    }
}

int compute_sha256_of_public_key(X509 *cert, unsigned char *hash) {
    EVP_PKEY *pkey = NULL;
    unsigned char *pubkey_buf = NULL;
    int pubkey_len = 0;

    pkey = X509_get_pubkey(cert);
    if (pkey == NULL) {
        fprintf(stderr, "Failed to extract public key from certificate\n");
        return 0;
    }
    
    // Convert the public key to DER format (binary encoding)
    pubkey_len = i2d_PUBKEY(pkey, &pubkey_buf);
    if (pubkey_len <= 0) {
        fprintf(stderr, "Failed to convert public key to DER format\n");
        EVP_PKEY_free(pkey);
        return 0;
    }
    
    // Compute the SHA-256 hash of the DER-encoded public key
    SHA256(pubkey_buf, pubkey_len, hash);
    
    // Clean up
    EVP_PKEY_free(pkey);
    OPENSSL_free(pubkey_buf);  // Free memory allocated by i2d_PUBKEY
    
    return 1;  // Success
}

int add_custom_tls_extension(SSL_CTX *ctx) {
    uint32_t flags_nonce = SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS;
    uint32_t flags_attestation = SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_CERTIFICATE;
    int ret = 0;

    ret = SSL_CTX_add_custom_ext(ctx, 
                            EVIDENCE_REQUEST_HELLO_EXTENSION_TYPE,
                            flags_nonce,
                            evidence_request_ext_add_cb, 
                            evidence_request_ext_free_cb, 
                            NULL, 
                            evidence_request_ext_parse_cb, 
                            NULL);
    
    if (ret != 1) {
        return 0;
    }

    ret = SSL_CTX_add_custom_ext(ctx, 
                        ATTESTATION_CERTIFICATE_EXTENSION_TYPE,
                        flags_attestation,
                        attestation_certificate_ext_add_cb, 
                        attestation_certificate_ext_free_cb, 
                        NULL, 
                        attestation_certificate_ext_parse_cb, 
                        NULL);
    if (ret != 1) {
        return 0;
    }

    return ret;
}

// Function to start the tls server
tls_server_connection* start_tls_server(const char* cert, int cert_len, const char* key, int key_len, const char* ip, int port) {
    tls_server_connection *tls_server = (tls_server_connection*)malloc(sizeof(tls_server_connection));

    fprintf(stderr, "Start TLS called on: IP (%s) and PORT (%d)\n", ip, port);

    init_openssl();
    tls_server->ctx = create_context(TLS_SERVER_CTX);
    if (tls_server->ctx == NULL) {
        free(tls_server);
        perror("Unable to create contex");
        return NULL;
    }

    if (!load_certificates_from_memory(tls_server->ctx, cert, cert_len, key, key_len)) {
        fprintf(stderr, "Failed to load certificates\n");
        free(tls_server);
        return NULL;
    }
    // add_custom_tls_extension(tls_server->ctx);

    tls_server->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (tls_server->server_fd < 0) {
        free(tls_server);
        perror("Unable to create socket");
        return NULL;
    }

    tls_server->addr.sin_family = AF_INET;
    tls_server->addr.sin_port = htons(port);

    // in the case that the ip is an empty string or NULL, the ip will be 0.0.0.0 
    if (ip == NULL || ((strlen(ip) + 1) < INET_ADDRSTRLEN)) {
        tls_server->addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (inet_pton(AF_INET, ip, &(tls_server->addr.sin_addr)) <= 0) {
            perror("Invalid IP address");
            free(tls_server);
            return NULL;
        }
    }

    if (bind(tls_server->server_fd, (struct sockaddr*)&(tls_server->addr), sizeof(tls_server->addr)) < 0) {
        perror("Unable to bind");
        free(tls_server);
        return NULL;
    }

    if (listen(tls_server->server_fd, 1) < 0) {
        perror("Unable to listen");
        free(tls_server);
        return NULL;
    }

    printf("Listening on port: %d\n", port);
    return tls_server;
}

// Function to accept a client connection
tls_connection* tls_server_accept(tls_server_connection *tls_server) {
    uint32_t len = sizeof(tls_server->addr);
    tls_connection *conn = (tls_connection*)malloc(sizeof(tls_connection));

    int client_fd = accept(tls_server->server_fd, (struct sockaddr*)&(tls_server->addr), &len);
    if (client_fd < 0) {
        perror("Unable to accept");
        free(conn);
        return NULL;
    }

    conn->ssl = SSL_new(tls_server->ctx);
    conn->socket_fd = client_fd;
    conn->ctx = NULL;
    SSL_set_fd(conn->ssl, client_fd);

    if (SSL_accept(conn->ssl) <= 0) {
        printf("Unable to accept. Handshake failed.\n");
        free(conn);
        return NULL;
    }

    return conn;
}

char* tls_return_ip(struct sockaddr_in  *addr) {
    char *ip_str = (char*)malloc(INET_ADDRSTRLEN*sizeof(char));

    if (inet_ntop(AF_INET, &(addr->sin_addr), ip_str, INET_ADDRSTRLEN) == NULL) {
        perror("inet_ntop");
        free(ip_str);
        return NULL;
    }

    return ip_str;
}

char* tls_server_return_ip(tls_server_connection *tls_server) {
    socklen_t len = sizeof(tls_server->addr);

    printf("tls_server_return_ip called: \n");
    if (getsockname(tls_server->server_fd, (struct sockaddr*)(&tls_server->addr), &len) == -1) {
        return NULL;
    }

    return tls_return_ip(&(tls_server->addr));
}

int tls_server_return_port(tls_server_connection *tls_server) {
    return ntohs(tls_server->addr.sin_port);
}

// Function to close the server
int tls_server_close(tls_server_connection *tls_server) {
    close(tls_server->server_fd);
    SSL_CTX_free(tls_server->ctx);
    cleanup_openssl();
    free(tls_server);
    return 0;
}

int tls_read(tls_connection *conn, void *buf, int num) {
    return SSL_read(conn->ssl, buf, num);
}

int tls_write(tls_connection *conn, const void *buf, int num) {
    if (SSL_get_shutdown(conn->ssl) & SSL_SENT_SHUTDOWN) {
        return 0;
    }

    return SSL_write(conn->ssl, buf, num);
}

int tls_close(tls_connection *conn) { // int free_res
    if (conn != NULL) {
        
        if (conn->ssl != NULL) {
            int ret = 0;

            // Maybe delete while loop
            // while(ret != 1) {
            ret = SSL_shutdown(conn->ssl);
            printf("Try to shutdown! Ret: %d\n", ret);

            if (ret < 0) {
                printf("SSL did not shutdown correctly: %d\n", ret);
                free(conn);
                close(conn->socket_fd);
                conn = NULL;
                return -1;
            } else if (ret == 1) {
                printf("SHUTDOWN SUCCESSFULLY!\n");
            } else if (ret == 0) {
                printf("SHUTDOWN in PROGRESS\n");
                return 0;
            }
            // }
            conn->ssl = NULL;
        }
        if (conn->socket_fd >= 0) {
            close(conn->socket_fd);
            conn->socket_fd = -1;
        }
        SSL_free(conn->ssl);
        if (conn->ctx != NULL) {
            SSL_CTX_free(conn->ctx);
            conn->ctx = NULL;
        }

        free(conn);
        conn = NULL;
        printf("tls_close then called\n");
        return 1;
    } else {
        printf("tls_close else called\n");
    }

    return 0;
}

int tls_get_error(tls_connection *conn, int ret) {
    int err = SSL_get_error(conn->ssl, ret);

    switch (err) {
        case SSL_ERROR_NONE:
            return 0;  // No error
        case SSL_ERROR_ZERO_RETURN:
            return -1; // TLS connection closed
        case SSL_ERROR_WANT_READ:
        case SSL_ERROR_WANT_WRITE:
            return -2; // Operation not complete, retry later
        case SSL_ERROR_SYSCALL:
            return -3; // I/O error
        case SSL_ERROR_SSL:
            return -4;
        default:
            return -6; // Generic SSL error
    }
}

char* tls_conn_return_addr(tls_connection *conn) {
    socklen_t len = sizeof(conn->local_addr);

    if (getsockname(conn->socket_fd, (struct sockaddr*)(&conn->local_addr), &len) == -1) {
        return NULL;
    }

    return tls_return_ip(&(conn->local_addr));
}

char* tls_conn_remote_addr(tls_connection *conn) {
    socklen_t addr_len = sizeof(conn->remote_addr);
    char *ip_str = (char*)malloc(INET_ADDRSTRLEN*sizeof(char));

    if (getpeername(conn->socket_fd, (struct sockaddr*)&(conn->remote_addr), &addr_len) == -1) {
        perror("getpeername failed");
        free(ip_str);
        return NULL;
    }

    if (inet_ntop(AF_INET, &(conn->remote_addr.sin_addr), ip_str, INET_ADDRSTRLEN) == NULL) {
        perror("inet_ntop failed");
        free(ip_str);
        return NULL;
    }

    return ip_str;
}

int tls_return_local_port(tls_connection *conn) {
    return ntohs(conn->local_addr.sin_port);
}

int tls_return_remote_port(tls_connection *conn) {
    return ntohs(conn->remote_addr.sin_port);
}

void custom_free(void *ptr) {
    free(ptr);
}

tls_connection* new_tls_connection(char *address, int port) {
    SSL_CTX *ctx;
    SSL *ssl;
    int server_fd;
    tls_connection *tls_client = (tls_connection*)malloc(sizeof(tls_connection));

    init_openssl();
    ctx = create_context(TLS_CLIENT_CTX);
    if (ctx == NULL) {
        perror("could not create context");
        free(tls_client);
        return NULL;
    }
    // add_custom_tls_extension(ctx);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("unable to create socket");
        free(tls_client);
        return NULL;
    }

    tls_client->local_addr.sin_family = AF_INET;
    tls_client->local_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, address, &(tls_client->local_addr.sin_addr)) <= 0) {
        fprintf(stderr, "failed to get ip address in string form: %s\n", address);
        perror("Invalid IP address\n");
        return NULL;
    }

    if (connect(server_fd, (struct sockaddr*)&(tls_client->local_addr), sizeof(tls_client->local_addr)) < 0) {
        perror("unable to connect");
        free(tls_client);
        return NULL;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_fd);

    if (SSL_connect(ssl) <= 0) {
        perror("unable to connect");
        free(tls_client);
        return NULL;
    }

    tls_client->socket_fd = server_fd;
    tls_client->ssl = ssl;
    tls_client->ctx = ctx;
    return tls_client;
}

int set_socket_timeout(tls_connection* conn, int timeout_sec, int timeout_usec) {
    struct timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = timeout_usec;

    if (setsockopt(conn->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        return -1;
    }

    if (setsockopt(conn->socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        return -1;
    }

    return 0;
}
