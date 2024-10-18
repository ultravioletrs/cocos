#include "atls_extensions.h"
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <netdb.h>
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

    // SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

// TODO: Delete
void sprint_string_hex(char* dst, const unsigned char* s, int len){ 
    for(int i = 0; i < len; i++){
        sprintf(dst, "%02x", (unsigned int) *s++);
        dst+=2;
    }
}

int add_custom_tls_extension(SSL_CTX *ctx, tls_connection *conn) {
    uint32_t flags_nonce = SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS;
    uint32_t flags_attestation = SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_CERTIFICATE;
    int ret = 0;
    void *data = NULL;

    if (conn != NULL) {
        data = (void*)&conn->tls_ext_data;
    }

    ret = SSL_CTX_add_custom_ext(ctx, 
                            EVIDENCE_REQUEST_HELLO_EXTENSION_TYPE,
                            flags_nonce,
                            evidence_request_ext_add_cb, 
                            evidence_request_ext_free_cb, 
                            data, 
                            evidence_request_ext_parse_cb, 
                            data);
    if (ret != 1) {
        return 0;
    }

    ret = SSL_CTX_add_custom_ext(ctx, 
                        ATTESTATION_CERTIFICATE_EXTENSION_TYPE,
                        flags_attestation,
                        attestation_certificate_ext_add_cb, 
                        attestation_certificate_ext_free_cb, 
                        data, 
                        attestation_certificate_ext_parse_cb, 
                        data);
    if (ret != 1) {
        return 0;
    }

    return ret;
}

// Function to start the TLS server
tls_server_connection* start_tls_server(const char* cert, int cert_len, const char* key, int key_len, const char* ip, int port, uintptr_t fetch_handle) {
    tls_server_connection *tls_server = (tls_server_connection*)malloc(sizeof(tls_server_connection));

    fprintf(stderr, "Start TLS called on: IP (%s) and PORT (%d)\n", ip, port);
    init_openssl();

    tls_server->cert = (char*)malloc(cert_len*sizeof(char));
    if (tls_server->cert == NULL) {
        perror("memory not allocated");
        free(tls_server);
        return NULL;
    }

    tls_server->key = (char*)malloc(key_len*sizeof(char));
    if (tls_server->key == NULL) {
        perror("memory not allocated");
        free(tls_server);
        return NULL;
    }

    memcpy(tls_server->cert, cert, cert_len);
    memcpy(tls_server->key, key, key_len);
    tls_server->cert_len = cert_len;
    tls_server->key_len = key_len;
    tls_server->fetch_attestation_handler = fetch_handle;

    // tls_server->ctx = create_context(TLS_SERVER_CTX);
    // if (tls_server->ctx == NULL) {
    //     free(tls_server);
    //     perror("Unable to create contex");
    //     return NULL;
    // }

    // if (!load_certificates_from_memory(tls_server->ctx, cert, cert_len, key, key_len)) {
    //     fprintf(stderr, "Failed to load certificates\n");
    //     free(tls_server);
    //     return NULL;
    // }
    // add_custom_tls_extension(tls_server->ctx, NULL);

    tls_server->server_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (tls_server->server_fd < 0) {
        free(tls_server);
        perror("Unable to create socket");
        return NULL;
    }

    // both IPv4-mapped and IPv6 addresses
    int opt = 0;
    if (setsockopt(tls_server->server_fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) != 0) {
        perror("setsockopt(IPV6_V6ONLY) failed");
        close(tls_server->server_fd);
        free(tls_server);
        return NULL;
    }

    memset(&(tls_server->addr), 0, sizeof(tls_server->addr));
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&tls_server->addr;
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(port);

    // in the case that the ip is an empty string or NULL, the ip will be 0.0.0.0 
    if (ip == NULL || ((strlen(ip) + 1) < INET_ADDRSTRLEN)) {
        addr6->sin6_addr = in6addr_any;
    } else {
        if (strchr(ip, ':') != NULL) {
            // IPv6 address
            if (inet_pton(AF_INET6, ip, &(addr6->sin6_addr)) <= 0) {
                perror("Invalid IPv6 address");
                close(tls_server->server_fd);
                free(tls_server);
                return NULL;
            }
        } else {
            // IPv4 address (IPv4-mapped to IPv6)
            struct in_addr ipv4_addr;
            if (inet_pton(AF_INET, ip, &ipv4_addr) <= 0) {
                perror("Invalid IPv4 address");
                close(tls_server->server_fd);
                free(tls_server);
                return NULL;
            }
            // Use IPv4-mapped IPv6 address (::ffff:IPv4)
            memset(&addr6->sin6_addr, 0, sizeof(addr6->sin6_addr));
            addr6->sin6_addr.s6_addr[10] = 0xff;
            addr6->sin6_addr.s6_addr[11] = 0xff;
            memcpy(&addr6->sin6_addr.s6_addr[12], &ipv4_addr, sizeof(ipv4_addr));
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
    uint32_t len = sizeof(struct sockaddr_storage);
    tls_connection *conn = (tls_connection*)malloc(sizeof(tls_connection));

    conn->ctx = create_context(TLS_SERVER_CTX);
    if (conn->ctx == NULL) {
        free(conn);
        perror("Unable to create contex");
        return NULL;
    }

    if (!load_certificates_from_memory(conn->ctx, tls_server->cert, tls_server->cert_len, tls_server->key, tls_server->key_len)) {
        fprintf(stderr, "Failed to load certificates\n");
        free(conn);
        return NULL;
    }
    add_custom_tls_extension(conn->ctx, conn);

    int client_fd = accept(tls_server->server_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("Unable to accept");
        free(conn);
        return NULL;
    }

    conn->ssl = SSL_new(conn->ctx);
    conn->socket_fd = client_fd;
    conn->ctx = NULL;
    conn->tls_ext_data.data = NULL;
    conn->tls_ext_data.data_length = 0;
    conn->tls_ext_data.fetch_attestation_handler = tls_server->fetch_attestation_handler;
    conn->tls_ext_data.verification_validation_handler = 0;
    SSL_set_fd(conn->ssl, client_fd);

    if (getsockname(client_fd, (struct sockaddr *)&conn->local_addr, &len) == -1) {
        perror("getsockname failed during tls server accept");
        SSL_free(conn->ssl);
        SSL_CTX_free(conn->ctx);
        close(client_fd);
        free(conn);
        return NULL;
    }

    if (getpeername(client_fd, (struct sockaddr *)&conn->remote_addr, &len) == -1) {
        perror("getpeername failed during tls server accept");
        SSL_free(conn->ssl);
        SSL_CTX_free(conn->ctx);
        close(client_fd);
        free(conn);
        return NULL;
    }

    if (SSL_accept(conn->ssl) <= 0) {
        perror("unable to accept. SSL handshake failed");
        SSL_free(conn->ssl);
        SSL_CTX_free(conn->ctx);
        close(client_fd);
        free(conn);
        return NULL;
    }

    return conn;
}

// Function to close the server
int tls_server_close(tls_server_connection *tls_server) {
    close(tls_server->server_fd);
    cleanup_openssl();
    free(tls_server->cert);
    free(tls_server->key);
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

int tls_close(tls_connection *conn) {
    if (conn != NULL) {
        
        if (conn->ssl != NULL) {
            int ret = SSL_shutdown(conn->ssl);

            if (ret < 0) {
                perror("SSL did not shutdown correctly");
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
        if (conn->tls_ext_data.data != NULL) {
            free(conn->tls_ext_data.data);
        }

        free(conn);
        conn = NULL;
        return 1;
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

char* tls_return_addr(struct sockaddr_storage *addr) {
    socklen_t addr_len = sizeof(struct sockaddr_storage);
    int inet_size =addr->ss_family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
    char *ip_str = (char*)malloc(inet_size*sizeof(char));
    void * addr_ptr;

    if (addr->ss_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)addr;
        addr_ptr = &(ipv4->sin_addr);
    } else if (addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)addr;
        addr_ptr = &(ipv6->sin6_addr);
    } else {
        fprintf(stderr, "unknown family: %d\n", addr->ss_family);
        free(ip_str);
        return NULL;
    }

    if (inet_ntop(addr->ss_family, addr_ptr, ip_str, inet_size) == NULL) {
        perror("inet_ntop failed");
        free(ip_str);
        return NULL;
    }

    return ip_str;
}

int tls_return_port(struct sockaddr_storage *addr) {
    if (addr->ss_family == AF_INET) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)addr;
        return ntohs(ipv4->sin_port);
    } else if (addr->ss_family == AF_INET6) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)addr;
         return ntohs(ipv6->sin6_port);
    }

    fprintf(stderr, "cannot return port from unknown family: %d\n", addr->ss_family);
    return -1;
}

void custom_free(void *ptr) {
    free(ptr);
}

tls_connection* new_tls_connection(char *address, int port, uintptr_t vv_handle) {
    SSL_CTX *ctx;
    SSL *ssl;
    int socket_fd;
    int status;
    struct addrinfo hints, *res, *p;
    char port_str[6];
    tls_connection *conn = (tls_connection*)malloc(sizeof(tls_connection));
    socklen_t addr_len;

    snprintf(port_str, sizeof(port_str), "%d", port);

    init_openssl();
    ctx = create_context(TLS_CLIENT_CTX);
    if (ctx == NULL) {
        perror("could not create context");
        free(conn);
        SSL_CTX_free(ctx);
        return NULL;
    }
    
    conn->ctx = ctx;
    conn->tls_ext_data.verification_validation_handler = vv_handle;
    conn->tls_ext_data.fetch_attestation_handler = 0;
    conn->tls_ext_data.data_length = 0;
    conn->tls_ext_data.data = NULL;
    add_custom_tls_extension(ctx, conn);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0; // any protocol.

    if ((status = getaddrinfo(address, port_str, &hints, &res)) != 0) {
        perror("getaddrinfo error");
        free(conn);
        SSL_CTX_free(ctx);
        return NULL;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        socket_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (socket_fd < 0) {
            perror("unable to create socket");
            continue;
        }

        if (connect(socket_fd, p->ai_addr, p->ai_addrlen)) {
            close(socket_fd);
            perror("unable to connect");
            continue;
        }

        fprintf(stderr, "connected on %s\n", address);
        memcpy(&conn->local_addr, p->ai_addr, p->ai_addrlen);
        break;
    }

    freeaddrinfo(res);

    if (p == NULL) {
        perror("failed to connect");
        free(conn);
        SSL_CTX_free(ctx);
        return NULL;
    }
    conn->socket_fd = socket_fd;

    addr_len = sizeof(conn->remote_addr);
    if (getpeername(socket_fd, (struct sockaddr *)&conn->remote_addr, &addr_len) == -1) {
        perror("getpeername failed");
        close(socket_fd);
        free(conn);
        SSL_CTX_free(ctx);
        return NULL;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, socket_fd);
    conn->ssl = ssl;

    if (SSL_connect(ssl) <= 0) {
        perror("unable to SSL connect");
        close(socket_fd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        free(conn);
        return NULL;
    }

    return conn;
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
