#include "extensions.h"
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
    BIO* cert_bio = NULL;
    BIO* key_bio = NULL;
    X509* x509_cert = NULL;
    EVP_PKEY* pkey = NULL;
    int success = 0;

    cert_bio = BIO_new_mem_buf(cert, cert_len);
    if (cert_bio == NULL) {
        goto cleanup;
    }

    key_bio = BIO_new_mem_buf(key, key_len);
    if (key_bio == NULL) {
        goto cleanup;
    }

    x509_cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
    if (x509_cert == NULL) {
        goto cleanup;
    }

    pkey = PEM_read_bio_PrivateKey(key_bio, NULL, 0, NULL);
    if (pkey == NULL) {
        goto cleanup;
    }

    if (SSL_CTX_use_certificate(ctx, x509_cert) <= 0) {
        goto cleanup;
    }

    if (SSL_CTX_use_PrivateKey(ctx, pkey) <= 0) {
        goto cleanup;
    }

    if (SSL_CTX_check_private_key(ctx) <= 0) {
        goto cleanup;
    }

    success = 1;

cleanup:
    if (cert_bio) BIO_free(cert_bio);
    if (key_bio) BIO_free(key_bio);
    if (x509_cert) X509_free(x509_cert);
    if (pkey) EVP_PKEY_free(pkey);
    
    if (!success) {
        ERR_print_errors_fp(stderr);
    }
    
    return success;
}

int enforce_tls1_3_only(SSL_CTX *ctx) {
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 0) {
        return 0;
    }
    if (SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 0) {
        return 0;
    }

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

    if (!enforce_tls1_3_only(ctx)) {
        fprintf(stderr, "could not enforce TLS1.3\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    return ctx;
}

int add_custom_tls_extension(SSL_CTX *ctx, tls_connection *conn) {
    uint32_t flags_nonce = SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS;
    uint32_t flags_attestation = SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_CERTIFICATE;
    int ret = 1;
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
tls_server_connection* start_tls_server(const char* cert, int cert_len, const char* key, int key_len, const char* ip, int port) {
    tls_server_connection *tls_server = (tls_server_connection*)malloc(sizeof(tls_server_connection));
    int opt = 0;

    if (tls_server == NULL) {
        perror("memory could not be allocated");
        return NULL;
    }

    init_openssl();

    tls_server->cert = (char*)malloc(cert_len * sizeof(char));
    if (tls_server->cert == NULL) {
        perror("memory could not be allocated");
        goto cleanup_tls_server;
    }

    tls_server->key = (char*)malloc(key_len * sizeof(char));
    if (tls_server->key == NULL) {
        perror("memory could not be allocated");
        goto cleanup_cert;
    }

    memcpy(tls_server->cert, cert, cert_len);
    memcpy(tls_server->key, key, key_len);
    tls_server->cert_len = cert_len;
    tls_server->key_len = key_len;

    tls_server->server_fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (tls_server->server_fd < 0) {
        perror("Unable to create socket");
        goto cleanup_key;
    }

    // Enable both IPv4-mapped and IPv6 addresses
    if (setsockopt(tls_server->server_fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) != 0) {
        perror("setsockopt(IPV6_V6ONLY) failed");
        goto cleanup_socket;
    }

    // Configure address structure
    memset(&(tls_server->addr), 0, sizeof(tls_server->addr));
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&tls_server->addr;
    addr6->sin6_family = AF_INET6;
    addr6->sin6_port = htons(port);

    // Set the appropriate address (IPv4-mapped if needed)
    if (ip == NULL || (strlen(ip) + 1) < INET_ADDRSTRLEN) {
        addr6->sin6_addr = in6addr_any;
    } else if (strchr(ip, ':') != NULL) {
        if (inet_pton(AF_INET6, ip, &(addr6->sin6_addr)) <= 0) {
            perror("Invalid IPv6 address");
            goto cleanup_socket;
        }
    } else {
        struct in_addr ipv4_addr;
        if (inet_pton(AF_INET, ip, &ipv4_addr) <= 0) {
            perror("Invalid IPv4 address");
            goto cleanup_socket;
        }
        memset(&addr6->sin6_addr, 0, sizeof(addr6->sin6_addr));
        addr6->sin6_addr.s6_addr[10] = 0xff;
        addr6->sin6_addr.s6_addr[11] = 0xff;
        memcpy(&addr6->sin6_addr.s6_addr[12], &ipv4_addr, sizeof(ipv4_addr));
    }

    if (bind(tls_server->server_fd, (struct sockaddr*)&(tls_server->addr), sizeof(tls_server->addr)) < 0) {
        perror("Unable to bind");
        goto cleanup_socket;
    }

    if (listen(tls_server->server_fd, SOMAXCONN) < 0) {
        perror("Unable to listen");
        goto cleanup_socket;
    }

    printf("Listening on port: %d\n", port);
    return tls_server;

    // Cleanup labels
cleanup_socket:
    close(tls_server->server_fd);
cleanup_key:
    free(tls_server->key);
cleanup_cert:
    free(tls_server->cert);
cleanup_tls_server:
    free(tls_server);
    return NULL;
}

// Function to accept a client connection
tls_connection* tls_server_accept(tls_server_connection *tls_server) {
    uint32_t len = sizeof(struct sockaddr_storage);
    tls_connection *conn = (tls_connection*)malloc(sizeof(tls_connection));
    int client_fd = -1;
    int ret = 0;

    if (conn == NULL) {
        perror("Unable to allocate memory for tls_connection");
        return NULL;
    }
    conn->ctx = NULL;
    conn->ssl = NULL;
    conn->socket_fd = -1;

    // Initialize the context
    conn->ctx = create_context(TLS_SERVER_CTX);
    if (conn->ctx == NULL) {
        perror("Unable to create context");
        goto cleanup_conn;
    }

    // Load certificates
    if (!load_certificates_from_memory(conn->ctx, tls_server->cert, tls_server->cert_len, tls_server->key, tls_server->key_len)) {
        fprintf(stderr, "Failed to load certificates\n");
        goto cleanup_ctx;
    }

    // Add custom TLS extension
    ret = add_custom_tls_extension(conn->ctx, conn);
    if (!ret) {
        perror("Unable to add custom tls extensions");
        goto cleanup_ctx;
    }

    // Accept client connection
    client_fd = accept(tls_server->server_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("Unable to accept connection");
        goto cleanup_ctx;
    }

    // Create SSL object
    conn->ssl = SSL_new(conn->ctx);
    if (conn->ssl == NULL) {
        perror("Unable to create SSL object");
        goto cleanup_fd;
    }

    // Set file descriptor
    conn->socket_fd = client_fd;
    SSL_set_fd(conn->ssl, client_fd);

    // Get local address
    if (getsockname(client_fd, (struct sockaddr *)&conn->local_addr, &len) == -1) {
        perror("getsockname failed during TLS server accept");
        goto cleanup_ssl;
    }

    // Get remote address
    if (getpeername(client_fd, (struct sockaddr *)&conn->remote_addr, &len) == -1) {
        perror("getpeername failed during TLS server accept");
        goto cleanup_ssl;
    }

    // Perform SSL handshake
    ret = SSL_accept(conn->ssl);
    if (ret <= 0) {
        perror("SSL handshake failed during accept");
        goto cleanup_ssl;
    }

    return conn;

cleanup_ssl:
    if (conn->ssl) SSL_free(conn->ssl);
cleanup_fd:
    if (client_fd >= 0) close(client_fd);
cleanup_ctx:
    if (conn->ctx) SSL_CTX_free(conn->ctx);
cleanup_conn:
    free(conn);
    return NULL;
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
            int ret = 0;

            if (SSL_has_pending(conn->ssl) == 1 || (SSL_get_shutdown(conn->ssl) & SSL_SENT_SHUTDOWN)) {
                int num = SSL_pending(conn->ssl);
                char c[num];
                int res = 0;
                int end = 0;

                res = SSL_read(conn->ssl, (void*)c, num);
                res = SSL_get_error(conn->ssl, res);

                if (res == SSL_ERROR_ZERO_RETURN) {
                    end = 1;
                } else if (res != SSL_ERROR_NONE) {
                    fprintf(stderr, "SSL_read failed in TLS close call\n");
                    end = 1;
                }

                if ((SSL_get_shutdown(conn->ssl) & SSL_RECEIVED_SHUTDOWN) || end == 1) {
                    ret = SSL_shutdown(conn->ssl);
                }
            } else {
                ret = SSL_shutdown(conn->ssl);
            }

            if (ret < 0) {
                ret = SSL_get_error(conn->ssl, ret);
                fprintf(stderr, "SSL did not shutdown correctly, error code: %d\n", ret);
                free(conn);
                close(conn->socket_fd);
                conn = NULL;
                return -1;
            } else if (ret == 0) {
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

        free(conn);
        conn = NULL;
        return 1;
    }

    return 1;
}

char* tls_return_addr(struct sockaddr_storage *addr) {
    socklen_t addr_len = sizeof(struct sockaddr_storage);
    int inet_size =addr->ss_family == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
    char *ip_str = (char*)malloc(inet_size*sizeof(char));
    void * addr_ptr;

    if (ip_str == NULL) {
        perror("memory could not be allocated");
        return NULL;
    }

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

tls_connection* new_tls_connection(char *address, int port) {
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int socket_fd = -1;
    int status;
    struct addrinfo hints, *res = NULL, *p = NULL;
    char port_str[6];
    tls_connection *conn = NULL;
    socklen_t addr_len;
    int ret = 0;

    conn = (tls_connection*)malloc(sizeof(tls_connection));
    if (!conn) {
        perror("Failed to allocate memory for atls connection");
        return NULL;
    }

    // Format the port string
    snprintf(port_str, sizeof(port_str), "%d", port);

    // Initialize OpenSSL
    init_openssl();

    // Create SSL context
    ctx = create_context(TLS_CLIENT_CTX);
    if (!ctx) {
        perror("Could not create context");
        goto cleanup_conn;
    }

    conn->ctx = ctx;
    // Add custom TLS extension
    ret = add_custom_tls_extension(conn->ctx, conn);
    if (!ret) {
        perror("Unable to add custom tls extensions");
        goto cleanup_ctx;
    }

    // Prepare the address info hints
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    // Get address info
    status = getaddrinfo(address, port_str, &hints, &res);
    if (status != 0) {
        perror("getaddrinfo error");
        goto cleanup_ctx;
    }

    // Iterate through the results and try to connect
    for (p = res; p != NULL; p = p->ai_next) {
        socket_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (socket_fd < 0) {
            perror("unable to create socket");
            continue;
        }

        if (connect(socket_fd, p->ai_addr, p->ai_addrlen)) {
            close(socket_fd);
            continue;
        }

        memcpy(&conn->local_addr, p->ai_addr, p->ai_addrlen);
        break;
    }

    freeaddrinfo(res);

    if (p == NULL) {
        goto cleanup_ctx;
    }

    conn->socket_fd = socket_fd;

    // Retrieve and store the remote address
    addr_len = sizeof(conn->remote_addr);
    if (getpeername(socket_fd, (struct sockaddr *)&conn->remote_addr, &addr_len) == -1) {
        perror("getpeername failed");
        goto cleanup_socket;
    }

    // Create the SSL structure
    ssl = SSL_new(ctx);
    if (!ssl) {
        perror("Failed to create SSL object");
        goto cleanup_socket;
    }

    if (!SSL_set_fd(ssl, socket_fd)) {
        perror("Failed to set SSL file descriptor");
        goto cleanup_ssl;
    }
    conn->ssl = ssl;

    // Perform the SSL handshake
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "SSL handshake failed\n");
        goto cleanup_ssl;
    }

    return conn;

cleanup_ssl:
    if (ssl) SSL_free(ssl);
cleanup_socket:
    if (socket_fd >= 0) close(socket_fd);
cleanup_ctx:
    if (ctx) SSL_CTX_free(ctx);
cleanup_conn:
    free(conn);
    return NULL;
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

int set_socket_read_timeout(tls_connection* conn, int timeout_sec, int timeout_usec) {
    struct timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = timeout_usec;

    if (setsockopt(conn->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        return -1;
    }

    return 0;
}

int set_socket_write_timeout(tls_connection* conn, int timeout_sec, int timeout_usec) {
    struct timeval timeout;
    timeout.tv_sec = timeout_sec;
    timeout.tv_usec = timeout_usec;

    if (setsockopt(conn->socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        return -1;
    }

    return 0;
}