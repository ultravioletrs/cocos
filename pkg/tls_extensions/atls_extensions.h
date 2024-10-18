#ifndef ATLS_EXTENSION_H
#define ATLS_EXTENSION_H

#include <openssl/ssl.h>
#include <arpa/inet.h>

#define EVIDENCE_REQUEST_HELLO_EXTENSION_TYPE 65
#define ATTESTATION_CERTIFICATE_EXTENSION_TYPE 66
#define ATTESTATION_REPORT_SIZE 0x4A0
#define REPORT_DATA_SIZE 64
#define CLIENT_RANDOM_SIZE 32
#define TLS_CLIENT_CTX 0
#define TLS_SERVER_CTX 1

#define CPUID_EXTENDED_FEATURES 0x8000001F
#define NO_TEE 0
#define AMD_TEE 1

typedef struct tls_extension_data
{
    char *data;
    int data_length;
    uintptr_t fetch_attestation_handler;
    uintptr_t verification_validation_handler;
} tls_extension_data;

typedef struct tls_server_connection
{
    int server_fd;
    char* cert; 
    int cert_len;
    char* key;
    int key_len;
    // SSL_CTX *ctx;
    struct sockaddr_storage addr;
    uintptr_t fetch_attestation_handler;
} tls_server_connection;

typedef struct tls_connection
{
    SSL_CTX *ctx;
    SSL *ssl;
    int socket_fd;
    struct sockaddr_storage local_addr;
    struct sockaddr_storage remote_addr;
    tls_extension_data tls_ext_data;
} tls_connection;

void sprint_string_hex(char* dst, const unsigned char* s, int len);
tls_server_connection* start_tls_server(const char* cert, int cert_len, const char* key, int key_len, const char* ip, int port, uintptr_t fetch_handle);
tls_connection* tls_server_accept(tls_server_connection *tls_server);
int tls_server_close(tls_server_connection *tls_server);
int tls_read(tls_connection *conn, void *buf, int num);
int tls_write(tls_connection *conn, const void *buf, int num);
int tls_close(tls_connection *conn);
int tls_extension_client(char *address, int port);
void custom_free(void *ptr);
tls_connection* new_tls_connection(char *address, int port, uintptr_t vv_handle);
int set_socket_timeout(tls_connection* conn, int timeout_sec, int timeout_usec);
char* tls_return_addr(struct sockaddr_storage *addr);
int tls_get_error(tls_connection *conn, int ret);
int tls_return_port(struct sockaddr_storage *addr);
int compute_sha256_of_public_key(X509 *cert, unsigned char *hash);

// Extensions
void evidence_request_ext_free_cb(SSL *s, unsigned int ext_type,
                                    unsigned int context,
                                    const unsigned char *out,
                                    void *add_arg);
int evidence_request_ext_add_cb(SSL *s, unsigned int ext_type,
                                unsigned int context,
                                const unsigned char **out,
                                size_t *outlen, X509 *x,
                                size_t chainidx, int *al,
                                void *add_arg);
int evidence_request_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg);
void  attestation_certificate_ext_free_cb(SSL *s, unsigned int ext_type,
                                    unsigned int context,
                                    const unsigned char *out,
                                    void *add_arg);
int attestation_certificate_ext_add_cb(SSL *s, unsigned int ext_type,
                                unsigned int context,
                                const unsigned char **out,
                                size_t *outlen, X509 *x,
                                size_t chainidx, int *al,
                                void *add_arg);
int  attestation_certificate_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const unsigned char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg);

#endif // ATLS_EXTENSION_H
