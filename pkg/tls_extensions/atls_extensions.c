#include "atls_extensions.h"
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

extern int callVerificationValidationCallback(uintptr_t callbackHandle, const u_char* attReport, int attReportSize, const u_char* repData);
extern u_char* callFetchAttestationCallback(uintptr_t callbackHandle, const u_char* reportDataByte, int* outlen);

int triggerVerificationValidationCallback(uintptr_t callbackHandle, u_char *attestationReport, int reportSize, u_char *reportData) {
    int outlen = 0;

    fprintf(stderr, "Triggering VerificationValidationCallback C...\n");

    if (attestationReport == NULL || reportData == NULL) {
        fprintf(stderr, "attestation data and report data cannot be NULL\n");
        return -1;
    }


    return callVerificationValidationCallback(callbackHandle, attestationReport, reportSize, reportData);
}

u_char* triggerFetchAttestationCallback(uintptr_t callbackHandle, char *reportData) {
    int outlen = REPORT_DATA_SIZE;

    fprintf(stderr, "Triggering FetchAttestationCallback from C...\n");

    if(reportData == NULL) {
        fprintf(stderr, "Report data cannot be NULL");
        return NULL;
    }

    return callFetchAttestationCallback(callbackHandle, reportData, &outlen);
}

void cpuid(unsigned int leaf, unsigned int subleaf, unsigned int* eax, unsigned int* ebx, unsigned int* ecx, unsigned int* edx) {
    __asm__ __volatile__(
        "cpuid"
        : "=a" (*eax), "=b" (*ebx), "=c" (*ecx), "=d" (*edx)
        : "a" (leaf), "c" (subleaf)
    );
}

int check_sev_snp() {
    unsigned int eax, ebx, ecx, edx;

    cpuid(CPUID_EXTENDED_FEATURES, 0, &eax, &ebx, &ecx, &edx);

    if (eax & (1 << 2)) {
        fprintf(stderr, "SEV-SNP is supported\n");
        return 1;
    } 

    fprintf(stderr, "SEV-SNP is NOT supported\n");
    return 0;
}

int compute_sha256_of_public_key_nonce(X509 *cert, u_char *nonce, u_char *hash) {
    EVP_PKEY *pkey = NULL;
    u_char *pubkey_buf = NULL;
    u_char *concatinated = NULL;
    int pubkey_len = 0;
    int totla_len = 0; 

    pkey = X509_get_pubkey(cert);
    if (pkey == NULL) {
        fprintf(stderr, "Failed to extract public key from certificate\n");
        return 0;
    }

    pubkey_len = i2d_PUBKEY(pkey, &pubkey_buf);
    if (pubkey_len <= 0) {
        fprintf(stderr, "Failed to convert public key to DER format\n");
        EVP_PKEY_free(pkey);
        return -1;
    }
    
    totla_len = pubkey_len + CLIENT_RANDOM_SIZE;
    concatinated = (u_char*)malloc(totla_len);
    if (concatinated == NULL) {
        perror("failed to allocate memory");
        return -1;
    }
    memcpy(concatinated, nonce, CLIENT_RANDOM_SIZE);
    memcpy(concatinated + CLIENT_RANDOM_SIZE, pubkey_buf, pubkey_len);

    // Compute the SHA-256 hash of the DER-encoded public key
    SHA512(concatinated, totla_len, hash);

    // Clean up
    EVP_PKEY_free(pkey);
    OPENSSL_free(pubkey_buf);
    free(concatinated);
    
    return 0;  // Success
}

void print_data(int inlen, const char *in) {
    char* hex_buffer = malloc(inlen*2 + 1);
    sprint_string_hex(hex_buffer, in, inlen);

    fprintf(stderr, "Report data: %s\n", hex_buffer);
    free(hex_buffer);
}

/*
    Evidence request extension
    - Contains a random nonce that goes into the attestation report
    - Is sent in the ClientHello message
*/
void evidence_request_ext_free_cb(SSL *s, unsigned int ext_type,
                                    unsigned int context,
                                    const u_char *out,
                                    void *add_arg)
{
    fprintf(stderr, "evidence_request_ext_free_cb called\n");
    free((void *)out);
}

int evidence_request_ext_add_cb(SSL *s, unsigned int ext_type,
                                unsigned int context,
                                const u_char **out,
                                size_t *outlen, X509 *x,
                                size_t chainidx, int *al,
                                void *add_arg)
{
    switch (context)
    {
    case SSL_EXT_CLIENT_HELLO:
        {
            tls_extension_data *ext_data = (tls_extension_data*)add_arg;
            u_char* client_random_buffer = malloc(CLIENT_RANDOM_SIZE);

            if (ext_data != NULL) {
                fprintf(stderr, "evidence_request_ext_add_cb Context: add_arg is not NULL\n");
                ext_data->data = (char*)malloc(CLIENT_RANDOM_SIZE);
                ext_data->data_length = CLIENT_RANDOM_SIZE;
                SSL_get_client_random(s, ext_data->data, CLIENT_RANDOM_SIZE);
            } else {
                fprintf(stderr, "evidence_request_ext_add_cb Context: add_arg is NULL\n");
            }

            SSL_get_client_random(s, client_random_buffer, CLIENT_RANDOM_SIZE);
            fprintf(stderr, "evidence_request_ext_add_cb Context: SSL_EXT_CLIENT_HELLO\n");

            *out = client_random_buffer;
            *outlen = CLIENT_RANDOM_SIZE;
            return 1;
        }
    case SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS:
        {
            uint32_t *platform_type = (u_int32_t*)malloc(sizeof(u_int32_t));
            if (check_sev_snp()) {
                *platform_type = AMD_TEE; 
            } else {
                *platform_type = NO_TEE;
            }

            *out = (u_char*)platform_type;
            *outlen = sizeof(u_int32_t);
        }
        fprintf(stderr, "evidence_request_ext_add_cb from server: %u\n", context);
        return 1;
    default:
        break;
    }

    return 0;
}

int evidence_request_ext_parse_cb(SSL *s, unsigned int ext_type,
                                    unsigned int context,
                                    const u_char *in,
                                    size_t inlen, X509 *x,
                                    size_t chainidx, int *al,
                                    void *parse_arg)
{
    char* hex_buffer = malloc(inlen*2 + 1);
    sprint_string_hex(hex_buffer, in, inlen);

    fprintf(stderr, "evidence_request_ext_parse_cb called\n");
    fprintf(stderr, "Receiving nonce from client: %s\n", hex_buffer);
    free(hex_buffer);

    switch (context)
    {
    case SSL_EXT_CLIENT_HELLO:
        tls_extension_data *ext_data = (tls_extension_data*)parse_arg;

        fprintf(stderr, "evidence_request_ext_parse_cb for SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS called\n");

        if (ext_data != NULL) {
            ext_data->data = malloc((inlen + 1)*sizeof(char));

            if (ext_data->data == NULL) {
                fprintf(stderr, "evidence_request_ext_parse_cb could not allocate memory\n");
                return 0;
            }
            memcpy(ext_data->data, in, inlen);
            ext_data->data[inlen] = '\0';
            ext_data->data_length = inlen;
            fprintf(stderr, "evidence_request_ext_parse_cb: successfully copied %ld bytes\n", inlen);
        } else {
            fprintf(stderr, "evidence_request_ext_parse_cb extension data cannot be NULL\n");
            return 0;
        }
        return 1;
    case SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS:
        u_int32_t *tee_type = (u_int32_t*)in;
        fprintf(stderr, "evidence_request_ext_parse_cb for SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS called, TEE type: %u\n", *tee_type);
        return 1;
    default:
        fprintf(stderr, "evidence_request_ext_parse_cb bad context\n");
        return 0;
    }
}

/*
    Attestation Certificate extension
    - Contains the attestation report
    - The attestation report contains the hash of the nonce and the Publik Key of the x.509 Agent certificate
*/
void  attestation_certificate_ext_free_cb(SSL *s, unsigned int ext_type,
                                    unsigned int context,
                                    const u_char *out,
                                    void *add_arg)
{
    free((void *)out);
}

int attestation_certificate_ext_add_cb(SSL *s, unsigned int ext_type,
                                unsigned int context,
                                const u_char **out,
                                size_t *outlen, X509 *x,
                                size_t chainidx, int *al,
                                void *add_arg)
{
    switch (context)
    {
    case SSL_EXT_TLS1_3_CERTIFICATE:
        tls_extension_data *ext_data = (tls_extension_data*)add_arg;
        if (ext_data != NULL) {
            u_char *attestation_report;
            u_char *hash = (u_char*)malloc(REPORT_DATA_SIZE*sizeof(u_char));

            if (hash == NULL) {
                perror("could not allocate memory");
                return 0;
            }

            if (x != NULL) {
                int ret = compute_sha256_of_public_key_nonce(x, ext_data->data, hash);
                if (ret != 0) {
                    fprintf(stderr, "error while calculating hash\n");
                    free(hash);
                    return 0;
                }
            } else {
                fprintf(stderr, "certificate must be used for aTLS\n");
                free(hash);
                return 0;
            }

            attestation_report = triggerFetchAttestationCallback(ext_data->fetch_attestation_handler, hash);
            fprintf(stderr, "attestation_certificate_ext_add_cb: SSL_EXT_TLS1_3_CERTIFICATE\n");
            free(hash);

            *out = attestation_report;
            *outlen = ATTESTATION_REPORT_SIZE;
            return 1;
        } else {
            fprintf(stderr, "attestation_certificate_ext_add_cb: add exstension data cannot be NULL\n");
            return 0;
        }
    default:
        fprintf(stderr, "Default attestation_certificate_ext_add_cb called: %u\n", context);
        return 1;
    }
}

int  attestation_certificate_ext_parse_cb(SSL *s, unsigned int ext_type,
                                          unsigned int context,
                                          const u_char *in,
                                          size_t inlen, X509 *x,
                                          size_t chainidx, int *al,
                                          void *parse_arg)
{
    switch (context)
    {
    case SSL_EXT_CLIENT_HELLO:
        fprintf(stderr, "attestation_certificate_ext_parse_cb server called\n");
        break;
    case SSL_EXT_TLS1_3_CERTIFICATE:
        if (x != NULL) {
            tls_extension_data *ext_data = (tls_extension_data*)parse_arg;

            fprintf(stderr, "X509 certificate is not null.\n");
            fprintf(stderr, "Context: %u\n", context);

            if (ext_data != NULL) {
                char *attestation_report = (char*)malloc(ATTESTATION_REPORT_SIZE*sizeof(char));
                int res = 0;
                u_char *hash = (u_char*)malloc(REPORT_DATA_SIZE*sizeof(u_char));

                if (x != NULL) {
                    int ret = compute_sha256_of_public_key_nonce(x, ext_data->data, hash);
                    if (ret != 0) {
                        fprintf(stderr, "error while calculating hash\n");
                        free(hash);
                        return 0;
                    }
                } else {
                    fprintf(stderr, "certificate must be used for aTLS\n");
                    free(hash);
                    return 0;
                }

                print_data(REPORT_DATA_SIZE, hash);
                memcpy(attestation_report, in, inlen);

                res = triggerVerificationValidationCallback(ext_data->verification_validation_handler, 
                                                    attestation_report,
                                                    ATTESTATION_REPORT_SIZE,
                                                    hash);
                free(attestation_report);
                free(hash);
                
                if (res != 0) {
                    fprintf(stderr, "verification and validation failed, aborting connection\n");
                    return 0;
                }
            } else {
                fprintf(stderr, "extension data cannot be NULL\n");
                return 0;
            }
            break;
        } else {
            fprintf(stderr, "certificates must be used for aTLS\n");
            return 0;
        }
    }

    return 1;
}
