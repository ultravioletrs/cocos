#include "extensions.h"
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <fcntl.h>
#include <unistd.h>

extern int callVerificationValidationCallback(uintptr_t callbackHandle, const u_char* attReport, int attReportSize, const u_char* repData);
extern u_char* callFetchAttestationCallback(uintptr_t callbackHandle, const u_char* reportDataByte, int* outlen);
extern uintptr_t validationVerificationCallback(int teeType);
extern uintptr_t fetchAttestationCallback(int teeType);

int triggerVerificationValidationCallback(uintptr_t callbackHandle, u_char *attestationReport, int reportSize, u_char *reportData) {
    if (attestationReport == NULL || reportData == NULL) {
        fprintf(stderr, "attestation data and report data cannot be NULL\n");
        return -1;
    }


    return callVerificationValidationCallback(callbackHandle, attestationReport, reportSize, reportData);
}

u_char* triggerFetchAttestationCallback(uintptr_t callbackHandle, char *reportData) {
    int outlen = REPORT_DATA_SIZE;

    if(reportData == NULL) {
        fprintf(stderr, "Report data cannot be NULL");
        return NULL;
    }

    return callFetchAttestationCallback(callbackHandle, reportData, &outlen);
}

int check_sev_snp() {
    int fd = open(SEV_GUEST_DRIVER_PATH, O_RDONLY);

    if (fd == -1) {
        perror("Error opening /dev/sev-guest");
        fprintf(stderr, "SEV guest driver is not available.\n");
        return -1;
    } else {
        close(fd);
    }

    return 1;
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

    // Compute the SHA-512 hash of the DER-encoded public key and the random nonce
    SHA512(concatinated, totla_len, hash);

    // Clean up
    EVP_PKEY_free(pkey);
    OPENSSL_free(pubkey_buf);
    free(concatinated);
    
    return 0;  // Success
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
        evidence_request *er = (evidence_request*)malloc(sizeof(evidence_request));

        if (er == NULL) {
            perror("could not allocate memory");
            *al = SSL_AD_INTERNAL_ERROR;
            return -1;
        }

        if (ext_data != NULL) {
            if (RAND_bytes(ext_data->er.data, CLIENT_RANDOM_SIZE) != 1) {
                perror("could not generate random bytes, will use SSL client random");
                SSL_get_client_random(s, ext_data->er.data, CLIENT_RANDOM_SIZE);
            }
        } else {
            fprintf(stderr, "add_arg is NULL\n");
            free(er);
            *al = SSL_AD_INTERNAL_ERROR;
            return -1;
        }

        memcpy(er->data, ext_data->er.data, CLIENT_RANDOM_SIZE);
        er->tee_type = AMD_TEE;
        ext_data->er.tee_type = AMD_TEE;

        *out = (const u_char *)er;
        *outlen = sizeof(evidence_request);
        return 1;
    }
    case SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS:
    {
        tls_extension_data *ext_data = (tls_extension_data*)add_arg;

        if (ext_data != NULL) {
            int32_t *platform_type = (int32_t*)malloc(sizeof(int32_t));

            if (platform_type == NULL) {
                perror("could not allocate memory");
                *al = SSL_AD_INTERNAL_ERROR;
                return -1;
            }

            if (check_sev_snp() > 0) {
                *platform_type = AMD_TEE; 
            } else {
                *platform_type = NO_TEE;
            }

            if ((*platform_type != ext_data->er.tee_type) || (*platform_type == NO_TEE)) {
                *platform_type = NO_TEE;
                ext_data->er.tee_type = NO_TEE;
            } else {
                ext_data->er.tee_type = AMD_TEE;
                ext_data->fetch_attestation_handler = fetchAttestationCallback(ext_data->er.tee_type);
            }

            *out = (u_char*)platform_type;
            *outlen = sizeof(int32_t);
        } else {
            fprintf(stderr, "add_arg is NULL\n");
            *al = SSL_AD_INTERNAL_ERROR;
            return -1;
        }

        return 1;
    }
    default:
        break;
    }

    fprintf(stderr, "bad context\n");
    *al = SSL_AD_INTERNAL_ERROR;
    return -1;
}

int evidence_request_ext_parse_cb(SSL *s, unsigned int ext_type,
                                    unsigned int context,
                                    const u_char *in,
                                    size_t inlen, X509 *x,
                                    size_t chainidx, int *al,
                                    void *parse_arg)
{
    switch (context)
    {
    case SSL_EXT_CLIENT_HELLO:
    {
        tls_extension_data *ext_data = (tls_extension_data*)parse_arg;
        evidence_request *er = (evidence_request*)in;

        if (ext_data != NULL) {
            memcpy(ext_data->er.data, er->data, CLIENT_RANDOM_SIZE);
            ext_data->er.tee_type = er->tee_type;
        } else {
            fprintf(stderr, "parse_arg is NULL\n");
            return 0;
        }
        return 1;
    }
    case SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS:
    {
        int *tee_type = (int*)in;
        tls_extension_data *ext_data = (tls_extension_data*)parse_arg;

        if (ext_data != NULL) {
            ext_data->er.tee_type = *tee_type;

            if (ext_data->er.tee_type != NO_TEE) {
                ext_data->verification_validation_handler = validationVerificationCallback(ext_data->er.tee_type);
            } else {
                fprintf(stderr, "must use a TEE for aTLS\n");
                return 0;
            }
        } else {
            fprintf(stderr, "parse_arg is NULL\n");
            return 0;
        }
        return 1;
    }
    default:
        fprintf(stderr, "bad context\n");
        return 0;
    }
}

/*
    Attestation Certificate extension
    - Contains the attestation report
    - The attestation report contains the hash of the nonce and the Public Key of the x.509 Agent certificate
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
    case SSL_EXT_CLIENT_HELLO:
        return 1;
    case SSL_EXT_TLS1_3_CERTIFICATE:
    {
        tls_extension_data *ext_data = (tls_extension_data*)add_arg;
        if (ext_data != NULL) {
            u_char *attestation_report;
            u_char *hash = (u_char*)malloc(REPORT_DATA_SIZE*sizeof(u_char));

            if (hash == NULL) {
                perror("could not allocate memory");
                *al = SSL_AD_INTERNAL_ERROR;
                return -1;
            }

            if (x != NULL) {
                int ret = compute_sha256_of_public_key_nonce(x, ext_data->er.data, hash);
                if (ret != 0) {
                    fprintf(stderr, "error while calculating hash\n");
                    free(hash);
                    *al = SSL_AD_INTERNAL_ERROR;
                    return -1;
                }
            } else {
                fprintf(stderr, "agent certificate must be used for aTLS\n");
                free(hash);
                *al = SSL_AD_INTERNAL_ERROR;
                return -1;
            }

            attestation_report = triggerFetchAttestationCallback(ext_data->fetch_attestation_handler, hash);
            if (attestation_report == NULL) {
                fprintf(stderr, "attestation report is NULL\n");
                *al = SSL_AD_INTERNAL_ERROR;
                return -1;
            }
            free(hash);

            *out = attestation_report;
            *outlen = ATTESTATION_REPORT_SIZE;
            return 1;
        } else {
            fprintf(stderr, "add_arg is NULL\n");
            *al = SSL_AD_INTERNAL_ERROR;
            return -1;
        }
    }
    default:
        fprintf(stderr, "bad context\n");
        *al = SSL_AD_INTERNAL_ERROR;
        return -1;
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
        // Return 1 so the server can return the custom certificate extension.
        return 1;
    case SSL_EXT_TLS1_3_CERTIFICATE:
    {
        if (x != NULL) {
            tls_extension_data *ext_data = (tls_extension_data*)parse_arg;

            if (ext_data != NULL) {
                char *attestation_report = (char*)malloc(ATTESTATION_REPORT_SIZE*sizeof(char));
                u_char *hash = (u_char*)malloc(REPORT_DATA_SIZE*sizeof(u_char));
                int res = 0;

                if (hash == NULL || attestation_report == NULL) {
                    perror("could not allocate memory");

                    if (hash != NULL) free(hash);
                    if (attestation_report != NULL) free(attestation_report);

                    return 0;
                }

                if (compute_sha256_of_public_key_nonce(x, ext_data->er.data, hash) != 0) {
                    fprintf(stderr, "calculating hash failed\n");
                    free(attestation_report);
                    free(hash);
                    return 0;
                }

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
                fprintf(stderr, "parse_arg is NULL\n");
                return 0;
            }

            return 1;
        } else {
            fprintf(stderr, "agent certificates must be used for aTLS\n");
            return 0;
        }
    }
    default:
        fprintf(stderr, "bad context\n");
        return 0;
    }
}
