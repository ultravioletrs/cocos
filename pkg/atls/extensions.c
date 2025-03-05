#include "extensions.h"
#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <fcntl.h>
#include <unistd.h>

extern int callVerificationValidationCallback(uintptr_t callbackHandle, const u_char* pubKey, int pubKeyLen, const u_char* quote, int quoteSize, const u_char* teeNonce, const u_char* nonce);
extern u_char* callFetchAttestationCallback(uintptr_t callbackHandle, const u_char* pubKey, int pubKeyLen, const u_char* teeNonceByte, const u_char* vTPMNonceByte, unsigned long* outlen);
extern uintptr_t validationVerificationCallback(int teeType);
extern uintptr_t fetchAttestationCallback(int teeType);

int triggerVerificationValidationCallback(uintptr_t callbackHandle, u_char* pub_key, int pub_key_len, u_char *quote, int quote_size, u_char *tee_nonce, u_char *vtpm_nonce) {
    if (quote == NULL || vtpm_nonce == NULL || tee_nonce == NULL || pub_key == NULL) {
        fprintf(stderr, "attestation and noce and public key cannot be NULL\n");
        return -1;
    }

    return callVerificationValidationCallback(callbackHandle, pub_key, pub_key_len, quote, quote_size, tee_nonce, vtpm_nonce);
}

u_char* triggerFetchAttestationCallback(uintptr_t callback_handle, u_char* pub_key, int pub_key_len, char *tee_nonce, char *vtpm_nonce, unsigned long *outlen) {
    if(tee_nonce == NULL || vtpm_nonce == NULL) {
        fprintf(stderr, "Report data cannot be NULL");
        return NULL;
    }

    return callFetchAttestationCallback(callback_handle, pub_key, pub_key_len, tee_nonce, vtpm_nonce, outlen);
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
            if (RAND_bytes(ext_data->er.vtpm_nonce, CLIENT_RANDOM_SIZE) != 1) {
                perror("could not generate random bytes for vtpm nonce, will use SSL client random");
                SSL_get_client_random(s, ext_data->er.vtpm_nonce, CLIENT_RANDOM_SIZE);
            }

            if (RAND_bytes(ext_data->er.tee_nonce, REPORT_DATA_SIZE) != 1) {
                perror("could not generate random bytes for tee nonce, will use SSL client random");
                SSL_get_client_random(s, ext_data->er.tee_nonce, REPORT_DATA_SIZE);
            }
        } else {
            fprintf(stderr, "add_arg is NULL\n");
            free(er);
            *al = SSL_AD_INTERNAL_ERROR;
            return -1;
        }

        memcpy(er->vtpm_nonce, ext_data->er.vtpm_nonce, CLIENT_RANDOM_SIZE);
        memcpy(er->tee_nonce, ext_data->er.tee_nonce, REPORT_DATA_SIZE);
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
            memcpy(ext_data->er.vtpm_nonce, er->vtpm_nonce, CLIENT_RANDOM_SIZE);
            memcpy(ext_data->er.tee_nonce, er->tee_nonce, REPORT_DATA_SIZE);
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
    - The attestation report contains the hash of the nonce, the Public Key of the x.509 Agent certificate, and the vTPM AK
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
            u_char *quote;
            size_t len = 0;
            EVP_PKEY *pkey = NULL;
            u_char *pubkey_buf = NULL;
            int pubkey_len = 0;
        

            if (x != NULL) {
                pkey = X509_get_pubkey(x);
                if (pkey == NULL) {
                    fprintf(stderr, "Failed to extract public key from certificate\n");
                    return -1;
                }
            
                pubkey_len = i2d_PUBKEY(pkey, &pubkey_buf);
                if (pubkey_len <= 0) {
                    fprintf(stderr, "Failed to convert public key to DER format\n");
                    EVP_PKEY_free(pkey);
                    return -1;
                }
            } else {
                fprintf(stderr, "agent certificate must be used for aTLS\n");
                *al = SSL_AD_INTERNAL_ERROR;
                return -1;
            }

            quote = triggerFetchAttestationCallback(ext_data->fetch_attestation_handler, pubkey_buf, pubkey_len, ext_data->er.tee_nonce, ext_data->er.vtpm_nonce, &len);
            if (quote == NULL) {
                fprintf(stderr, "attestation report is NULL\n");
                *al = SSL_AD_INTERNAL_ERROR;
                EVP_PKEY_free(pkey);
                OPENSSL_free(pubkey_buf);
                return -1;
            }

            EVP_PKEY_free(pkey);
            OPENSSL_free(pubkey_buf);

            *out = quote;
            *outlen = len;
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
                char *quote = (char*)malloc(inlen*sizeof(char));
                EVP_PKEY *pkey = NULL;
                u_char *pubkey_buf = NULL;
                int pubkey_len = 0;
                int res = 0;

                if (quote == NULL) {
                    perror("could not allocate memory");
                    return 0;
                }

                pkey = X509_get_pubkey(x);
                if (pkey == NULL) {
                    fprintf(stderr, "Failed to extract public key from certificate\n");
                    return -1;
                }
            
                pubkey_len = i2d_PUBKEY(pkey, &pubkey_buf);
                if (pubkey_len <= 0) {
                    fprintf(stderr, "Failed to convert public key to DER format\n");
                    EVP_PKEY_free(pkey);
                    return -1;
                }
                memcpy(quote, in, inlen);

                res = triggerVerificationValidationCallback(ext_data->verification_validation_handler,
                                                    pubkey_buf,
                                                    pubkey_len,
                                                    quote,
                                                    inlen,
                                                    (u_char*)&ext_data->er.tee_nonce,
                                                    (u_char*)&ext_data->er.vtpm_nonce);
                free(quote);
                EVP_PKEY_free(pkey);
                OPENSSL_free(pubkey_buf);
                
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
