//
// Created by smirnov on 11/8/21.
//

#include "tls_handler.h"

#include <memory.h>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/tls1.h>
#include <openssl/ssl3.h>
#include <netinet/in.h>

#define tls_log_error(args...) do { fprintf(stderr, "TLS HANDLER: "args); fprintf(stderr,"\n"); } while(0)

static int tls_handler_decrypt(struct tls_handler *handler,
                               enum TLS_HANDLER_DIRECTION direction,
                               uint64_t counter,
                               unsigned char *data, size_t length);

static int tls1_PRF(const void *seed1, size_t seed1_len,
                    const void *seed2, size_t seed2_len,
                    const void *seed3, size_t seed3_len,
                    const void *seed4, size_t seed4_len,
                    const void *seed5, size_t seed5_len,
                    const unsigned char *sec, size_t slen,
                    unsigned char *out, size_t olen);

static int
tls1_generate_key_block(unsigned char *server_random,
                        unsigned char *client_random,
                        unsigned char *master_key,
                        size_t master_key_length,
                        unsigned char *km, size_t num);

int tls_handler_init(struct tls_handler *handler,
                     unsigned char *client_random, size_t client_random_length,
                     unsigned char *server_random, size_t server_random_length,
                     unsigned char *master_key, size_t master_key_length) {

    if(
            !handler       ||
            !client_random ||
            !server_random ||
            !master_key    ||
            client_random_length != 32 ||
            server_random_length != 32 ||
            master_key_length    != 48
    ) {
        tls_log_error("Invalid init arguments");
        return 0;
    }

    int ret =
                tls1_generate_key_block(server_random,
                                        client_random,
                                        master_key,
                                        48,
                                        handler->prf_result,
                                        sizeof(handler->prf_result));
    if(!ret) {
        tls_log_error("Failed to run PRF on keys");
        return 0;
    }

    handler->client_write_key = handler->prf_result;
    handler->server_write_key = handler->prf_result+16;
    handler->client_write_implicit_iv  = handler->prf_result+32;
    handler->server_write_implicit_iv  = handler->prf_result+36;

    return 1;
}

int tls_handler_process_packet(struct tls_handler *handler,
                               enum TLS_HANDLER_DIRECTION direction,
                               uint64_t counter,
                               unsigned char *packet, size_t packet_length,
                               unsigned char *output, size_t output_length) {

    if(!handler) {
        return -1;
    }

    if(output_length < packet_length) {
        tls_log_error("Output MUST be at least as long as an input");
        return -1;
    }

    uint8_t type;
    uint8_t protocol_version_major;
    uint8_t protocol_version_minor;
    uint16_t length;

    size_t tls_header_size = sizeof(type)
                             +sizeof(protocol_version_major)
                             +sizeof(protocol_version_minor)
                             +sizeof(length);


    if(packet_length < 5) {
        tls_log_error("Too small to be TLS packet");
        return -1;
    }

    type = packet[0];
    protocol_version_major = packet[1];
    protocol_version_minor = packet[2];
    length = ntohs(*(uint16_t*)(packet+3));

    if(type == SSL3_RT_APPLICATION_DATA) {

        if(protocol_version_major != 0x3 || protocol_version_minor != 0x3) {
            tls_log_error("Wrong protocol version. Must be 0x03,0x03 TLS 1.2");
            return -1;
        }

        memcpy(output, packet + tls_header_size, length);

        return tls_handler_decrypt(handler, direction, counter, output, length);
    } else {
        tls_log_error("Not 'Application Data' TLS packet");
    }

    return 0;
}

static int tls_handler_decrypt(struct tls_handler *handler,
                               enum TLS_HANDLER_DIRECTION direction,
                               uint64_t counter,
                               unsigned char *data, size_t length) {

        // 8 bytes explicit IV part
        // 16 bytes of authentication tag at the end of message
        if(length < 24) {
            tls_log_error("Too small for tls decrypt");
            return -1;
        }

        // 13 bytes of authenticated data according to https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.3.3
        // additional_data = seq_num + TLSCompressed.type +
        //                   TLSCompressed.version + TLSCompressed.length;
        // 0x17 - Application Data packet type
        // 0x03 0x03 - TLS Version 1.2
        unsigned char AAD[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17, 0x03, 0x03, (length>>8)&0xff, length&0xff};

        unsigned char *KEY, *IV;
        if(direction == TLS_HANDLER_DIRECTION_CLIENT_TO_SERVER) {
            KEY = handler->client_write_key;
            IV  = handler->client_write_implicit_iv;
        } else {
            KEY = handler->server_write_key;
            IV  = handler->server_write_implicit_iv;
        }

        *((uint64_t*)AAD) = htobe64(counter);

        const EVP_CIPHER *cipher = EVP_aes_128_gcm();
        EVP_CIPHER_CTX   *ctx    = EVP_CIPHER_CTX_new();
        EVP_CipherInit_ex(ctx, cipher, NULL, KEY, NULL, 0);

        // Implicit part of IV is 4 bytes long according to https://datatracker.ietf.org/doc/html/rfc5288
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, 4, IV);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_TLS1_AAD, sizeof(AAD), AAD);

        int ret = EVP_Cipher(ctx, data, data, length);

        EVP_CIPHER_CTX_free(ctx);

        if(ret != -1) {
            // just erase explicit IV at the start
            memmove(data,data+8, ret);
            return ret;
        }

        return ret;
}

// ported from openssl/ssl/t1_enc.c
static int tls1_PRF(const void *seed1, size_t seed1_len,
                    const void *seed2, size_t seed2_len,
                    const void *seed3, size_t seed3_len,
                    const void *seed4, size_t seed4_len,
                    const void *seed5, size_t seed5_len,
                    const unsigned char *sec, size_t slen,
                    unsigned char *out, size_t olen) {

    const EVP_MD *md = EVP_sha256();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
    int ret = 0;

    if (pctx == NULL || EVP_PKEY_derive_init(pctx) <= 0
        || EVP_PKEY_CTX_set_tls1_prf_md(pctx, md) <= 0
        || EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, sec, (int)slen) <= 0
        || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed1, (int)seed1_len) <= 0
        || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed2, (int)seed2_len) <= 0
        || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed3, (int)seed3_len) <= 0
        || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed4, (int)seed4_len) <= 0
        || EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, seed5, (int)seed5_len) <= 0
        || EVP_PKEY_derive(pctx, out, &olen) <= 0) {

        goto err;
    }

    ret = 1;

    err:
    EVP_PKEY_CTX_free(pctx);
    return ret;
}

static int
tls1_generate_key_block(unsigned char *server_random,
                        unsigned char *client_random,
                        unsigned char *master_key,
                        size_t master_key_length,
                        unsigned char *km, size_t num) {
    int ret;

    ret = tls1_PRF(TLS_MD_KEY_EXPANSION_CONST,
                   TLS_MD_KEY_EXPANSION_CONST_SIZE, server_random,
                   SSL3_RANDOM_SIZE, client_random, SSL3_RANDOM_SIZE,
                   NULL, 0, NULL, 0, master_key,
                   master_key_length, km, num);

    return ret;
}