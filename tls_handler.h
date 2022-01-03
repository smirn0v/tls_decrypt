//
// Created by smirnov on 11/8/21.
//

#ifndef AA_TLS_HANDLER_H
#define AA_TLS_HANDLER_H

#include <stdint.h>
#include <stddef.h>

enum TLS_HANDLER_DIRECTION {
    TLS_HANDLER_DIRECTION_CLIENT_TO_SERVER,
    TLS_HANDLER_DIRECTION_SERVER_TO_CLIENT
};

struct tls_handler {
    unsigned char prf_result[40];

    unsigned char *client_write_key;
    unsigned char *client_write_implicit_iv;

    unsigned char *server_write_key;
    unsigned char *server_write_implicit_iv;
};

int tls_handler_init(struct tls_handler *handler,
                     unsigned char *client_random, size_t client_random_length,
                     unsigned char *server_random, size_t server_random_length,
                     unsigned char *master_key, size_t master_key_length);

int tls_handler_process_packet(struct tls_handler *handler,
                               enum TLS_HANDLER_DIRECTION direction,
                               uint64_t counter,
                               unsigned char *packet, size_t packet_length,
                               unsigned char *output, size_t output_length);

#endif //AA_TLS_HANDLER_H
