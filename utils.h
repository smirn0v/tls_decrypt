//
// Created by smirnov on 1/3/22.
//

#ifndef TLS_DECRYPT_UTILS_H
#define TLS_DECRYPT_UTILS_H

#include <stdlib.h>

#define utils_die_on_f(cond, message...) do{ if((cond)) { fprintf(stderr, message); exit(0); }} while(0)
#define utils_die_on(cond, message) utils_die_on_f(cond, "%s\n", message)

int utils_hex_to_bin(const unsigned char *hex, unsigned char *bin, size_t bin_length);
const char *utils_bin_to_hex(const unsigned char *bin, size_t bin_length);
void utils_memory_dump(const unsigned char *data, size_t len);

#endif //TLS_DECRYPT_UTILS_H
