//
// Created by smirnov on 1/3/22.
//

#include "utils.h"

#include <string.h>

#include <openssl/bio.h>

static unsigned char hex_char_to_bin(unsigned char hex);

int utils_hex_to_bin(const unsigned char *hex, unsigned char *bin, size_t bin_length) {
    size_t hex_len = strlen((const char*)hex);
    if(hex_len%2 != 0 || hex_len/2 > bin_length) {
        return 0;
    }

    for(int i = 0; i < hex_len; i+=2) {
        unsigned char high, low;
        high = hex_char_to_bin(hex[i]);
        low  = hex_char_to_bin(hex[i+1]);
        bin[i/2] = (high<<4)|low;
    }

    return 1;
}

const char *utils_bin_to_hex(const unsigned char *bin, size_t bin_length) {
    static char buffer[512];

    char *p = buffer;

    for(int i=0; i<bin_length; i++) {
        p += sprintf(p,"%02x", bin[i]);
    }

    return buffer;
}

void utils_memory_dump(const unsigned char *data, size_t len) {

    BIO *log_buffer = BIO_new(BIO_s_mem());

    BIO_dump_indent(log_buffer, (const char*)data, len, 0);

    char line[512];
    int line_read;
    do {
        line_read = BIO_gets(log_buffer, line, sizeof(line));
        if(line_read > 0) {
            if(line[line_read-1] == '\n') {
                line[line_read-1] = 0;
            }
            printf("%s\n", line);
        }
    } while (line_read > 0);

    BIO_free(log_buffer);
}

// Private

static unsigned char hex_char_to_bin(unsigned char hex) {
    if(hex >= '0' && hex <= '9') {
        return hex - '0';
    } else if(hex >='A' && hex <= 'Z') {
        return hex - 'A'+10;
    } else if(hex >= 'a' && hex <= 'z') {
        return hex - 'a'+10;
    }
    fprintf(stderr, "wrong hex char\n");
    exit(0);
}