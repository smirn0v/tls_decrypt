#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "tls_handler.h"
#include "utils.h"

static void usage(void);

enum CLI_OPTION{
    kCLI_OPTION_CLIENT_RANDOM   = 1,
    kCLI_OPTION_SERVER_RANDOM   = 1<<1,
    kCLI_OPTION_MASTER          = 1<<2,
    kCLI_OPTION_INPUT           = 1<<3,
    kCLI_OPTION_COUNTER         = 1<<4,
    kCLI_OPTION_CLIENT_TO_SERVER = 1<<5,
    kCLI_OPTION_SERVER_TO_CLIENT = 1<<6
};

#define kCLI_OPTION_ONLY_KEYS (kCLI_OPTION_CLIENT_RANDOM|kCLI_OPTION_SERVER_RANDOM|kCLI_OPTION_MASTER)
#define kCLI_OPTION_DECRYPT_C2S (kCLI_OPTION_ONLY_KEYS | kCLI_OPTION_INPUT | kCLI_OPTION_COUNTER | kCLI_OPTION_CLIENT_TO_SERVER)
#define kCLI_OPTION_DECRYPT_S2C (kCLI_OPTION_ONLY_KEYS | kCLI_OPTION_INPUT | kCLI_OPTION_COUNTER | kCLI_OPTION_SERVER_TO_CLIENT)

int main(int argc, char *argv[]) {

    int opt;
    unsigned char client_random_hex[32*2+1];
    unsigned char client_random[32];
    unsigned char server_random_hex[32*2+1];
    unsigned char server_random[32];
    unsigned char master_hex[48*2+1];
    unsigned char master[48];
    unsigned char input[65535];
    size_t input_length;
    unsigned char output[65535];
    uint64_t counter;
    enum TLS_HANDLER_DIRECTION direction;

    struct tls_handler tls;

    static struct option long_options[] =
                                 {
                                         {"client_random",  required_argument, 0, kCLI_OPTION_CLIENT_RANDOM},
                                         {"server_random",  required_argument, 0, kCLI_OPTION_SERVER_RANDOM},
                                         {"master",    required_argument, 0, kCLI_OPTION_MASTER},
                                         {"input",    required_argument, 0, kCLI_OPTION_INPUT},
                                         {"counter",    required_argument, 0, kCLI_OPTION_COUNTER},
                                         {"to_server",  no_argument, 0, kCLI_OPTION_CLIENT_TO_SERVER},
                                         {"to_client",  no_argument, 0, kCLI_OPTION_SERVER_TO_CLIENT},
                                         {0, 0, 0, 0}
                                 };

#define HANDLE_KEY(NAME) do {                                                   \
utils_die_on(strnlen(optarg,100) != sizeof(NAME)*2, "wrong '"#NAME "' length"); \
strcpy((char*)NAME##_hex, optarg);                                              \
utils_hex_to_bin(NAME##_hex, NAME, sizeof(NAME));                               \
} while(0)

    uint8_t options_filled = 0;
    while ((opt = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
        options_filled |= opt;
        switch(opt) {
            case kCLI_OPTION_CLIENT_RANDOM: HANDLE_KEY(client_random); break;
            case kCLI_OPTION_SERVER_RANDOM: HANDLE_KEY(server_random); break;
            case kCLI_OPTION_MASTER: HANDLE_KEY(master);  break;
            case kCLI_OPTION_INPUT: {
                FILE *f = fopen(optarg, "rb");
                utils_die_on_f(!f, "failed to open '%s'", optarg);

                input_length = fread(input, 1, sizeof(input), f);
                utils_die_on(input_length == 0, "nothing to decrypt");

                fclose(f);
            }
                break;
            case kCLI_OPTION_COUNTER: counter = strtoull(optarg, NULL, 10); break;
            case kCLI_OPTION_CLIENT_TO_SERVER: direction = TLS_HANDLER_DIRECTION_CLIENT_TO_SERVER; break;
            case kCLI_OPTION_SERVER_TO_CLIENT: direction = TLS_HANDLER_DIRECTION_SERVER_TO_CLIENT; break;
            default: usage();
        }
    }

    if(options_filled != kCLI_OPTION_ONLY_KEYS   &&
       options_filled != kCLI_OPTION_DECRYPT_C2S &&
       options_filled != kCLI_OPTION_DECRYPT_S2C) {
        usage();
    }

    int ret =
    tls_handler_init(&tls,
                     client_random, sizeof(client_random),
                     server_random, sizeof(server_random),
                     master, sizeof(master));
    utils_die_on(!ret,"failed to init tls handler");

    printf("client write key   : %s\n", utils_bin_to_hex(tls.client_write_key, 16));
    printf("server write key   : %s\n", utils_bin_to_hex(tls.server_write_key, 16));
    printf("client implicit iv : %s\n", utils_bin_to_hex(tls.client_write_implicit_iv, 4));
    printf("server implicit iv : %s\n", utils_bin_to_hex(tls.server_write_implicit_iv, 4));

    if(options_filled == kCLI_OPTION_DECRYPT_C2S || options_filled == kCLI_OPTION_DECRYPT_S2C) {
        int ret = tls_handler_process_packet(&tls, direction, counter, input, input_length, output, sizeof(output));
        utils_die_on(ret==-1 || ret ==0, "failed to decrypt");

        printf("\ndecrypted input:\n");
        utils_memory_dump(output, ret);
    }

    return 0;
}

static void usage(void) {
    fprintf(stderr, "Usage: tls_decrypt --client_random <32 bytes in hex>\n");
    fprintf(stderr, "                   --server_random <32 bytes in hex>\n");
    fprintf(stderr, "                   --master <48 bytes in hex>\n");
    fprintf(stderr, "                   [\n");
    fprintf(stderr, "                     --counter <packet sequence number for AEAD associated data>\n");
    fprintf(stderr, "                     --to_server or --to_client\n");
    fprintf(stderr, "                     --input <file with TLS packet to decrypt>\n");
    fprintf(stderr, "                   ]\n");
    fprintf(stderr, "Only AES128 GCM Ciphersuite is supported.\n");
    fprintf(stderr, "Only 'Application Data' type TLS packets will be decrypted.");
    fprintf(stderr, "If no input file given - only keys will be generated.");
    exit(0);
}
