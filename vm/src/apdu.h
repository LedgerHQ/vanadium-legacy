#pragma once

#include <stddef.h>
#include <stdint.h>

#include "error.h"
#include "stream.h"

#include "os_io_seproxyhal.h"

#define OFFSET_CLA   0
#define OFFSET_INS   1
#define OFFSET_P1    2
#define OFFSET_P2    3
#define OFFSET_LC    4
#define OFFSET_CDATA 6

#define CLA_GENERAL 0x34

enum cmd_stream_e {
    CMD_REQUEST_PAGE = 0x6101,
    CMD_COMMIT_PAGE = 0x6201,
    CMD_SEND_BUFFER = 0x6301,
    CMD_RECV_BUFFER = 0x6401,
    CMD_EXIT = 0x6501,
    CMD_FATAL = 0x6601,
    CMD_REQUEST_MANIFEST = 0x6701,
    CMD_REQUEST_APP_PAGE = 0x6801,
    CMD_REQUEST_APP_HMAC = 0x6802,
};

#define MAX_APDU_DATA_SIZE 548 // TODO

// Note that this diverges from the standard APDU message format used in most apps
struct apdu_s {
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    uint16_t lc;
    uint8_t data[MAX_APDU_DATA_SIZE];
} __attribute__((packed));

_Static_assert(IO_APDU_BUFFER_SIZE >= sizeof(struct apdu_s), "invalid IO_APDU_BUFFER_SIZE");

struct cmd_response_app_s {
    struct manifest_s manifest;
    uint8_t signature[72];
    uint8_t signature_size;
} __attribute__((packed));

_Static_assert(IO_APDU_BUFFER_SIZE >= sizeof(struct cmd_response_app_s),
               "invalid struct cmd_response_app_s");

size_t handle_general_apdu(uint8_t ins, uint8_t *data, size_t size);
bool handle_sign_app(const struct cmd_response_app_s *response, size_t *tx);

static inline struct apdu_s *parse_apdu(size_t size)
{
    struct apdu_s *apdu = (struct apdu_s *)G_io_apdu_buffer;

    if (size < OFFSET_CDATA || size - OFFSET_CDATA != apdu->lc) {
        return NULL;
    }

    return apdu;
}
