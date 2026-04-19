#include "block_header.h"
#include <cstring>

void serialize_header(const BlockHeader& hdr, uint8_t out[80]) {
    memcpy(out, &hdr, 80);
}