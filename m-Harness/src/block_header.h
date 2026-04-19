#pragma once
#include <cstdint>

#pragma pack(push, 1)
struct BlockHeader {
    uint32_t version;
    uint8_t prev_block[32];
    uint8_t merkle_root[32];
    uint32_t time;
    uint32_t bits;
    uint32_t nonce;
};
#pragma pack(pop)

void serialize_header(const BlockHeader& hdr, uint8_t out[80]); #pragma once
