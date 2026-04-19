#include "miner.h"
#include "block_header.h"
#include "sha256.h"
#include <cstdio>
#include <cstring>

void miner_thread_func() {
    BlockHeader hdr{};
    hdr.version = 0x20000000;

    memset(hdr.prev_block, 0x11, 32);
    memset(hdr.merkle_root, 0x22, 32);

    hdr.time = 0x5F5E1000;
    hdr.bits = 0x1d00ffff;
    hdr.nonce = 0;

    uint8_t header_bytes[80];
    uint8_t hash[32];

    while (!g_stop.load()) {
        serialize_header(hdr, header_bytes);
        double_sha256(header_bytes, 80, hash);

        g_hash_count.fetch_add(1);

        if (hash[31] == 0x00 && hash[30] == 0x00) {
            printf("[FOUND] nonce=%u hash=", hdr.nonce);
            for (int i = 31; i >= 0; --i) printf("%02x", hash[i]);
            printf("\n");
        }

        hdr.nonce++;
    }
}