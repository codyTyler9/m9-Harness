#include "sha256.h"
#include <cstdint>
#include <cstring>

namespace {

    inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    static const uint32_t K[64] = {
        0x428a2f98ul,0x71374491ul,0xb5c0fbcful,0xe9b5dba5ul,
        0x3956c25bul,0x59f111f1ul,0x923f82a4ul,0xab1c5ed5ul,
        0xd807aa98ul,0x12835b01ul,0x243185beul,0x550c7dc3ul,
        0x72be5d74ul,0x80deb1feul,0x9bdc06a7ul,0xc19bf174ul,
        0xe49b69c1ul,0xefbe4786ul,0x0fc19dc6ul,0x240ca1ccul,
        0x2de92c6ful,0x4a7484aaul,0x5cb0a9dcul,0x76f988daul,
        0x983e5152ul,0xa831c66dul,0xb00327c8ul,0xbf597fc7ul,
        0xc6e00bf3ul,0xd5a79147ul,0x06ca6351ul,0x14292967ul,
        0x27b70a85ul,0x2e1b2138ul,0x4d2c6dfcul,0x53380d13ul,
        0x650a7354ul,0x766a0abbul,0x81c2c92eul,0x92722c85ul,
        0xa2bfe8a1ul,0xa81a664bul,0xc24b8b70ul,0xc76c51a3ul,
        0xd192e819ul,0xd6990624ul,0xf40e3585ul,0x106aa070ul,
        0x19a4c116ul,0x1e376c08ul,0x2748774cul,0x34b0bcb5ul,
        0x391c0cb3ul,0x4ed8aa4aul,0x5b9cca4ful,0x682e6ff3ul,
        0x748f82eeul,0x78a5636ful,0x84c87814ul,0x8cc70208ul,
        0x90befffaul,0xa4506cebul,0xbef9a3f7ul,0xc67178f2ul
    };

    struct Context {
        uint32_t h[8];
        uint64_t bitlen;
        uint8_t buffer[64];
        size_t buffer_len;
    };

    void init(Context& ctx) {
        ctx.h[0] = 0x6a09e667ul; ctx.h[1] = 0xbb67ae85ul;
        ctx.h[2] = 0x3c6ef372ul; ctx.h[3] = 0xa54ff53aul;
        ctx.h[4] = 0x510e527ful; ctx.h[5] = 0x9b05688cul;
        ctx.h[6] = 0x1f83d9abul; ctx.h[7] = 0x5be0cd19ul;
        ctx.bitlen = 0;
        ctx.buffer_len = 0;
    }

    void transform(Context& ctx, const uint8_t block[64]) {
        uint32_t w[64];

        for (int i = 0; i < 16; i++) {
            w[i] = (uint32_t(block[i * 4]) << 24) |
                (uint32_t(block[i * 4 + 1]) << 16) |
                (uint32_t(block[i * 4 + 2]) << 8) |
                (uint32_t(block[i * 4 + 3]));
        }

        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = ctx.h[0], b = ctx.h[1], c = ctx.h[2], d = ctx.h[3];
        uint32_t e = ctx.h[4], f = ctx.h[5], g = ctx.h[6], h = ctx.h[7];

        for (int i = 0; i < 64; i++) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g; g = f; f = e; e = d + temp1;
            d = c; c = b; b = a; a = temp1 + temp2;
        }

        ctx.h[0] += a; ctx.h[1] += b; ctx.h[2] += c; ctx.h[3] += d;
        ctx.h[4] += e; ctx.h[5] += f; ctx.h[6] += g; ctx.h[7] += h;
    }

    void update(Context& ctx, const uint8_t* data, size_t len) {
        ctx.bitlen += uint64_t(len) * 8;

        size_t i = 0;
        if (ctx.buffer_len > 0) {
            while (i < len && ctx.buffer_len < 64)
                ctx.buffer[ctx.buffer_len++] = data[i++];
            if (ctx.buffer_len == 64) {
                transform(ctx, ctx.buffer);
                ctx.buffer_len = 0;
            }
        }

        while (i + 64 <= len) {
            transform(ctx, data + i);
            i += 64;
        }

        while (i < len)
            ctx.buffer[ctx.buffer_len++] = data[i++];
    }

    void final(Context& ctx, uint8_t out[32]) {
        ctx.buffer[ctx.buffer_len++] = 0x80;

        if (ctx.buffer