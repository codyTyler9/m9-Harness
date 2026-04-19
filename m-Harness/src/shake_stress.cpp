// miner_with_stress.cpp
// Drop into Visual Studio as a Console App source file.
// Compile as C++17 or later.

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <thread>
#include <atomic>
#include <vector>
#include <chrono>
#include <random>

// =======================
// Simple SHA-256 (inline)
// =======================

namespace sha256 {

    static const uint32_t K[64] = {
        0x428a2f98ul, 0x71374491ul, 0xb5c0fbcful, 0xe9b5dba5ul,
        0x3956c25bul, 0x59f111f1ul, 0x923f82a4ul, 0xab1c5ed5ul,
        0xd807aa98ul, 0x12835b01ul, 0x243185beul, 0x550c7dc3ul,
        0x72be5d74ul, 0x80deb1feul, 0x9bdc06a7ul, 0xc19bf174ul,
        0xe49b69c1ul, 0xefbe4786ul, 0x0fc19dc6ul, 0x240ca1ccul,
        0x2de92c6ful, 0x4a7484aaul, 0x5cb0a9dcul, 0x76f988daul,
        0x983e5152ul, 0xa831c66dul, 0xb00327c8ul, 0xbf597fc7ul,
        0xc6e00bf3ul, 0xd5a79147ul, 0x06ca6351ul, 0x14292967ul,
        0x27b70a85ul, 0x2e1b2138ul, 0x4d2c6dfcul, 0x53380d13ul,
        0x650a7354ul, 0x766a0abbul, 0x81c2c92eul, 0x92722c85ul,
        0xa2bfe8a1ul, 0xa81a664bul, 0xc24b8b70ul, 0xc76c51a3ul,
        0xd192e819ul, 0xd6990624ul, 0xf40e3585ul, 0x106aa070ul,
        0x19a4c116ul, 0x1e376c08ul, 0x2748774cul, 0x34b0bcb5ul,
        0x391c0cb3ul, 0x4ed8aa4aul, 0x5b9cca4ful, 0x682e6ff3ul,
        0x748f82eeul, 0x78a5636ful, 0x84c87814ul, 0x8cc70208ul,
        0x90befffaul, 0xa4506cebul, 0xbef9a3f7ul, 0xc67178f2ul
    };

    inline uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }

    struct Context {
        uint32_t h[8];
        uint64_t bitlen;
        uint8_t buffer[64];
        size_t buffer_len;
    };

    void init(Context& ctx) {
        ctx.h[0] = 0x6a09e667ul;
        ctx.h[1] = 0xbb67ae85ul;
        ctx.h[2] = 0x3c6ef372ul;
        ctx.h[3] = 0xa54ff53aul;
        ctx.h[4] = 0x510e527ful;
        ctx.h[5] = 0x9b05688cul;
        ctx.h[6] = 0x1f83d9abul;
        ctx.h[7] = 0x5be0cd19ul;
        ctx.bitlen = 0;
        ctx.buffer_len = 0;
    }

    void transform(Context& ctx, const uint8_t block[64]) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (uint32_t(block[i * 4 + 0]) << 24) |
                (uint32_t(block[i * 4 + 1]) << 16) |
                (uint32_t(block[i * 4 + 2]) << 8) |
                (uint32_t(block[i * 4 + 3]) << 0);
        }
        for (int i = 16; i < 64; ++i) {
            uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        uint32_t a = ctx.h[0];
        uint32_t b = ctx.h[1];
        uint32_t c = ctx.h[2];
        uint32_t d = ctx.h[3];
        uint32_t e = ctx.h[4];
        uint32_t f = ctx.h[5];
        uint32_t g = ctx.h[6];
        uint32_t h = ctx.h[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h + S1 + ch + K[i] + w[i];
            uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        ctx.h[0] += a;
        ctx.h[1] += b;
        ctx.h[2] += c;
        ctx.h[3] += d;
        ctx.h[4] += e;
        ctx.h[5] += f;
        ctx.h[6] += g;
        ctx.h[7] += h;
    }

    void update(Context& ctx, const uint8_t* data, size_t len) {
        ctx.bitlen += uint64_t(len) * 8;

        size_t i = 0;
        if (ctx.buffer_len > 0) {
            while (i < len && ctx.buffer_len < 64) {
                ctx.buffer[ctx.buffer_len++] = data[i++];
            }
            if (ctx.buffer_len == 64) {
                transform(ctx, ctx.buffer);
                ctx.buffer_len = 0;
            }
        }

        while (i + 64 <= len) {
            transform(ctx, data + i);
            i += 64;
        }

        while (i < len) {
            ctx.buffer[ctx.buffer_len++] = data[i++];
        }
    }

    void final(Context& ctx, uint8_t out[32]) {
        // Pad
        ctx.buffer[ctx.buffer_len++] = 0x80;
        if (ctx.buffer_len > 56) {
            while (ctx.buffer_len < 64) ctx.buffer[ctx.buffer_len++] = 0x00;
            transform(ctx, ctx.buffer);
            ctx.buffer_len = 0;
        }
        while (ctx.buffer_len < 56) ctx.buffer[ctx.buffer_len++] = 0x00;

        // Append length (big-endian)
        uint64_t bitlen = ctx.bitlen;
        for (int i = 7; i >= 0; --i) {
            ctx.buffer[ctx.buffer_len++] = uint8_t((bitlen >> (i * 8)) & 0xFF);
        }
        transform(ctx, ctx.buffer);

        for (int i = 0; i < 8; ++i) {
            out[i * 4 + 0] = uint8_t((ctx.h[i] >> 24) & 0xFF);
            out[i * 4 + 1] = uint8_t((ctx.h[i] >> 16) & 0xFF);
            out[i * 4 + 2] = uint8_t((ctx.h[i] >> 8) & 0xFF);
            out[i * 4 + 3] = uint8_t((ctx.h[i] >> 0) & 0xFF);
        }
    }

    void hash(const uint8_t* data, size_t len, uint8_t out[32]) {
        Context ctx;
        init(ctx);
        update(ctx, data, len);
        final(ctx, out);
    }

} // namespace sha256

// Double SHA-256
void double_sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint8_t tmp[32];
    sha256::hash(data, len, tmp);
    sha256::hash(tmp, 32, out);
}

// =======================
// Bitcoin block header
// =======================

#pragma pack(push, 1)
struct BlockHeader {
    uint32_t version;          // 4 bytes, little-endian
    uint8_t prev_block[32];    // 32 bytes, little-endian hash
    uint8_t merkle_root[32];   // 32 bytes, little-endian hash
    uint32_t time;             // 4 bytes, UNIX time, little-endian
    uint32_t bits;             // 4 bytes, compact target, little-endian
    uint32_t nonce;            // 4 bytes, little-endian
};
#pragma pack(pop)

// Serialize header to 80-byte buffer (already packed, but we keep this explicit)
void serialize_header(const BlockHeader& hdr, uint8_t out[80]) {
    std::memcpy(out, &hdr, 80);
}

// =======================
// Global control
// =======================

std::atomic<bool> g_stop{ false };
std::atomic<uint64_t> g_hash_count{ 0 };

// =======================
// Mining thread
// =======================

void mining_thread_func() {
    BlockHeader hdr{};
    hdr.version = 0x20000000; // example version

    // Fake previous block hash and merkle root (normally from network / mempool)
    std::memset(hdr.prev_block, 0x11, sizeof(hdr.prev_block));
    std::memset(hdr.merkle_root, 0x22, sizeof(hdr.merkle_root));

    hdr.time = 0x5F5E1000; // placeholder timestamp
    hdr.bits = 0x1d00ffff; // Bitcoin's original difficulty bits (for testing)
    hdr.nonce = 0;

    uint8_t header_bytes[80];
    uint8_t hash[32];

    while (!g_stop.load(std::memory_order_relaxed)) {
        serialize_header(hdr, header_bytes);
        double_sha256(header_bytes, 80, hash);

        g_hash_count.fetch_add(1, std::memory_order_relaxed);

        // Example pseudo-target: check if first 16 bits are zero
        if (hash[31] == 0x00 && hash[30] == 0x00) {
            // Note: Bitcoin hashes are displayed big-endian; we just print raw here.
            std::printf("[FOUND] nonce=%u hash=", hdr.nonce);
            for (int i = 31; i >= 0; --i) {
                std::printf("%02x", hash[i]);
            }
            std::printf("\n");
        }

        hdr.nonce++;
        if (hdr.nonce == 0) {
            std::printf("[MINER] Nonce wrapped.\n");
        }
    }
}

// =======================
// "SHAKE" RAM stress thread
// =======================
//
// This is where you can later plug in a real SHAKE XOF.
// For now, it:
//  - Allocates a big buffer
//  - Walks it in chunks
//  - Mutates it with a cheap pseudo-random pattern
//  - Keeps memory and caches hot while mining runs
//

void ram_stress_thread_func() {
    const size_t buffer_size = 128 * 1024 * 1024; // 128 MB
    std::vector<uint8_t> buf(buffer_size);

    // Initialize buffer with a pattern
    for (size_t i = 0; i < buffer_size; ++i) {
        buf[i] = static_cast<uint8_t>(i & 0xFF);
    }

    std::mt19937_64 rng{ 0xDEADBEEF };
    std::uniform_int_distribution<uint64_t> dist;

    const size_t chunk = 4096;

    while (!g_stop.load(std::memory_order_relaxed)) {
        for (size_t offset = 0; offset < buffer_size; offset += chunk) {
            size_t len = (offset + chunk <= buffer_size) ? chunk : (buffer_size - offset);

            // TODO: replace this with a real SHAKE256 XOF call if desired.
            // For now, we just XOR with pseudo-random data to simulate heavy memory churn.
            uint64_t r = dist(rng);
            for (size_t i = 0; i < len; ++i) {
                buf[offset + i] ^= static_cast<uint8_t>((r >> ((i % 8) * 8)) & 0xFF);
            }

            if (g_stop.load(std::memory_order_relaxed)) break;
        }
        // Optional small sleep to avoid completely starving the miner on weak CPUs
        // std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

// =======================
// Stats / main
// =======================

void stats_thread_func() {
    using clock = std::chrono::steady_clock;
    auto last_time = clock::now();
    uint64_t last_count = 0;

    while (!g_stop.load(std::memory_order_relaxed)) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        auto now = clock::now();
        uint64_t count = g_hash_count.load(std::memory_order_relaxed);

        double dt = std::chrono::duration<double>(now - last_time).count();
        uint64_t diff = count - last_count;
        double hps = diff / dt;

        std::printf("[STATS] %.2f H/s (hashes per second)\n", hps);

        last_time = now;
        last_count = count;
    }
}

int main() {
    std::printf("Starting mining + RAM stress harness.\n");
    std::printf("This is NOT a full Bitcoin miner. It's a header + hash pipeline for experiments.\n");
    std::printf("Press Enter to stop.\n");

    std::thread miner(mining_thread_func);
    std::thread stress(ram_stress_thread_func);
    std::thread stats(stats_thread_func);

    std::getchar();
    g_stop.store(true, std::memory_order_relaxed);

    miner.join();
    stress.join();
    stats.join();

    std::printf("Stopped.\n");
    return 0;
}