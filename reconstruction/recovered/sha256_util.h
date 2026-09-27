#ifndef BH176_SHA256_UTIL_H
#define BH176_SHA256_UTIL_H

// Shared SHA-256 + hex helpers used by the client-assembly loaders. Extracted
// from original_client_world.cpp (PR #7, 4fd056c) so OriginalClientApp verifies
// dynamic-record digests with the exact same implementation the block domain
// already uses: one oracle, not two that can drift apart.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>

namespace bh176 {

namespace sha256_detail {

struct Ctx {
    std::uint32_t state[8];
    std::uint64_t count;
    std::uint8_t buffer[64];

    static const std::uint32_t K[64];

    static std::uint32_t rotr(std::uint32_t x, std::uint32_t n) { return (x >> n) | (x << (32 - n)); }
    static std::uint32_t ch(std::uint32_t x, std::uint32_t y, std::uint32_t z) { return (x & y) ^ (~x & z); }
    static std::uint32_t maj(std::uint32_t x, std::uint32_t y, std::uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    static std::uint32_t ep0(std::uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    static std::uint32_t ep1(std::uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    static std::uint32_t sig0(std::uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    static std::uint32_t sig1(std::uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

    Ctx() {
        state[0] = 0x6a09e667; state[1] = 0xbb67ae85; state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
        state[4] = 0x510e527f; state[5] = 0x9b05688c; state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;
        count = 0;
    }

    void transform(const std::uint8_t data[64]) {
        std::uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        std::uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
        std::uint32_t m[64];
        for (int i = 0; i < 16; ++i)
            m[i] = (std::uint32_t(data[i * 4]) << 24) | (std::uint32_t(data[i * 4 + 1]) << 16) |
                   (std::uint32_t(data[i * 4 + 2]) << 8) | std::uint32_t(data[i * 4 + 3]);
        for (int i = 16; i < 64; ++i)
            m[i] = sig1(m[i - 2]) + m[i - 7] + sig0(m[i - 15]) + m[i - 16];
        for (int i = 0; i < 64; ++i) {
            std::uint32_t t1 = h + ep1(e) + ch(e, f, g) + K[i] + m[i];
            std::uint32_t t2 = ep0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    }

    void update(const std::uint8_t* data, std::size_t len) {
        std::size_t idx = std::size_t(count & 63);
        count += len;
        for (std::size_t i = 0; i < len; ++i) {
            buffer[idx++] = data[i];
            if (idx == 64) {
                transform(buffer);
                idx = 0;
            }
        }
    }

    std::string finalize() {
        std::uint8_t final_count[8];
        std::uint64_t bit_len = count * 8;
        for (int i = 0; i < 8; ++i) final_count[i] = std::uint8_t(bit_len >> ((7 - i) * 8));
        update(reinterpret_cast<const std::uint8_t*>("\x80"), 1);
        while ((count & 63) != 56) update(reinterpret_cast<const std::uint8_t*>("\0"), 1);
        update(final_count, 8);
        char hex_str[65];
        for (int i = 0; i < 8; ++i)
            std::snprintf(hex_str + i * 8, 9, "%08x", state[i]);
        return std::string(hex_str, 64);
    }
};

inline const std::uint32_t Ctx::K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

}  // namespace sha256_detail

inline std::string sha256Hex(std::string_view data) {
    sha256_detail::Ctx ctx;
    ctx.update(reinterpret_cast<const std::uint8_t*>(data.data()), data.size());
    return ctx.finalize();
}

// 64 lowercase hex characters — the exact shape both index files declare.
inline bool isSha256Hex(std::string_view text) {
    if (text.size() != 64) return false;
    for (const char c : text) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

// Strict lowercase-hex decode. Returns false on odd length, non-hex chars or
// empty input; never guesses a nibble.
inline bool hexDecode(std::string_view hex, std::string& out) {
    out.clear();
    if (hex.empty() || hex.size() % 2 != 0) return false;
    out.reserve(hex.size() / 2);
    int nibble = -1;
    for (const char c : hex) {
        int v;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else return false;
        if (nibble < 0) {
            nibble = v;
        } else {
            out.push_back(static_cast<char>(nibble * 16 + v));
            nibble = -1;
        }
    }
    return nibble < 0;
}

// Lowercase hex encoding (index key_hex <-> coordinate text comparison).
inline std::string hexEncode(std::string_view input) {
    std::string hex;
    hex.reserve(input.size() * 2);
    char buf[3];
    for (const unsigned char c : input) {
        std::snprintf(buf, sizeof(buf), "%02x", c);
        hex += buf;
    }
    return hex;
}

}  // namespace bh176

#endif
