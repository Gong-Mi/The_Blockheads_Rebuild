#include "original_client_world.h"

#include <array>
#include <charconv>
#include <cstring>
#include <fstream>
#include <sstream>
#include <system_error>
#include <vector>

namespace bh176 {
namespace {

bool fail(std::string* error, const std::string& message) {
    if (error) *error = message;
    return false;
}

bool parseInt32(const std::string& text, std::int32_t& value) {
    if (text.empty()) return false;
    const char* begin = text.data();
    const char* end = begin + text.size();
    auto result = std::from_chars(begin, end, value);
    return result.ec == std::errc{} && result.ptr == end;
}

bool parseSize(const std::string& text, std::size_t& value) {
    if (text.empty()) return false;
    std::uint64_t parsed = 0;
    const char* begin = text.data();
    const char* end = begin + text.size();
    auto result = std::from_chars(begin, end, parsed);
    if (result.ec != std::errc{} || result.ptr != end ||
        parsed > static_cast<std::uint64_t>(SIZE_MAX)) return false;
    value = static_cast<std::size_t>(parsed);
    return true;
}

bool safeRelativePath(const std::filesystem::path& path) {
    if (path.empty() || path.is_absolute()) return false;
    for (const auto& part : path) {
        if (part == "..") return false;
    }
    return true;
}

bool splitIndexLine(const std::string& line, std::array<std::string, 6>& fields) {
    std::stringstream stream(line);
    for (std::size_t i = 0; i < fields.size(); ++i) {
        if (!std::getline(stream, fields[i], '\t')) return false;
    }
    std::string extra;
    return !std::getline(stream, extra, '\t');
}

struct SHA256 {
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

    SHA256() {
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

const std::uint32_t SHA256::K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

std::string computeSha256(const std::vector<std::uint8_t>& data) {
    SHA256 ctx;
    ctx.update(data.data(), data.size());
    return ctx.finalize();
}

std::string toHex(const std::string& input) {
    std::string hex;
    hex.reserve(input.size() * 2);
    char buf[3];
    for (unsigned char c : input) {
        std::snprintf(buf, sizeof(buf), "%02x", c);
        hex += buf;
    }
    return hex;
}

}  // namespace

bool OriginalClientWorld::load(const std::filesystem::path& snapshot_root,
                               std::string* error) {
    const auto index_path = snapshot_root / "blocks" / "index.tsv";
    std::ifstream index(index_path);
    if (!index) return fail(error, "cannot open blocks/index.tsv");

    std::string line;
    if (!std::getline(index, line) ||
        line != "key_hex\tx\ty\tfile\traw_sha256\tbytes") {
        return fail(error, "invalid blocks/index.tsv header");
    }

    std::map<std::pair<std::int32_t, std::int32_t>, PhysicalBlockPayload> next;
    std::size_t line_number = 1;
    while (std::getline(index, line)) {
        ++line_number;
        if (line.empty()) return fail(error, "empty index row");
        std::array<std::string, 6> fields;
        if (!splitIndexLine(line, fields)) {
            return fail(error, "invalid index row at line " + std::to_string(line_number));
        }

        std::int32_t x = 0, y = 0;
        std::size_t declared_bytes = 0;
        if (!parseInt32(fields[1], x) || !parseInt32(fields[2], y) ||
            !parseSize(fields[5], declared_bytes)) {
            return fail(error, "invalid coordinate/size at index line " +
                                  std::to_string(line_number));
        }
        if (fields[0].empty() || fields[0].size() % 2 != 0) {
            return fail(error, "invalid key at index line " + std::to_string(line_number));
        }
        for (unsigned char c : fields[0]) {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return fail(error, "non-hex key at index line " + std::to_string(line_number));
            }
        }
        const std::string expected_coord = std::to_string(x) + "_" + std::to_string(y);
        if (fields[0] != toHex(expected_coord)) {
            return fail(error, "key coordinate mismatch at index line " + std::to_string(line_number));
        }

        const std::filesystem::path relative_file(fields[3]);
        if (!safeRelativePath(relative_file) || relative_file.parent_path() != "blocks" ||
            relative_file.extension() != ".raw" || relative_file.filename() != (expected_coord + ".raw")) {
            return fail(error, "unsafe block file path at index line " +
                                  std::to_string(line_number));
        }
        const auto file_path = snapshot_root / relative_file;
        std::ifstream raw(file_path, std::ios::binary);
        if (!raw) return fail(error, "cannot open block file " + fields[3]);
        std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(raw)), {});
        if (declared_bytes != bytes.size() || bytes.size() != kPhysicalBlockPayloadSize) {
            return fail(error, "invalid physical block size for " + fields[3]);
        }
        if (computeSha256(bytes) != fields[4]) {
            return fail(error, "checksum mismatch for " + fields[3]);
        }

        PhysicalBlockPayload payload;
        std::memcpy(payload.tiles.data(), bytes.data(), kTileBytesPerPhysicalBlock);
        payload.physicalBlockField13 = bytes[kTileBytesPerPhysicalBlock];
        const auto* tail = bytes.data() + kTileBytesPerPhysicalBlock + 1;
        payload.physicalBlockField24 = static_cast<std::uint32_t>(tail[0]) |
                                       (static_cast<std::uint32_t>(tail[1]) << 8) |
                                       (static_cast<std::uint32_t>(tail[2]) << 16) |
                                       (static_cast<std::uint32_t>(tail[3]) << 24);
        if (!next.emplace(std::make_pair(x, y), std::move(payload)).second) {
            return fail(error, "duplicate physical block coordinate");
        }
    }

    blocks_.swap(next);
    if (error) error->clear();
    return true;
}

const PhysicalBlockPayload* OriginalClientWorld::blockAt(std::int32_t x,
                                                          std::int32_t y) const {
    const auto it = blocks_.find(std::make_pair(x, y));
    return it == blocks_.end() ? nullptr : &it->second;
}

}  // namespace bh176
