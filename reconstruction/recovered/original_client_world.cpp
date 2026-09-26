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

        const std::filesystem::path relative_file(fields[3]);
        if (!safeRelativePath(relative_file) || relative_file.parent_path() != "blocks" ||
            relative_file.extension() != ".raw") {
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
