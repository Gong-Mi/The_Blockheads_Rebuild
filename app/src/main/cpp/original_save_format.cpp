#include "original_save_format.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <zlib.h>

namespace bh176 {
namespace {

void setError(std::string* error, const std::string& value) {
    if (error) *error = value;
}

std::uint32_t readLe32(const std::uint8_t* value) {
    return static_cast<std::uint32_t>(value[0]) |
           (static_cast<std::uint32_t>(value[1]) << 8U) |
           (static_cast<std::uint32_t>(value[2]) << 16U) |
           (static_cast<std::uint32_t>(value[3]) << 24U);
}

}  // namespace

std::int16_t OriginalTile::temperatureOffset() const {
    const std::uint16_t value = static_cast<std::uint16_t>(raw[20]) |
                                (static_cast<std::uint16_t>(raw[21]) << 8U);
    return static_cast<std::int16_t>(value);
}

bool decodePhysicalBlockPayload(const std::uint8_t* bytes,
                                std::size_t size,
                                PhysicalBlockPayload& output,
                                std::string* error) {
    if (!bytes) {
        setError(error, "physical-block payload is null");
        return false;
    }
    if (size != kPhysicalBlockPayloadSize) {
        setError(error,
                 "physical-block payload must be exactly 65541 bytes after gzip inflate");
        return false;
    }

    for (std::size_t index = 0; index < kTilesPerPhysicalBlock; ++index) {
        std::memcpy(output.tiles[index].raw.data(),
                    bytes + index * kOriginalTileSize,
                    kOriginalTileSize);
    }
    output.physicalBlockField13 = bytes[kTileBytesPerPhysicalBlock];
    output.physicalBlockField24 = readLe32(bytes + kTileBytesPerPhysicalBlock + 1);
    return true;
}

bool decodeGzipPhysicalBlock(const std::uint8_t* bytes,
                             std::size_t size,
                             PhysicalBlockPayload& output,
                             std::string* error) {
    if (!bytes || size == 0) {
        setError(error, "gzip physical-block record is empty");
        return false;
    }
    if (size > static_cast<std::size_t>(std::numeric_limits<uInt>::max())) {
        setError(error, "gzip physical-block record is too large for zlib");
        return false;
    }

    std::array<std::uint8_t, kPhysicalBlockPayloadSize> inflated{};
    z_stream stream{};
    stream.next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(bytes));
    stream.avail_in = static_cast<uInt>(size);
    stream.next_out = reinterpret_cast<Bytef*>(inflated.data());
    stream.avail_out = static_cast<uInt>(inflated.size());

    const int initResult = inflateInit2(&stream, MAX_WBITS + 16);
    if (initResult != Z_OK) {
        setError(error, "inflateInit2 failed");
        return false;
    }
    const int inflateResult = inflate(&stream, Z_FINISH);
    const bool exact = inflateResult == Z_STREAM_END &&
                       stream.total_out == kPhysicalBlockPayloadSize;
    inflateEnd(&stream);

    if (!exact) {
        setError(error,
                 "gzip record did not inflate to the exact 1.7.6 physical-block size");
        return false;
    }
    return decodePhysicalBlockPayload(inflated.data(), inflated.size(), output, error);
}

}  // namespace bh176
