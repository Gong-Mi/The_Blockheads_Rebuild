#ifndef ORIGINAL_SAVE_FORMAT_H
#define ORIGINAL_SAVE_FORMAT_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace bh176 {

constexpr std::size_t kMacroTileEdge = 32;
constexpr std::size_t kTilesPerPhysicalBlock = kMacroTileEdge * kMacroTileEdge;
constexpr std::size_t kOriginalTileSize = 64;
constexpr std::size_t kTileBytesPerPhysicalBlock =
        kTilesPerPhysicalBlock * kOriginalTileSize;
constexpr std::size_t kPhysicalBlockPayloadSize =
        kTileBytesPerPhysicalBlock + 1 + sizeof(std::uint32_t);

// The Objective-C type encoding in the 1.7.6 binary is:
// CCCCCCCCCCCCCSSSsCISSSSSQ[8S]
// ARMv7 natural alignment makes this structure exactly 64 bytes. Names below
// are only assigned where a named predicate/function proves the field meaning.
struct OriginalTile {
    std::array<std::uint8_t, kOriginalTileSize> raw{};

    std::uint8_t type() const { return raw[0]; }
    std::uint8_t backWallType() const { return raw[1]; }
    std::uint8_t contentsType() const { return raw[3]; }
    std::uint8_t temperatureScaleByte() const { return raw[7]; }
    std::int16_t temperatureOffset() const;
};

static_assert(sizeof(OriginalTile) == kOriginalTileSize,
              "The Blockheads 1.7.6 Tile must remain 64 bytes");

struct PhysicalBlockPayload {
    std::array<OriginalTile, kTilesPerPhysicalBlock> tiles{};

    // savePhysicalBlock:... appends PhysicalBlock byte offset 13 after tiles.
    // Its semantic name is not yet proven, so retain an offset-based name.
    std::uint8_t physicalBlockField13 = 0;

    // savePhysicalBlock:... then appends four bytes from offset 24.
    std::uint32_t physicalBlockField24 = 0;
};

bool decodePhysicalBlockPayload(const std::uint8_t* bytes,
                                std::size_t size,
                                PhysicalBlockPayload& output,
                                std::string* error = nullptr);

bool decodeGzipPhysicalBlock(const std::uint8_t* bytes,
                            std::size_t size,
                            PhysicalBlockPayload& output,
                            std::string* error = nullptr);

inline bool decodeGzipPhysicalBlock(const std::vector<std::uint8_t>& bytes,
                                    PhysicalBlockPayload& output,
                                    std::string* error = nullptr) {
    return decodeGzipPhysicalBlock(bytes.data(), bytes.size(), output, error);
}

}  // namespace bh176

#endif
