#ifndef ORIGINAL_CLIENT_WORLD_H
#define ORIGINAL_CLIENT_WORLD_H

#include "../../app/src/main/cpp/original_save_format.h"
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <string>

namespace bh176 {

// Client-side raw world state. It deliberately keeps the original 64-byte Tile
// layout instead of casting it to the replacement game's packed Tile struct.
class OriginalClientWorld {
public:
    bool load(const std::filesystem::path& snapshot_root,
              std::string* error = nullptr);

    const PhysicalBlockPayload* blockAt(std::int32_t x, std::int32_t y) const;
    std::size_t blockCount() const { return blocks_.size(); }

    // Publish a fully-verified candidate world (transactional open in
    // OriginalClientApp). Only called after every load check has passed.
    void swap(OriginalClientWorld& other) noexcept { blocks_.swap(other.blocks_); }

private:
    std::map<std::pair<std::int32_t, std::int32_t>, PhysicalBlockPayload> blocks_;
};

}  // namespace bh176

#endif
