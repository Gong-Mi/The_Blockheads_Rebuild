#include "dynamic_object_init_derived_stuff.h"

namespace blockheads::recovered {

namespace {

void store_word(std::vector<std::uint8_t>& image, std::size_t offset, std::uint32_t val) {
    if (offset + 4 <= image.size()) {
        image[offset + 0] = static_cast<std::uint8_t>(val & 0xff);
        image[offset + 1] = static_cast<std::uint8_t>((val >> 8) & 0xff);
        image[offset + 2] = static_cast<std::uint8_t>((val >> 16) & 0xff);
        image[offset + 3] = static_cast<std::uint8_t>((val >> 24) & 0xff);
    }
}

}  // namespace

DynamicObjectInitDerivedResult dynamic_object_init_derived_stuff(
    const DynamicObjectInitDerivedInputs& in) {
    DynamicObjectInitDerivedResult result;
    result.image.assign(kDynamicObjectDerivedImageSize, 0);

    store_word(result.image, 4, in.world_ptr);
    store_word(result.image, 8, in.dynamic_world_ptr);
    store_word(result.image, 16, static_cast<std::uint32_t>(in.pos_x));
    store_word(result.image, 20, static_cast<std::uint32_t>(in.pos_y));

    // 1. [world macroTiles]
    result.calls.emplace_back(DynamicObjectInitDerivedStuffCall::WorldMacroTiles, in.world_ptr);

    // 2. convertWorldToMacroCoord & lookupMacroTile -> macroTileOwner (offset 12)
    store_word(result.image, 12, in.macro_tile_ptr);

    // If macroTile == nil -> return false
    if (in.macro_tile_ptr == 0) {
        result.return_value = false;
        return result;
    }

    // 3. If physical block not loaded
    if (!in.physical_block_loaded) {
        if (in.load_physical_block_if_needed) {
            result.calls.emplace_back(DynamicObjectInitDerivedStuffCall::LoadPhysicalBlock, in.macro_tile_ptr);
        } else {
            result.return_value = false;
            return result;
        }
    }

    // 4. [self shouldAddToMacroBlock]
    result.calls.emplace_back(DynamicObjectInitDerivedStuffCall::ShouldAddToMacroBlock, in.should_add_to_macro_block ? 1 : 0);
    if (!in.should_add_to_macro_block) {
        result.return_value = true;
        return result;
    }

    // 5. [dynamicWorld loadDynamicObjectsIfNotAlreadyLoadedForMacroTile:includeSurfaceBlocks:1]
    result.calls.emplace_back(DynamicObjectInitDerivedStuffCall::LoadDynamicObjects, in.macro_tile_ptr);

    // 6. [macroTile->dynamicObjects addObject:self]
    result.calls.emplace_back(DynamicObjectInitDerivedStuffCall::AddObject, in.self_ptr);

    // 7. If !initDerivedStuff -> [self objectType] -> [dynamicWorld dynamicWorldChangedAtPos:objectType:]
    if (!in.init_derived_stuff) {
        result.calls.emplace_back(DynamicObjectInitDerivedStuffCall::ObjectType, static_cast<std::uint32_t>(in.object_type));
        result.calls.emplace_back(DynamicObjectInitDerivedStuffCall::DynamicWorldChanged, static_cast<std::uint32_t>(in.object_type));
    }

    result.return_value = true;
    return result;
}

}  // namespace blockheads::recovered
