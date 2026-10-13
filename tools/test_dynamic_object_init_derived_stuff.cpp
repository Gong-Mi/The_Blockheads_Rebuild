#include "dynamic_object_init_derived_stuff.h"

#include <cassert>
#include <iostream>

using blockheads::recovered::DynamicObjectInitDerivedStuffCall;
using blockheads::recovered::DynamicObjectInitDerivedInputs;
using blockheads::recovered::dynamic_object_init_derived_stuff;

int main() {
    // 1. Happy path: physical block loaded, shouldAddToMacroBlock = true, initDerivedStuff = true
    {
        DynamicObjectInitDerivedInputs in;
        in.self_ptr = 0x60000000u;
        in.world_ptr = 0x60010000u;
        in.dynamic_world_ptr = 0x60020000u;
        in.pos_x = 100;
        in.pos_y = 200;
        in.macro_tile_ptr = 0x60030000u;
        in.physical_block_loaded = true;
        in.should_add_to_macro_block = true;
        in.init_derived_stuff = true;
        in.load_physical_block_if_needed = true;

        auto res = dynamic_object_init_derived_stuff(in);
        assert(res.return_value == true);
        assert(res.calls.size() == 4);
        assert(res.calls[0].first == DynamicObjectInitDerivedStuffCall::WorldMacroTiles);
        assert(res.calls[1].first == DynamicObjectInitDerivedStuffCall::ShouldAddToMacroBlock);
        assert(res.calls[2].first == DynamicObjectInitDerivedStuffCall::LoadDynamicObjects);
        assert(res.calls[3].first == DynamicObjectInitDerivedStuffCall::AddObject);

        // Check macroTileOwner stored at offset 12
        std::uint32_t owner = *reinterpret_cast<const std::uint32_t*>(&res.image[12]);
        assert(owner == in.macro_tile_ptr);
    }

    // 2. Nil macroTile path -> return false
    {
        DynamicObjectInitDerivedInputs in;
        in.macro_tile_ptr = 0;

        auto res = dynamic_object_init_derived_stuff(in);
        assert(res.return_value == false);
        assert(res.calls.size() == 1); // Only WorldMacroTiles
        std::uint32_t owner = *reinterpret_cast<const std::uint32_t*>(&res.image[12]);
        assert(owner == 0);
    }

    // 3. Physical block not loaded, loadPhysicalBlockIfNeeded = true
    {
        DynamicObjectInitDerivedInputs in;
        in.physical_block_loaded = false;
        in.load_physical_block_if_needed = true;
        in.should_add_to_macro_block = true;

        auto res = dynamic_object_init_derived_stuff(in);
        assert(res.return_value == true);
        assert(res.calls.size() == 5);
        assert(res.calls[1].first == DynamicObjectInitDerivedStuffCall::LoadPhysicalBlock);
    }

    // 4. Physical block not loaded, loadPhysicalBlockIfNeeded = false -> return false
    {
        DynamicObjectInitDerivedInputs in;
        in.physical_block_loaded = false;
        in.load_physical_block_if_needed = false;

        auto res = dynamic_object_init_derived_stuff(in);
        assert(res.return_value == false);
    }

    // 5. shouldAddToMacroBlock = false -> return true early without loading dynamic objects or adding
    {
        DynamicObjectInitDerivedInputs in;
        in.should_add_to_macro_block = false;

        auto res = dynamic_object_init_derived_stuff(in);
        assert(res.return_value == true);
        assert(res.calls.size() == 2); // WorldMacroTiles, ShouldAddToMacroBlock
    }

    // 6. !initDerivedStuff -> notifies dynamicWorldChangedAtPos:objectType:
    {
        DynamicObjectInitDerivedInputs in;
        in.init_derived_stuff = false;
        in.object_type = 42;

        auto res = dynamic_object_init_derived_stuff(in);
        assert(res.return_value == true);
        assert(res.calls.size() == 6);
        assert(res.calls[4].first == DynamicObjectInitDerivedStuffCall::ObjectType);
        assert(res.calls[4].second == 42);
        assert(res.calls[5].first == DynamicObjectInitDerivedStuffCall::DynamicWorldChanged);
        assert(res.calls[5].second == 42);
    }

    std::cout << "test_dynamic_object_init_derived_stuff: PASS\n";
    return 0;
}
