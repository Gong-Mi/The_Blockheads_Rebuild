// Hand-written contract checks for the recovered Workbench loader (b4q).
#include "workbench_init.h"

#include <cassert>
#include <cstring>
#include <iostream>

using blockheads::recovered::WorkbenchInitCall;
using blockheads::recovered::WorkbenchInitInputs;
using blockheads::recovered::workbench_init_with_world;
using blockheads::recovered::kWorkbenchImageSize;
using blockheads::recovered::kWorkbenchOffsetCraftingItem;
using blockheads::recovered::kWorkbenchOffsetCount;
using blockheads::recovered::kWorkbenchOffsetHasFuel;
using blockheads::recovered::kWorkbenchOffsetIsInUse;
using blockheads::recovered::kWorkbenchOffsetIsInUseFuel;
using blockheads::recovered::kWorkbenchOffsetLight;
using blockheads::recovered::kWorkbenchOffsetSavedBhFuel;
using blockheads::recovered::kWorkbenchOffsetSourceItems;

namespace {

std::uint32_t word_at(const std::vector<std::uint8_t>& image, std::size_t off) {
    return static_cast<std::uint32_t>(image[off]) |
           (static_cast<std::uint32_t>(image[off + 1]) << 8) |
           (static_cast<std::uint32_t>(image[off + 2]) << 16) |
           (static_cast<std::uint32_t>(image[off + 3]) << 24);
}

int count_code(
        const std::vector<std::pair<WorkbenchInitCall, std::uint32_t>>& t,
        WorkbenchInitCall code) {
    int n = 0;
    for (const auto& c : t)
        if (c.first == code) ++n;
    return n;
}

WorkbenchInitInputs base_inputs() {
    WorkbenchInitInputs in;
    in.self_ptr = 0x60000000u;
    in.world_ivar = 0x5E1A0004u;
    in.dynamic_world_ivar = 0x5E1A0008u;
    in.cache_ivar = 0x5E1A0040u;
    in.pos_x = 12;
    in.pos_y = 34;
    in.workbench_type_value = 3;
    in.selected_index_value = 1;
    in.x_scroll_value = 2.5f;
    in.level_value = 2;
    in.craft_progress_value = 0.5f;
    in.hurry_timer_value = 7.0f;
    in.hurry_seconds_value = 8.0f;
    in.hurrying_value = 0;
    in.hurry_cost_value = 5;
    in.fire_spread_value = 9.0f;
    in.fuel_fraction_value = 0.75f;
    in.has_fuel_value = 1;
    in.last_world_time_value = 123.5;
    in.is_in_use_fuel_value = 0;
    in.available_elec_value = 42;
    in.blockhead_index_fuel_value = -1;
    return in;
}

}  // namespace

int main() {
    // 1. Nil super.
    {
        WorkbenchInitInputs in = base_inputs();
        in.super_returns_nil = true;
        auto res = workbench_init_with_world(in);
        assert(res.return_value == 0);
        assert(res.calls.size() == 1);
    }

    // 2. Plain walk: 36 calls, the double currentBlockheadIndexFuel read.
    {
        WorkbenchInitInputs in = base_inputs();
        auto res = workbench_init_with_world(in);
        assert(res.return_value == in.self_ptr);
        assert(res.calls.size() == 36);
        assert(count_code(res.calls,
                         WorkbenchInitCall::ObjectForKeyBlockheadIndexFuel) == 2);
        assert(count_code(res.calls,
                         WorkbenchInitCall::IntValueBlockheadIndexFuel) == 1);
        // -1 sentinel stored as 0xffffffff
        assert(word_at(res.image, kWorkbenchOffsetSavedBhFuel) == 0xffffffffu);
        assert(count_code(res.calls, WorkbenchInitCall::SetInteractionWorkbenchCraft) == 0);
        assert(count_code(res.calls, WorkbenchInitCall::InitSubDerivedItems) == 1);
    }

    // 3. isInUse + v2 type 1: BlockheadCraftableItemObject path + wiring.
    {
        WorkbenchInitInputs in = base_inputs();
        in.is_in_use = 1;
        in.is_in_use_init = 1;   // the super's isInUse side effect (the gate)
        in.crafting_v2_present = true;
        in.craftable_object_type = 1;
        in.crafting_item_nonnil = true;
        auto res = workbench_init_with_world(in);
        assert(count_code(res.calls, WorkbenchInitCall::CraftableAlloc) == 1);
        // alloc arg encodes the classref: 1 = BlockheadCraftableItemObject
        for (const auto& c : res.calls)
            if (c.first == WorkbenchInitCall::CraftableAlloc) assert(c.second == 1);
        assert(word_at(res.image, kWorkbenchOffsetCraftingItem)
               == blockheads::recovered::kWorkbenchCraftableResult);
        assert(count_code(res.calls,
                          WorkbenchInitCall::SetInteractionWorkbenchCraft) == 1);
    }

    // 4. v1 migration: bytes + two 124-byte copies.
    {
        WorkbenchInitInputs in = base_inputs();
        in.is_in_use = 1;
        in.is_in_use_init = 1;
        in.crafting_v1_present = true;
        in.crafting_item_nonnil = true;
        auto res = workbench_init_with_world(in);
        assert(count_code(res.calls, WorkbenchInitCall::BytesCopy) == 3);
        // one selector record (0) + two memcpy records (124 each)
        int blob124 = 0;
        for (const auto& c : res.calls)
            if (c.first == WorkbenchInitCall::BytesCopy
                && c.second == 124) ++blob124;
        assert(blob124 == 2);
        assert(count_code(res.calls,
                          WorkbenchInitCall::CraftableInitWithCraftableItem) == 1);
    }

    // 5. isInUse with NO data: wiring still fires (nil receiver no-op).
    {
        WorkbenchInitInputs in = base_inputs();
        in.is_in_use = 1;
        in.is_in_use_init = 1;
        auto res = workbench_init_with_world(in);
        assert(count_code(res.calls,
                          WorkbenchInitCall::SetInteractionWorkbenchCraft) == 1);
        assert(count_code(res.calls, WorkbenchInitCall::CraftableAlloc) == 0);
    }

    // 6. sourceItems walk: fresh slot stored, type-11 slot skipped.
    {
        WorkbenchInitInputs in = base_inputs();
        in.is_in_use = 1;
        in.is_in_use_init = 1;
        in.crafting_v2_present = true;
        in.craftable_object_type = 1;
        in.crafting_item_nonnil = true;
        in.slot_elem_counts = {3, 0};
        in.slot_types = {0, 11};
        in.sub_types = {7, 11, 9};
        in.count_value = 1;
        auto res = workbench_init_with_world(in);
        // slot 0: 3 payloads; slot 1: type-11 -> gated before count
        assert(count_code(res.calls, WorkbenchInitCall::ReleaseSlot) == 2);
        assert(count_code(res.calls,
                          WorkbenchInitCall::MutableArrayAllocSlot) == 1);
        assert(word_at(res.image, kWorkbenchOffsetSourceItems)
               == blockheads::recovered::kWorkbenchFreshSlot);
    }

    // 7. fuel wiring + light restore.
    {
        WorkbenchInitInputs in = base_inputs();
        in.is_in_use_fuel_value = 1;
        in.light_dict_present = true;
        in.light_answer = 0x5E1A0C80u;
        auto res = workbench_init_with_world(in);
        assert(count_code(res.calls,
                          WorkbenchInitCall::SetInteractionWorkbenchFuel) == 1);
        assert(count_code(res.calls, WorkbenchInitCall::LightInitWithWorld) == 1);
        assert(word_at(res.image, kWorkbenchOffsetLight) == 0x5E1A0C80u);
        assert(count_code(res.calls, WorkbenchInitCall::MacroTiles) == 3);
    }

    std::cout << "test_workbench_init: all assertions passed\n";
    return 0;
}
