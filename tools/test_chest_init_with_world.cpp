// Hand-written contract checks for the recovered Chest loader (batch b4m).
//
// These expectations are computed by hand from the ARM listing (never from the
// C++ implementation) and are deliberately independent of the Unicorn
// differential: the differential proves the pair matches the original binary,
// this file proves the pair itself is not self-consistently wrong (capacity
// edges, the re-read after the rules gate, the 16-bit shelf truncation).
#include "chest_init_with_world.h"

#include <cassert>
#include <iostream>

using blockheads::recovered::ChestInitCall;
using blockheads::recovered::ChestInitInputs;
using blockheads::recovered::ChestSlotEntry;
using blockheads::recovered::ChestSlotItemEntry;
using blockheads::recovered::chest_init_with_world;
using blockheads::recovered::chest_slot_capacity;
using blockheads::recovered::kChestImageSize;
using blockheads::recovered::kChestInventoryArrayToken;
using blockheads::recovered::kChestOffsetChestType;
using blockheads::recovered::kChestOffsetInventoryItems;
using blockheads::recovered::kChestOffsetShelfItemDataBs;
using blockheads::recovered::kChestOffsetShelfRenderItems;
using blockheads::recovered::kChestSlotArrayBase;

namespace {

std::uint32_t word_at(const std::vector<std::uint8_t>& image, std::size_t off) {
    return static_cast<std::uint32_t>(image[off]) |
           (static_cast<std::uint32_t>(image[off + 1]) << 8) |
           (static_cast<std::uint32_t>(image[off + 2]) << 16) |
           (static_cast<std::uint32_t>(image[off + 3]) << 24);
}

std::uint16_t half_at(const std::vector<std::uint8_t>& image, std::size_t off) {
    return static_cast<std::uint16_t>(
        static_cast<std::uint16_t>(image[off]) |
        (static_cast<std::uint16_t>(image[off + 1]) << 8));
}

int count_code(const std::vector<std::pair<ChestInitCall, std::uint32_t>>& t,
               ChestInitCall code) {
    int n = 0;
    for (const auto& c : t) {
        if (c.first == code) ++n;
    }
    return n;
}

ChestSlotEntry slot_with(std::initializer_list<ChestSlotItemEntry> items) {
    ChestSlotEntry s;
    s.items.assign(items.begin(), items.end());
    return s;
}

}  // namespace

int main() {
    // 0. The capacity rule itself, both directions and the default.
    assert(chest_slot_capacity(2) == 4);
    assert(chest_slot_capacity(5) == 4);
    assert(chest_slot_capacity(0) == 16);
    assert(chest_slot_capacity(4) == 16);
    assert(chest_slot_capacity(-1) == 16);

    // 1. Nil super result: the body returns nil and touches no ivar.
    {
        ChestInitInputs in;
        in.super_returns_nil = true;
        in.owner_id_ivar = 0x0BAD0001u;
        auto res = chest_init_with_world(in);
        assert(res.return_value == 0);
        assert(res.calls.size() == 1);
        assert(res.calls[0].first == ChestInitCall::MsgSendSuper);
        assert(word_at(res.image, 36) == 0x0BAD0001u);
        assert(word_at(res.image, kChestOffsetInventoryItems) == 0);
        assert(word_at(res.image, kChestOffsetChestType) == 0);
    }

    // 2. chestType 2 (four-slot chest), saveItemSlots with four entries.
    {
        ChestInitInputs in;
        in.self_ptr = 0x60000000u;
        in.world_ivar = 0x5E1C0004u;
        in.dynamic_world_ivar = 0x5E1C0008u;
        in.pos_x = 0x11223344u;
        in.pos_y = 0x55667788u;
        in.chest_type_value = 2;
        in.safe_client_id_token = 0x5E1C0005u;
        in.object_type_value = 0x42u;
        in.slots_array_token = 0x5E1C0009u;
        in.slots = {slot_with({{0x8001, 3}}), slot_with({{0x8002, 11}}),
                    slot_with({{0x8003, 7}}), slot_with({{0x8004, 0}})};

        auto res = chest_init_with_world(in);
        assert(res.return_value == 0x60000000u);
        assert(word_at(res.image, 108) == 2);
        assert(word_at(res.image, 100) == kChestInventoryArrayToken);
        assert(word_at(res.image, 36) == 0x5E1C0005u);

        // Alloc/InitWithCapacity order and the four-slot capacity.
        assert(res.calls[0].first == ChestInitCall::MsgSendSuper);
        assert(res.calls[1].first == ChestInitCall::ObjectForKeyChestType);
        assert(res.calls[2].first == ChestInitCall::IntValueChestType);
        assert(res.calls[3].first == ChestInitCall::ObjectForKeySafeClientID);
        assert(res.calls[4].first == ChestInitCall::RetainSafeClientID);
        assert(res.calls[5].first == ChestInitCall::ObjectForKeySaveItemSlots);
        assert(res.calls[6].first == ChestInitCall::ObjectType);
        assert(res.calls[7].first == ChestInitCall::DynamicWorldChangedAtPos);
        assert(res.calls[8].first == ChestInitCall::AllocNSMutableArray);
        assert(res.calls[9].first == ChestInitCall::InitWithCapacity);
        assert(res.calls[9].second == 4);
        assert(res.calls[10].first == ChestInitCall::CountSaveItemSlots);
        assert(res.calls[10].second == 4);

        // Four slots, each 2 + 2 + 1 + enumeration entries.
        assert(count_code(res.calls, ChestInitCall::ArrayNSMutableArray) == 4);
        assert(count_code(res.calls, ChestInitCall::AddObjectSlotArray) == 4);
        assert(count_code(res.calls, ChestInitCall::ObjectAtIndex) == 4);
        assert(count_code(res.calls, ChestInitCall::StateMemset) == 4);
        assert(count_code(res.calls, ChestInitCall::FastEnumeration) == 8);
        assert(count_code(res.calls, ChestInitCall::AllocInventoryItem) == 4);
        assert(count_code(res.calls, ChestInitCall::InitWithSaveData) == 4);
        assert(count_code(res.calls, ChestInitCall::AutoreleaseItem) == 4);

        // itemType 11 filter: four items, one filtered out.
        assert(count_code(res.calls, ChestInitCall::AddObjectItem) == 3);
        for (const auto& c : res.calls) {
            if (c.first == ChestInitCall::AddObjectItem) {
                assert(c.second != 0x8002);
            }
        }

        // The slot arrays themselves are added to inventoryItems in order.
        std::size_t idx = 0;
        for (int i = 0; i < 4; ++i) {
            while (idx < res.calls.size() &&
                   res.calls[idx].first != ChestInitCall::AddObjectSlotArray) {
                ++idx;
            }
            assert(idx < res.calls.size());
            assert(res.calls[idx].second == kChestSlotArrayBase + i);
            ++idx;
        }
        // No shelf loop: inventoryItems is non-nil.
        assert(count_code(res.calls, ChestInitCall::InitSubDerivedItems) == 1);
        assert(res.calls.back().first == ChestInitCall::InitSubDerivedItems);
        assert(word_at(res.image, kChestOffsetShelfRenderItems) == 0);
    }

    // 3. Fewer saved slots than the chest capacity -> pad path, no restore.
    {
        ChestInitInputs in;
        in.chest_type_value = 2;                  // capacity 4
        in.slots_array_token = 0x5E1C0009u;
        in.slots = {slot_with({{0x9001, 1}}), slot_with({{0x9002, 2}})};

        auto res = chest_init_with_world(in);
        assert(word_at(res.image, 100) == kChestInventoryArrayToken);
        assert(count_code(res.calls, ChestInitCall::ArrayNSMutableArray) == 4);
        assert(count_code(res.calls, ChestInitCall::AddObjectSlotArray) == 4);
        assert(count_code(res.calls, ChestInitCall::ObjectAtIndex) == 0);
        assert(count_code(res.calls, ChestInitCall::FastEnumeration) == 0);
        assert(count_code(res.calls, ChestInitCall::AllocInventoryItem) == 0);
        // Exactly the capacity is requested, not the saved count.
        for (const auto& c : res.calls) {
            if (c.first == ChestInitCall::InitWithCapacity) {
                assert(c.second == 4);
            }
        }
    }

    // 4. chestType 4 + non-zero rules byte 0: the field is zeroed and then
    //    RE-READ, so the 16-slot path runs (the gate is not a dead store).
    {
        ChestInitInputs in;
        in.world_ivar = 0x5E1C0004u;
        in.chest_type_value = 4;
        in.rules_byte0 = 1;
        in.slots_array_token = 0x5E1C0009u;
        in.slots.assign(16, slot_with({}));

        auto res = chest_init_with_world(in);
        assert(word_at(res.image, 108) == 0);
        assert(res.calls[1].first == ChestInitCall::ObjectForKeyChestType);
        assert(res.calls[2].first == ChestInitCall::IntValueChestType);
        assert(res.calls[3].first == ChestInitCall::CustomRulesStret);
        assert(res.calls[3].second == 1);
        bool saw_capacity_16 = false;
        for (const auto& c : res.calls) {
            if (c.first == ChestInitCall::InitWithCapacity) {
                assert(c.second == 16);
                saw_capacity_16 = true;
            }
            // The zeroed field does not reach the four-slot branch.
            assert(c.second != 4 || c.first != ChestInitCall::InitWithCapacity);
        }
        assert(saw_capacity_16);
        assert(count_code(res.calls, ChestInitCall::ObjectForKeySaveItemSlots) == 1);
        assert(count_code(res.calls, ChestInitCall::ArrayNSMutableArray) == 16);
        assert(count_code(res.calls, ChestInitCall::FastEnumeration) == 16);
        assert(count_code(res.calls, ChestInitCall::InitSubDerivedItems) == 1);
    }

    // 5. chestType 4 + zero rules byte (and the nil-world memset variant):
    //    inventoryItems stays nil and the shelf loop restores both families,
    //    with the 16-bit truncation on the item-data shelf.
    for (int world_present = 0; world_present < 2; ++world_present) {
        ChestInitInputs in;
        in.world_ivar = world_present ? 0x5E1C0004u : 0u;
        in.chest_type_value = 4;
        in.rules_byte0 = 0;
        in.slots_array_token = 0x5E1C0009u;
        in.slots.assign(16, slot_with({}));
        in.shelf_render_box_tokens = {0x5E1CA001u, 0x5E1CA002u, 0, 0x5E1CA004u};
        in.shelf_render_values = {0x11u, 0x22u, 0u, 0x44u};
        in.shelf_item_data_box_tokens = {0x5E1CB001u, 0, 0x5E1CB003u, 0x5E1CB004u};
        in.shelf_item_data_values = {0x12345u, 0u, 0x7u, 0xFFFFu};

        auto res = chest_init_with_world(in);
        assert(word_at(res.image, 108) == 4);
        assert(word_at(res.image, 100) == 0);
        assert(count_code(res.calls, ChestInitCall::ObjectForKeySaveItemSlots) == 0);
        assert(count_code(res.calls, ChestInitCall::ArrayNSMutableArray) == 0);
        if (world_present) {
            assert(count_code(res.calls, ChestInitCall::CustomRulesStret) == 1);
            assert(count_code(res.calls, ChestInitCall::CustomRulesMemset) == 0);
        } else {
            assert(count_code(res.calls, ChestInitCall::CustomRulesStret) == 0);
            assert(count_code(res.calls, ChestInitCall::CustomRulesMemset) == 1);
        }
        assert(count_code(res.calls, ChestInitCall::StringWithFormatShelfRenderItems) == 4);
        assert(count_code(res.calls, ChestInitCall::ObjectForKeyShelfRenderItems) == 4);
        assert(count_code(res.calls, ChestInitCall::StringWithFormatShelfItemDataBs) == 4);
        assert(count_code(res.calls, ChestInitCall::ObjectForKeyShelfItemDataBs) == 4);

        assert(word_at(res.image, kChestOffsetShelfRenderItems + 0) == 0x11u);
        assert(word_at(res.image, kChestOffsetShelfRenderItems + 4) == 0x22u);
        assert(word_at(res.image, kChestOffsetShelfRenderItems + 8) == 0u);
        assert(word_at(res.image, kChestOffsetShelfRenderItems + 12) == 0x44u);
        // 0x12345 -> strh truncation to 0x2345; missing key -> 0.
        assert(half_at(res.image, kChestOffsetShelfItemDataBs + 0) == 0x2345u);
        assert(half_at(res.image, kChestOffsetShelfItemDataBs + 2) == 0u);
        assert(half_at(res.image, kChestOffsetShelfItemDataBs + 4) == 0x7u);
        assert(half_at(res.image, kChestOffsetShelfItemDataBs + 6) == 0xFFFFu);
        // 132 + 4 * 2 == instance_size (140): the image is fully covered.
        assert(kChestImageSize == 140);
        assert(res.calls.back().first == ChestInitCall::InitSubDerivedItems);
    }

    // 6. A pre-set ownerID skips the safeClientID default.
    {
        ChestInitInputs in;
        in.chest_type_value = 2;
        in.owner_id_ivar = 0x5E1C0FFFu;
        in.safe_client_id_token = 0x5E1C0EEEu;
        in.slots_array_token = 0x5E1C0009u;
        in.slots.assign(4, slot_with({}));

        auto res = chest_init_with_world(in);
        assert(count_code(res.calls, ChestInitCall::ObjectForKeySafeClientID) == 0);
        assert(count_code(res.calls, ChestInitCall::RetainSafeClientID) == 0);
        assert(word_at(res.image, 36) == 0x5E1C0FFFu);
    }

    // 7. Missing saveItemSlots key: nothing is restored, shelf loop runs.
    {
        ChestInitInputs in;
        in.chest_type_value = 0;
        in.slots_array_token = 0u;
        in.shelf_render_box_tokens = {0x5E1CA001u, 0x5E1CA002u, 0x5E1CA003u, 0x5E1CA004u};
        in.shelf_render_values = {1u, 2u, 3u, 4u};

        auto res = chest_init_with_world(in);
        assert(word_at(res.image, 100) == 0);
        assert(count_code(res.calls, ChestInitCall::AllocNSMutableArray) == 0);
        assert(count_code(res.calls, ChestInitCall::InitWithCapacity) == 0);
        assert(count_code(res.calls, ChestInitCall::ArrayNSMutableArray) == 0);
        assert(count_code(res.calls, ChestInitCall::ObjectForKeyShelfRenderItems) == 4);
        assert(word_at(res.image, kChestOffsetShelfRenderItems + 12) == 4u);
    }

    // 8. Chunked fast enumeration: 18 items -> batches 16, 2, 0 (terminal).
    {
        ChestInitInputs in;
        in.chest_type_value = 2;   // capacity 4
        in.slots_array_token = 0x5E1C0009u;
        ChestSlotEntry big;
        for (int i = 0; i < 18; ++i) {
            big.items.push_back(ChestSlotItemEntry{0xA000u + static_cast<std::uint32_t>(i),
                                                   static_cast<std::uint32_t>(i)});
        }
        in.slots = {big, slot_with({}), slot_with({}), slot_with({})};

        auto res = chest_init_with_world(in);
        std::vector<std::uint32_t> batches;
        for (const auto& c : res.calls) {
            if (c.first == ChestInitCall::FastEnumeration) batches.push_back(c.second);
        }
        // slot 0: 16, 2, 0; slots 1..3: 0 each.
        assert(batches.size() == 6);
        assert(batches[0] == 16 && batches[1] == 2 && batches[2] == 0);
        assert(batches[3] == 0 && batches[4] == 0 && batches[5] == 0);
        // 18 items, itemType == 11 at index 11 -> 17 added.
        assert(count_code(res.calls, ChestInitCall::AddObjectItem) == 17);
    }

    // 9. Enumeration mutation: the counter bumps while element 1 of slot 1 is
    //    constructed, so elements 2 and 3 of that batch observe the change.
    {
        ChestInitInputs in;
        in.chest_type_value = 2;
        in.slots_array_token = 0x5E1C0009u;
        in.slots = {slot_with({{0xB001, 1}, {0xB002, 2}, {0xB003, 3}, {0xB004, 4}}),
                    slot_with({{0xB005, 5}}), slot_with({}), slot_with({})};
        in.mutate_slot = 0;
        in.mutate_item = 1;

        auto res = chest_init_with_world(in);
        assert(count_code(res.calls, ChestInitCall::EnumerationMutation) == 2);
        // Both mutation calls carry the slot-0 array token.
        for (const auto& c : res.calls) {
            if (c.first == ChestInitCall::EnumerationMutation) {
                assert(c.second == kChestSlotArrayBase);
            }
        }
        // Without the fixture bump the same body emits none.
        ChestInitInputs plain = in;
        plain.mutate_slot = -1;
        plain.mutate_item = -1;
        auto plain_res = chest_init_with_world(plain);
        assert(count_code(plain_res.calls, ChestInitCall::EnumerationMutation) == 0);
    }

    std::cout << "test_chest_init_with_world: PASS\n";
    return 0;
}
