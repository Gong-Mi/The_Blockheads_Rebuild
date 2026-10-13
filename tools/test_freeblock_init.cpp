// Hand-written contract checks for the recovered FreeBlock loader (b4p).
#include "freeblock_init.h"

#include <cassert>
#include <cstring>
#include <iostream>

using blockheads::recovered::FreeblockInitCall;
using blockheads::recovered::FreeblockInitInputs;
using blockheads::recovered::freeblock_init_with_world;
using blockheads::recovered::freeblock_blacklist_627c40_contains;
using blockheads::recovered::freeblock_liquid_5b2ad4_contains;
using blockheads::recovered::kFreeblockImageSize;
using blockheads::recovered::kFreeblockOffsetBounceTimer;
using blockheads::recovered::kFreeblockOffsetCreationTime;
using blockheads::recovered::kFreeblockOffsetFallSpeed;
using blockheads::recovered::kFreeblockOffsetFloatPos;
using blockheads::recovered::kFreeblockOffsetHovers;
using blockheads::recovered::kFreeblockOffsetItemType;
using blockheads::recovered::kFreeblockOffsetDataA;
using blockheads::recovered::kFreeblockOffsetDataB;
using blockheads::recovered::kFreeblockOffsetSubItems;
using blockheads::recovered::kFreeblockOffsetPriorityBlockhead;
using blockheads::recovered::kFreeblockOffsetUpdateNeeds;

namespace {

std::uint32_t word_at(const std::vector<std::uint8_t>& image, std::size_t off) {
    return static_cast<std::uint32_t>(image[off]) |
           (static_cast<std::uint32_t>(image[off + 1]) << 8) |
           (static_cast<std::uint32_t>(image[off + 2]) << 16) |
           (static_cast<std::uint32_t>(image[off + 3]) << 24);
}

float float_at(const std::vector<std::uint8_t>& image, std::size_t off) {
    const std::uint32_t bits = word_at(image, off);
    float value = 0.0f;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

double double_at(const std::vector<std::uint8_t>& image, std::size_t off) {
    double value = 0.0;
    std::memcpy(&value, image.data() + off, sizeof(value));
    return value;
}

int count_code(
        const std::vector<std::pair<FreeblockInitCall, std::uint32_t>>& t,
        FreeblockInitCall code) {
    int n = 0;
    for (const auto& c : t) {
        if (c.first == code) ++n;
    }
    return n;
}

FreeblockInitInputs base_inputs() {
    FreeblockInitInputs in;
    in.self_ptr = 0x60000000u;
    in.world_ivar = 0x5E1A0004u;
    in.dynamic_world_ivar = 0x5E1A0008u;
    in.pos_x = 30;
    in.pos_y = -5;
    in.item_type_init = 7;
    in.bounce_timer_value = 1.5f;
    in.fall_speed_value = 20.0f;
    in.creation_time_value = 10.0;
    in.float_vx_value = 3.5f;
    in.float_vy_value = -1.25f;
    in.hovers_value = 0;
    in.item_type_value = 7;
    in.data_a_value = 3;
    in.data_b_value = 4;
    in.priority_id_value = 0;
    in.world_time = 50.0;
    in.object_type_value = 0x5E1A0041u;
    return in;
}

}  // namespace

int main() {
    // 1. Nil super: no key read, no ivar touched.
    {
        FreeblockInitInputs in = base_inputs();
        in.super_returns_nil = true;
        auto res = freeblock_init_with_world(in);
        assert(res.return_value == 0);
        assert(res.calls.size() == 1);
        assert(res.calls[0].first == FreeblockInitCall::MsgSendSuper);
        assert(word_at(res.image, kFreeblockOffsetItemType) == 7);
    }

    // 2. Plain key walk: all twelve keys, no hovers tail.
    {
        FreeblockInitInputs in = base_inputs();
        auto res = freeblock_init_with_world(in);
        assert(res.return_value == in.self_ptr);
        // key order: bounceTimer, fallSpeed, creationTime, floatPos[VX],
        // floatPos[VY], hovers, itemType, dataA, dataB (each +conversion),
        // then fresh-array alloc/init, subItems, one enumerate call,
        // dynSaveDict + copy, priorityId + intValue(0), initSubDerivedObjects.
        assert(res.calls.size() == 28);
        assert(res.calls[1].first == FreeblockInitCall::ObjectForKeyBounceTimer);
        assert(res.calls[3].first == FreeblockInitCall::ObjectForKeyFallSpeed);
        assert(res.calls[5].first == FreeblockInitCall::ObjectForKeyCreationTime);
        assert(res.calls[7].first == FreeblockInitCall::ObjectForKeyFloatPosVX);
        assert(res.calls[9].first == FreeblockInitCall::ObjectForKeyFloatPosVY);
        assert(res.calls[11].first == FreeblockInitCall::ObjectForKeyHovers);
        assert(res.calls[13].first == FreeblockInitCall::ObjectForKeyItemType);
        assert(res.calls[15].first == FreeblockInitCall::ObjectForKeyDataA);
        assert(res.calls[17].first == FreeblockInitCall::ObjectForKeyDataB);
        assert(float_at(res.image, kFreeblockOffsetBounceTimer) == 1.5f);
        assert(float_at(res.image, kFreeblockOffsetFallSpeed) == 20.0f);
        assert(double_at(res.image, kFreeblockOffsetCreationTime) == 10.0);
        assert(float_at(res.image, kFreeblockOffsetFloatPos) == 3.5f);
        assert(float_at(res.image, kFreeblockOffsetFloatPos + 4) == -1.25f);
        assert(word_at(res.image, kFreeblockOffsetItemType) == 7);
        // dataA/dataB are halfwords at 60/62 (strh in the original)
        const std::uint16_t ha = static_cast<std::uint16_t>(
            word_at(res.image, kFreeblockOffsetDataA) & 0xffffu);
        const std::uint16_t hb = static_cast<std::uint16_t>(
            word_at(res.image, kFreeblockOffsetDataB - 2) >> 16);
        assert(ha == 3);
        assert(hb == 4);
        assert(res.image[kFreeblockOffsetHovers] == 0);
        // subItems ivar = the fresh array token
        assert(word_at(res.image, kFreeblockOffsetSubItems) == 0x5E1A0B80u);
        // no hovers tail: no worldTime, no notification
        assert(count_code(res.calls, FreeblockInitCall::WorldTime) == 0);
        assert(count_code(res.calls,
                          FreeblockInitCall::DynamicWorldChangedAtPos) == 0);
    }

    // 3. subItems is an array of arrays; itemType==11 children are skipped.
    {
        FreeblockInitInputs in = base_inputs();
        in.sub_items = {7, 7, 11, 9};        // flattened
        in.elem_counts = {1, 2, 0, 1};
        in.elem_count = 4;
        auto res = freeblock_init_with_world(in);
        assert(res.return_value == in.self_ptr);
        assert(count_code(res.calls, FreeblockInitCall::MutableArrayArray) == 5);
        // 4 temp arrays (per element) + 1 fresh (pre-loop)
        assert(count_code(res.calls, FreeblockInitCall::CountByEnumerating) == 9);
        // outer: 1 batch + 1 exhausted; inner: elem0 1+1, elem1 1+1,
        // elem2 1 (empty), elem3 1+1 => 2 + 7 = 9
        assert(count_code(res.calls, FreeblockInitCall::InventoryAlloc) == 4);
        assert(count_code(res.calls,
                          FreeblockInitCall::InventoryItemType) == 4);
        // only 3 addObject: item adds (one type-11 child is skipped) + 4
        // temp adds + ... count exactly:
        int item_adds = 0, temp_adds = 0;
        for (const auto& c : res.calls) {
            if (c.first == FreeblockInitCall::SubItemsAddObject) {
                if (c.second == 0x5E1A0B21u) temp_adds++;
                else item_adds++;
            }
        }
        assert(temp_adds == 4);   // one per element (incl. the empty one)
        assert(item_adds == 3);    // types 7, 7, 9 added; 11 skipped
    }

    // 4. priorityBlockheadUinqueID resolution (receiver = dynamicWorld).
    {
        FreeblockInitInputs in = base_inputs();
        in.priority_id_value = 42;
        in.blockhead_answer = 0x5E1A00B0u;
        auto res = freeblock_init_with_world(in);
        assert(count_code(res.calls, FreeblockInitCall::BlockheadWithID) == 1);
        assert(count_code(res.calls, FreeblockInitCall::RetainBlockhead) == 1);
        assert(word_at(res.image, kFreeblockOffsetPriorityBlockhead)
               == in.blockhead_answer);
    }

    // 5. hovers gate: fresh creationTime -> no tail effects.
    {
        FreeblockInitInputs in = base_inputs();
        in.hovers_value = 1;
        in.world_time = 100.0;        // age = 90 <= 900 -> early return
        auto res = freeblock_init_with_world(in);
        assert(count_code(res.calls, FreeblockInitCall::WorldTime) == 1);
        assert(res.image[kFreeblockOffsetHovers] == 1);   // not cleared
        assert(res.image[kFreeblockOffsetUpdateNeeds] == 0);
    }

    // 6. hovers + old creationTime + blacklisted type -> end before re-anchor.
    {
        FreeblockInitInputs in = base_inputs();
        in.hovers_value = 1;
        in.world_time = 10000.0;
        in.item_type_value = 0x91;      // in the 0x627C40 probed set
        auto res = freeblock_init_with_world(in);
        assert(count_code(res.calls, FreeblockInitCall::WorldTime) == 1);
        assert(res.image[kFreeblockOffsetHovers] == 1);
        assert(count_code(res.calls,
                          FreeblockInitCall::DynamicWorldChangedAtPos) == 0);
    }

    // 7. hovers + old + clean type: re-anchor creationTime, hovers=0, notify.
    {
        FreeblockInitInputs in = base_inputs();
        in.hovers_value = 1;
        in.world_time = 10000.0;
        in.item_type_value = 7;
        auto res = freeblock_init_with_world(in);
        assert(count_code(res.calls, FreeblockInitCall::WorldTime) == 3);
        assert(res.image[kFreeblockOffsetHovers] == 0);
        // elapsed = 10000 - 10 - 900 = 9090 >= 900 -> no ground loop
        assert(count_code(res.calls, FreeblockInitCall::WorldTileQuery) == 0);
        assert(res.image[kFreeblockOffsetUpdateNeeds] == 1);
        assert(count_code(res.calls,
                          FreeblockInitCall::DynamicWorldChangedAtPos) == 1);
        // creationTime = 10000 - 9090 = 910.0 (the re-anchor, executed fact)
        double newc = double_at(res.image, kFreeblockOffsetCreationTime);
        assert(newc == 910.0);
        // floatPos untouched by the re-anchor (executed fact)
        assert(float_at(res.image, kFreeblockOffsetFloatPos) == 3.5f);
    }

    // 8. Ground-fall: solid at step 0 (falls one tile), air at step 1 (stops).
    {
        FreeblockInitInputs in = base_inputs();
        in.hovers_value = 1;
        in.world_time = 10000.0;
        in.item_type_value = 7;
        in.creation_time_value = 9090.0;   // age = 910 > 900; elapsed small
        // elapsed = 10000 - 9090 - 900 = 10 < 900 -> ground loop runs
        in.tiles = {{true, 2}, {false, 0}};   // solid at step 0, air at step 1
        auto res = freeblock_init_with_world(in);
        assert(count_code(res.calls, FreeblockInitCall::WorldTileQuery) == 2);
        assert(count_code(res.calls, FreeblockInitCall::UpdatePosition) == 1);
        assert(res.tiles_consumed == 2);
        // pos moved down by one (updatePosition set pos.y-1)
        std::int32_t py = 0;
        std::memcpy(&py, res.image.data() + 16 + 4, 4);
        assert(py == in.pos_y - 1);
        // floatPos.y -= 1.0f happened
        assert(float_at(res.image, kFreeblockOffsetFloatPos + 4) == -2.25f);
    }

    // 9. Probed helper sets: containment spot checks (frozen facts).
    {
        assert(freeblock_blacklist_627c40_contains(0x91));
        assert(freeblock_blacklist_627c40_contains(0xcc));
        assert(!freeblock_blacklist_627c40_contains(7));
        assert(freeblock_liquid_5b2ad4_contains(0x3f));
        assert(!freeblock_liquid_5b2ad4_contains(7));
        assert(!freeblock_liquid_5b2ad4_contains(0x91));  // not in liquid set
    }

    std::cout << "test_freeblock_init: all assertions passed\n";
    return 0;
}
