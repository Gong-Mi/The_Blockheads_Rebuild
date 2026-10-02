// Recovered implementation of the FreeBlock exact-variant loader (batch b4p).
// See freeblock_init.h for the decoded contract and evidence pins.
#include "freeblock_init.h"

#include <cstring>

namespace blockheads::recovered {
namespace {

inline std::uint32_t low32(double value) {
    std::uint64_t bits = 0;
    std::memcpy(&bits, &value, 8);
    return static_cast<std::uint32_t>(bits & 0xffffffffu);
}

inline std::uint32_t float_bits(float value) {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, 4);
    return bits;
}

inline double pair_as_double(float x, float y) {
    // ARM reads the two adjacent float slots as one double (vldr dN).
    std::uint32_t lo = float_bits(x);
    std::uint32_t hi = float_bits(y);
    std::uint64_t bits = (static_cast<std::uint64_t>(hi) << 32) | lo;
    double out = 0.0;
    std::memcpy(&out, &bits, 8);
    return out;
}

inline void store_pair_as_double(std::uint8_t* at, double value) {
    std::uint64_t bits = 0;
    std::memcpy(&bits, &value, 8);
    std::uint32_t lo = static_cast<std::uint32_t>(bits & 0xffffffffu);
    std::uint32_t hi = static_cast<std::uint32_t>(bits >> 32);
    std::memcpy(at, &lo, 4);
    std::memcpy(at + 4, &hi, 4);
}

inline void store_float(std::uint8_t* image, std::uint32_t off, float v) {
    std::memcpy(image + off, &v, 4);
}

inline float load_float(const std::uint8_t* image, std::uint32_t off) {
    float v = 0.0f;
    std::memcpy(&v, image + off, 4);
    return v;
}

struct Trace {
    std::vector<std::pair<FreeblockInitCall, std::uint32_t>> calls;
    void add(FreeblockInitCall code, std::uint32_t arg = 0) {
        calls.emplace_back(code, arg);
    }
};

}  // namespace

bool freeblock_blacklist_627c40_contains(std::uint32_t item_type) {
    for (std::uint32_t v : kFreeblockBlacklist627C40)
        if (v == item_type) return true;
    return false;
}

bool freeblock_liquid_5b2ad4_contains(std::uint32_t item_type) {
    for (std::uint32_t v : kFreeblockLiquid5B2AD4)
        if (v == item_type) return true;
    return false;
}

FreeblockInitResult freeblock_init_with_world(const FreeblockInitInputs& in) {
    FreeblockInitResult out;
    out.image.assign(kFreeblockImageSize, 0);
    std::uint8_t* self = out.image.data();
    Trace trace;

    // Pre-existing ivar state (super side effects are fixture inputs).
    std::memcpy(self + kFreeblockOffsetWorld, &in.world_ivar, 4);
    std::memcpy(self + kFreeblockOffsetDynamicWorld, &in.dynamic_world_ivar, 4);
    std::memcpy(self + kFreeblockOffsetPos, &in.pos_x, 4);
    std::memcpy(self + kFreeblockOffsetPos + 4, &in.pos_y, 4);
    std::memcpy(self + kFreeblockOffsetUniqueID, &in.unique_id, 4);
    std::memcpy(self + kFreeblockOffsetItemType, &in.item_type_init, 4);
    self[kFreeblockOffsetHovers] = static_cast<std::uint8_t>(in.hovers_init);

    // super2 forward: all four arguments.
    trace.add(FreeblockInitCall::MsgSendSuper, in.self_ptr);
    if (in.super_returns_nil) {
        out.return_value = 0;
        out.calls = trace.calls;
        return out;
    }

    auto store_word = [&](std::uint32_t off, std::uint32_t v) {
        std::memcpy(self + off, &v, 4);
    };
    auto store_half = [&](std::uint32_t off, std::uint16_t v) {
        std::memcpy(self + off, &v, 2);
    };

    // Key walk in the original's executed order.
    trace.add(FreeblockInitCall::ObjectForKeyBounceTimer, 0x5E1A0B05u);
    trace.add(FreeblockInitCall::FloatValueBounceTimer,
              float_bits(in.bounce_timer_value));
    store_float(self, kFreeblockOffsetBounceTimer, in.bounce_timer_value);

    trace.add(FreeblockInitCall::ObjectForKeyFallSpeed, 0x5E1A0B06u);
    trace.add(FreeblockInitCall::FloatValueFallSpeed,
              float_bits(in.fall_speed_value));
    store_float(self, kFreeblockOffsetFallSpeed, in.fall_speed_value);

    trace.add(FreeblockInitCall::ObjectForKeyCreationTime, 0x5E1A0B07u);
    trace.add(FreeblockInitCall::DoubleValueCreationTime,
              low32(in.creation_time_value));
    std::memcpy(self + kFreeblockOffsetCreationTime, &in.creation_time_value, 8);

    trace.add(FreeblockInitCall::ObjectForKeyFloatPosVX, 0x5E1A0B08u);
    trace.add(FreeblockInitCall::FloatValueFloatPosVX,
              float_bits(in.float_vx_value));
    store_float(self, kFreeblockOffsetFloatPos, in.float_vx_value);

    trace.add(FreeblockInitCall::ObjectForKeyFloatPosVY, 0x5E1A0B09u);
    trace.add(FreeblockInitCall::FloatValueFloatPosVY,
              float_bits(in.float_vy_value));
    store_float(self, kFreeblockOffsetFloatPos + 4, in.float_vy_value);

    trace.add(FreeblockInitCall::ObjectForKeyHovers, 0x5E1A0B01u);
    trace.add(FreeblockInitCall::BoolValueHovers,
              in.hovers_value ? 1u : 0u);
    self[kFreeblockOffsetHovers] =
        static_cast<std::uint8_t>(in.hovers_value ? 1 : 0);

    trace.add(FreeblockInitCall::ObjectForKeyItemType, 0x5E1A0B02u);
    trace.add(FreeblockInitCall::IntValueItemType, in.item_type_value);
    store_word(kFreeblockOffsetItemType, in.item_type_value);

    trace.add(FreeblockInitCall::ObjectForKeyDataA, 0x5E1A0B03u);
    trace.add(FreeblockInitCall::IntValueDataA, in.data_a_value);
    store_half(kFreeblockOffsetDataA,
               static_cast<std::uint16_t>(in.data_a_value & 0xffff));

    trace.add(FreeblockInitCall::ObjectForKeyDataB, 0x5E1A0B04u);
    trace.add(FreeblockInitCall::IntValueDataB, in.data_b_value);
    store_half(kFreeblockOffsetDataB,
               static_cast<std::uint16_t>(in.data_b_value & 0xffff));

    // The original creates a FRESH NSMutableArray first
    // (classref slot unresolved on disk -> receiver 0 in the harness), stores
    // it into self->subItems, and only THEN reads the save-dict array to
    // enumerate. Executed fact (b4p run).
    trace.add(FreeblockInitCall::MutableArrayArray, 0);
    trace.add(FreeblockInitCall::MutableArrayInit, 0x5E1A0B21u);
    store_word(kFreeblockOffsetSubItems, 0x5E1A0B80u);

    trace.add(FreeblockInitCall::ObjectForKeySubItems, 0x5E1A0B20u);

    // The save-dict subItems value is an ARRAY OF ARRAYS (executed fact): the
    // outer NSFastEnumeration walks per-element slot arrays; for each element
    // the original appends a fresh temp array to self->subItems and then
    // enumerates the element's sub-item payloads into InventoryItem children
    // (itemType == 11 children are skipped). Each enumeration level issues
    // one final 0-return call after the last non-empty batch (the recheck).
    const std::size_t elem_total = in.elem_count;
    std::size_t flat_i = 0;
    std::size_t elem_i = 0;
    while (true) {
        const std::size_t outer_batch =
            std::min<std::size_t>(16, elem_total - elem_i);
        trace.add(FreeblockInitCall::CountByEnumerating,
                  static_cast<std::uint32_t>(outer_batch));
        for (std::size_t e = 0; e < outer_batch; ++e) {
            trace.add(FreeblockInitCall::MutableArrayArray, 0);
            trace.add(FreeblockInitCall::SubItemsAddObject, 0x5E1A0B21u);
            const std::uint32_t sub_count = in.elem_counts[elem_i + e];
            std::size_t sub_i = 0;
            if (sub_count == 0) {
                trace.add(FreeblockInitCall::CountByEnumerating, 0);
            } else {
                while (sub_i < sub_count) {
                    const std::size_t inner_batch =
                        std::min<std::size_t>(16, sub_count - sub_i);
                    trace.add(FreeblockInitCall::CountByEnumerating,
                              static_cast<std::uint32_t>(inner_batch));
                    const std::uint32_t payload_issued =
                        static_cast<std::uint32_t>(flat_i + inner_batch);
                    const std::uint32_t item_token =
                        0x5E1A0B90u + payload_issued * 8;
                    for (std::size_t s = 0; s < inner_batch; ++s) {
                        const std::uint32_t sub_type = in.sub_items[flat_i];
                        const std::uint32_t sub_token =
                            0x60002420u + static_cast<std::uint32_t>(flat_i) * 8;
                        trace.add(FreeblockInitCall::InventoryAlloc, 0);
                        trace.add(FreeblockInitCall::InventoryInitWithSaveData,
                                  sub_token);
                        trace.add(FreeblockInitCall::InventoryAutorelease, 0);
                        trace.add(FreeblockInitCall::InventoryItemType, sub_type);
                        if (sub_type != kFreeblockSkippedItemType) {
                            trace.add(FreeblockInitCall::SubItemsAddObject,
                                      item_token);
                        }
                        flat_i += 1;
                    }
                    sub_i += inner_batch;
                }
                // the ARM re-asks once after the last non-empty batch
                trace.add(FreeblockInitCall::CountByEnumerating, 0);
            }
        }
        elem_i += outer_batch;
        if (elem_i >= elem_total) {
            // the outer enumeration re-asks once after the last NON-EMPTY
            // batch; an empty source array gets exactly one call.
            if (outer_batch > 0) {
                trace.add(FreeblockInitCall::CountByEnumerating, 0);
            }
            break;
        }
    }

    trace.add(FreeblockInitCall::ObjectForKeyDynSaveDict, 0x5E1A0B0Bu);
    trace.add(FreeblockInitCall::DynSaveDictCopy, 0);
    store_word(kFreeblockOffsetDynSaveDict, 0x5E1A0B0Bu);

    trace.add(FreeblockInitCall::ObjectForKeyPriorityId, 0x5E1A0B0Au);
    const std::uint32_t pid_low =
        static_cast<std::uint32_t>(in.priority_id_value);
    trace.add(FreeblockInitCall::IntValuePriorityId, pid_low);
    if (in.priority_id_value != 0) {
        trace.add(FreeblockInitCall::BlockheadWithID, pid_low);
        trace.add(FreeblockInitCall::RetainBlockhead, 0);
        store_word(kFreeblockOffsetPriorityBlockhead, in.blockhead_answer);
    }

    trace.add(FreeblockInitCall::InitSubDerivedObjects, 0);

    if (self[kFreeblockOffsetHovers] != 0) {
        // Gate 1: (worldTime - creationTime) > 900.0 (ARM `ble` skip).
        trace.add(FreeblockInitCall::WorldTime, low32(in.world_time));
        const double age = in.world_time - in.creation_time_value;
        if (!(age > kFreeblockHoversAgeLimitD)) {   // ARM `ble` taken -> end
            out.return_value = in.self_ptr;
            out.calls = trace.calls;
            return out;
        }

        // Inline itemType gates, then the 0x627C40 blacklist, then the
        // 0x5B2AD4 liquid predicate (any hit -> end).
        bool skip = false;
        for (std::uint32_t v : kFreeblockInlineSkip)
            if (v == in.item_type_value) skip = true;
        for (std::uint32_t v : kFreeblockInlineSkip2)
            if (v == in.item_type_value) skip = true;
        if (freeblock_blacklist_627c40_contains(in.item_type_value))
            skip = true;
        if (freeblock_liquid_5b2ad4_contains(in.item_type_value))
            skip = true;
        if (skip) {
            out.return_value = in.self_ptr;
            out.calls = trace.calls;
            return out;
        }

        // Executed fact (b4p): the re-anchor targets CREATION TIME, not
        // floatPos. elapsed = (float)(wt1 - creationTime - 900.0); hovers=0;
        // creationTime = wt2 - (double)elapsed. floatPos is untouched here
        // (only the ground-fall loop's y -= 1.0f touches it).
        trace.add(FreeblockInitCall::WorldTime, low32(in.world_time));
        double creation = 0.0;
        std::memcpy(&creation, self + kFreeblockOffsetCreationTime, 8);
        const float elapsed = static_cast<float>(
            in.world_time - creation - kFreeblockHoversAgeLimitD);
        self[kFreeblockOffsetHovers] = 0;
        trace.add(FreeblockInitCall::WorldTime, low32(in.world_time));
        const double new_creation =
            in.world_time - static_cast<double>(elapsed);
        std::memcpy(self + kFreeblockOffsetCreationTime, &new_creation, 8);

        // Gate 2: elapsed < 900.0f -> ground fall (ARM `bpl` skips).
        if (elapsed < kFreeblockHoversAgeLimit) {
            std::int32_t px = 0, py = 0;
            std::memcpy(&px, self + kFreeblockOffsetPos, 4);
            std::memcpy(&py, self + kFreeblockOffsetPos + 4, 4);
            for (std::uint32_t step = 0;
                 step < kFreeblockGroundFallMaxSteps; ++step) {
                const std::int32_t query_y = py - 1;
                trace.add(FreeblockInitCall::WorldTileQuery,
                          static_cast<std::uint32_t>(query_y));
                out.tiles_consumed += 1;
                bool solid = false;
                if (step < in.tiles.size() && in.tiles[step].present
                    && in.tiles[step].byte0 == kFreeblockGroundSolidKind) {
                    solid = true;
                }
                if (!solid) break;
                // floatPos.y -= 1.0f, then updatePosition:{px, query_y}.
                float vy = load_float(self, kFreeblockOffsetFloatPos + 4);
                store_float(self, kFreeblockOffsetFloatPos + 4, vy - 1.0f);
                trace.add(FreeblockInitCall::UpdatePosition,
                          ((static_cast<std::uint32_t>(query_y) & 0xffffu)
                           << 16) | (static_cast<std::uint32_t>(px) & 0xffffu));
                py = query_y;
                std::memcpy(self + kFreeblockOffsetPos + 4, &py, 4);
            }
        }

        self[kFreeblockOffsetUpdateNeeds] = 1;
        trace.add(FreeblockInitCall::ObjectType, in.object_type_value);
        std::int32_t nx = 0, ny = 0;
        std::memcpy(&nx, self + kFreeblockOffsetPos, 4);
        std::memcpy(&ny, self + kFreeblockOffsetPos + 4, 4);
        trace.add(FreeblockInitCall::DynamicWorldChangedAtPos,
                  ((static_cast<std::uint32_t>(ny) & 0xffffu) << 16)
                  | (static_cast<std::uint32_t>(nx) & 0xffffu));
    }

    out.return_value = in.self_ptr;
    out.calls = trace.calls;
    return out;
}

}  // namespace blockheads::recovered
