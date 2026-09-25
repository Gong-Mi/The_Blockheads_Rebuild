// Recovered implementation of the Workbench loader (batch b4q).
// See workbench_init.h for the decoded contract and evidence pins.
#include "workbench_init.h"

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

struct Trace {
    std::vector<std::pair<WorkbenchInitCall, std::uint32_t>> calls;
    void add(WorkbenchInitCall code, std::uint32_t arg = 0) {
        calls.emplace_back(code, arg);
    }
};

}  // namespace

WorkbenchInitResult workbench_init_with_world(const WorkbenchInitInputs& in) {
    WorkbenchInitResult out;
    out.image.assign(kWorkbenchImageSize, 0);
    std::uint8_t* self = out.image.data();
    Trace trace;

    auto store_word = [&](std::uint32_t off, std::uint32_t v) {
        std::memcpy(self + off, &v, 4);
    };
    auto store_half = [&](std::uint32_t off, std::uint16_t v) {
        std::memcpy(self + off, &v, 2);
    };
    auto store_byte = [&](std::uint32_t off, std::uint8_t v) {
        self[off] = v;
    };
    auto store_float = [&](std::uint32_t off, float v) {
        std::memcpy(self + off, &v, 4);
    };
    auto store_double = [&](std::uint32_t off, double v) {
        std::memcpy(self + off, &v, 8);
    };

    // Pre-existing ivar state (super side effects are fixture inputs).
    store_word(kWorkbenchOffsetWorld, in.world_ivar);
    store_word(kWorkbenchOffsetDynamicWorld, in.dynamic_world_ivar);
    store_word(kWorkbenchOffsetCache, in.cache_ivar);
    store_word(kWorkbenchOffsetPos, static_cast<std::uint32_t>(in.pos_x));
    store_word(kWorkbenchOffsetPos + 4, static_cast<std::uint32_t>(in.pos_y));
    store_word(kWorkbenchOffsetCurrentBlockhead, in.current_blockhead);
    store_word(kWorkbenchOffsetCurrentFuel, in.current_fuel_blockhead);
    store_byte(kWorkbenchOffsetIsInUse,
               static_cast<std::uint8_t>(in.is_in_use_init));

    // super2 forward: all four arguments.
    trace.add(WorkbenchInitCall::MsgSendSuper, in.self_ptr);
    if (in.super_returns_nil) {
        out.return_value = 0;
        out.calls = trace.calls;
        return out;
    }

    // The 16-key scalar walk in the original's executed order.
    trace.add(WorkbenchInitCall::ObjectForKeyWorkbenchType,
              kWorkbenchBoxWorkbenchType);
    trace.add(WorkbenchInitCall::IntValueWorkbenchType, in.workbench_type_value);
    store_word(kWorkbenchOffsetType, in.workbench_type_value);

    trace.add(WorkbenchInitCall::ObjectForKeySelectedIndex,
              kWorkbenchBoxSelectedIndex);
    trace.add(WorkbenchInitCall::IntValueSelectedIndex, in.selected_index_value);
    store_word(kWorkbenchOffsetSelectedIndex, in.selected_index_value);

    trace.add(WorkbenchInitCall::ObjectForKeyXScroll, kWorkbenchBoxXScroll);
    trace.add(WorkbenchInitCall::FloatValueXScroll, float_bits(in.x_scroll_value));
    store_float(kWorkbenchOffsetXScroll, in.x_scroll_value);

    trace.add(WorkbenchInitCall::ObjectForKeyLevel, kWorkbenchBoxLevel);
    trace.add(WorkbenchInitCall::IntValueLevel, in.level_value);
    store_word(kWorkbenchOffsetLevel, in.level_value);

    trace.add(WorkbenchInitCall::ObjectForKeyCraftProgressCount,
              kWorkbenchBoxCraftProgress);
    trace.add(WorkbenchInitCall::FloatValueCraftProgressCount,
              float_bits(in.craft_progress_value));
    store_float(kWorkbenchOffsetCraftProgress, in.craft_progress_value);

    trace.add(WorkbenchInitCall::ObjectForKeyHurryTimer, kWorkbenchBoxHurryTimer);
    trace.add(WorkbenchInitCall::FloatValueHurryTimer,
              float_bits(in.hurry_timer_value));
    store_float(kWorkbenchOffsetHurryTimer, in.hurry_timer_value);

    trace.add(WorkbenchInitCall::ObjectForKeyHurrySeconds,
              kWorkbenchBoxHurrySeconds);
    trace.add(WorkbenchInitCall::FloatValueHurrySeconds,
              float_bits(in.hurry_seconds_value));
    store_float(kWorkbenchOffsetHurrySeconds, in.hurry_seconds_value);

    trace.add(WorkbenchInitCall::ObjectForKeyHurrying, kWorkbenchBoxHurrying);
    trace.add(WorkbenchInitCall::IntValueHurrying, in.hurrying_value);
    store_byte(kWorkbenchOffsetHurrying,
               static_cast<std::uint8_t>(in.hurrying_value ? 1 : 0));

    trace.add(WorkbenchInitCall::ObjectForKeyHurryCost, kWorkbenchBoxHurryCost);
    trace.add(WorkbenchInitCall::IntValueHurryCost, in.hurry_cost_value);
    store_word(kWorkbenchOffsetHurryCost, in.hurry_cost_value);

    trace.add(WorkbenchInitCall::ObjectForKeyFireSpreadTimer,
              kWorkbenchBoxFireSpread);
    trace.add(WorkbenchInitCall::FloatValueFireSpreadTimer,
              float_bits(in.fire_spread_value));
    store_float(kWorkbenchOffsetFireSpread, in.fire_spread_value);

    trace.add(WorkbenchInitCall::ObjectForKeyFuelFraction,
              kWorkbenchBoxFuelFraction);
    trace.add(WorkbenchInitCall::FloatValueFuelFraction,
              float_bits(in.fuel_fraction_value));
    store_float(kWorkbenchOffsetFuelFraction, in.fuel_fraction_value);

    trace.add(WorkbenchInitCall::ObjectForKeyHasFuel, kWorkbenchBoxHasFuel);
    trace.add(WorkbenchInitCall::IntValueHasFuel, in.has_fuel_value);
    store_byte(kWorkbenchOffsetHasFuel,
               static_cast<std::uint8_t>(in.has_fuel_value ? 1 : 0));

    trace.add(WorkbenchInitCall::ObjectForKeyLastWorldTime,
              kWorkbenchBoxLastWorldTime);
    trace.add(WorkbenchInitCall::DoubleValueLastWorldTime,
              low32(in.last_world_time_value));
    store_double(kWorkbenchOffsetLastWorldTime, in.last_world_time_value);

    trace.add(WorkbenchInitCall::ObjectForKeyIsInUseFuel,
              kWorkbenchBoxIsInUseFuel);
    trace.add(WorkbenchInitCall::BoolValueIsInUseFuel,
              in.is_in_use_fuel_value ? 1u : 0u);
    store_byte(kWorkbenchOffsetIsInUseFuel,
               static_cast<std::uint8_t>(in.is_in_use_fuel_value ? 1 : 0));

    trace.add(WorkbenchInitCall::ObjectForKeyAvailableElectricity,
              kWorkbenchBoxAvailableElec);
    trace.add(WorkbenchInitCall::IntValueAvailableElectricity,
              in.available_elec_value);
    store_half(kWorkbenchOffsetAvailableElec,
               static_cast<std::uint16_t>(in.available_elec_value & 0xffff));

    // currentBlockheadIndexFuel: objectForKey TWICE, then intValue (executed
    // fact — the double read happens regardless of the value).
    trace.add(WorkbenchInitCall::ObjectForKeyBlockheadIndexFuel,
              kWorkbenchBoxBhIndexFuel);
    trace.add(WorkbenchInitCall::ObjectForKeyBlockheadIndexFuel,
              kWorkbenchBoxBhIndexFuel);
    trace.add(WorkbenchInitCall::IntValueBlockheadIndexFuel,
              static_cast<std::uint32_t>(in.blockhead_index_fuel_value));
    store_word(kWorkbenchOffsetSavedBhFuel,
               static_cast<std::uint32_t>(in.blockhead_index_fuel_value));

    if (self[kWorkbenchOffsetIsInUse] != 0) {
        // craftingItemDatav2 -> craftableObjectType -> the 3-way classref.
        trace.add(WorkbenchInitCall::ObjectForKeyCraftingItemDatav2,
                  in.crafting_v2_present ? kWorkbenchClusterV2 : 0);
        if (in.crafting_v2_present) {
            trace.add(WorkbenchInitCall::ObjectForKeyCraftableObjectType,
                      kWorkbenchBoxCraftableObjectType);
            trace.add(WorkbenchInitCall::IntValueCraftableObjectType,
                      in.craftable_object_type);
            trace.add(WorkbenchInitCall::CraftableAlloc,
                      in.craftable_object_type == 1 ? 1u
                      : (in.craftable_object_type == 2 ? 2u : 0u));
            trace.add(WorkbenchInitCall::CraftableInitWithSaveDict,
                      kWorkbenchClusterV2);
            if (in.crafting_item_nonnil) {
                store_word(kWorkbenchOffsetCraftingItem,
                           kWorkbenchCraftableResult);
            }
        } else {
            trace.add(WorkbenchInitCall::ObjectForKeyCraftingItemData,
                      in.crafting_v1_present ? kWorkbenchClusterV1 : 0);
            if (in.crafting_v1_present) {
                // the v1 -> v2 MIGRATION: bytes + TWO 124-byte memcpys,
                // then initWithCraftableItem: with the blob head.
                trace.add(WorkbenchInitCall::BytesCopy, 0);
                trace.add(WorkbenchInitCall::BytesCopy,
                          kWorkbenchCraftableBlobSize);
                trace.add(WorkbenchInitCall::CraftableAlloc, 0);
                trace.add(WorkbenchInitCall::BytesCopy,
                          kWorkbenchCraftableBlobSize);
                trace.add(WorkbenchInitCall::CraftableInitWithCraftableItem,
                          0x03020100u);   // blob[0..3] fixture bytes
                if (in.crafting_item_nonnil) {
                    store_word(kWorkbenchOffsetCraftingItem,
                               kWorkbenchCraftableResult);
                }
            }
        }

        if (in.crafting_item_nonnil) {
            // [craftingItemObject craftableItem] stret (124-byte struct),
            // then the count triple, then the sourceItems_%d per-slot loop.
            trace.add(WorkbenchInitCall::CraftableItemStret,
                      in.craftable_item_stret_type);
            trace.add(WorkbenchInitCall::ObjectForKeyCount,
                      kWorkbenchBoxCount);
            trace.add(WorkbenchInitCall::IntValueCount, in.count_value);
            store_word(kWorkbenchOffsetCount, in.count_value);
            trace.add(WorkbenchInitCall::ObjectForKeyCountLeft,
                      kWorkbenchBoxCountLeft);
            trace.add(WorkbenchInitCall::IntValueCountLeft, in.count_left_value);
            store_word(kWorkbenchOffsetCountLeft, in.count_left_value);
            trace.add(WorkbenchInitCall::ObjectForKeyCountCreated,
                      kWorkbenchBoxCountCreated);
            trace.add(WorkbenchInitCall::IntValueCountCreated,
                      in.count_created_value);
            store_word(kWorkbenchOffsetCountCreated, in.count_created_value);

            // The sourceItems_%d per-slot loop, gated by the stret slot count.
            const std::size_t slot_total = in.slot_elem_counts.size();
            for (std::size_t i = 0; i < slot_total; ++i) {
                trace.add(WorkbenchInitCall::ReleaseSlot, 0);
                trace.add(WorkbenchInitCall::StringWithFormatSourceItems,
                          static_cast<std::uint32_t>(i));
                trace.add(WorkbenchInitCall::ObjectForKeySourceItemsAt,
                          static_cast<std::uint32_t>(i));
                const std::uint32_t slot_type =
                    i < in.slot_types.size() ? in.slot_types[i] : 0;
                if (slot_type == kWorkbenchSkippedSlotType) {
                    continue;   // the 0xb slot gate (listing 0xAE5D4C)
                }
                const std::uint32_t sub_count = in.slot_elem_counts[i];
                trace.add(WorkbenchInitCall::ObjectForKeySourceItemsAt,
                          sub_count);
                if (sub_count == 0) {
                    continue;   // the count gate (listing 0xAE5E04 bls)
                }
                trace.add(WorkbenchInitCall::MutableArrayAllocSlot, 0);
                trace.add(WorkbenchInitCall::MutableArrayInitSlot,
                          kWorkbenchFreshSlot);
                // the original stores the fresh array into sourceItems[i]
                // right after init (listing 0xAE5EB0)
                store_word(kWorkbenchOffsetSourceItems
                               + static_cast<std::uint32_t>(i) * 4,
                           kWorkbenchFreshSlot);
                // inner NSFastEnumeration over the slot's payloads
                std::size_t base = 0;
                for (std::size_t s = 0; s < i; ++s)
                    base += in.slot_elem_counts[s];
                std::size_t served = 0;
                while (true) {
                    const std::size_t batch =
                        std::min<std::size_t>(16, sub_count - served);
                    trace.add(WorkbenchInitCall::CountByEnumeratingSource,
                              static_cast<std::uint32_t>(batch));
                    for (std::size_t b = 0; b < batch; ++b) {
                        trace.add(WorkbenchInitCall::InventoryAlloc, 0);
                        trace.add(WorkbenchInitCall::InventoryInitWithSaveData,
                                  in.sub_page_base
                                      + static_cast<std::uint32_t>(
                                          base + served + b) * 8);
                        trace.add(WorkbenchInitCall::InventoryAutorelease, 0);
                        trace.add(WorkbenchInitCall::SlotAddObject,
                                  0x5E1A0D18u);   // fixture item token
                    }
                    served += batch;
                    if (served >= sub_count) {
                        trace.add(WorkbenchInitCall::CountByEnumeratingSource, 0);
                        break;
                    }
                }
            }
        }
        // The craft wiring is gated by isInUse ALONE (executed fact: it
        // fires even when craftingItemObject is nil — msgSend on nil is a
        // no-op in the original; receiver = self->currentBlockhead).
        trace.add(WorkbenchInitCall::SetInteractionWorkbenchCraft, in.self_ptr);
    }

    // isInUseFuel -> the fuel blockhead wiring.
    if (self[kWorkbenchOffsetIsInUseFuel] != 0) {
        trace.add(WorkbenchInitCall::SetInteractionWorkbenchFuel, in.self_ptr);
    }

    // lightDict -> ArtificialLight 5-arg init + the tile-light update.
    trace.add(WorkbenchInitCall::ObjectForKeyLightDict,
              in.light_dict_present ? kWorkbenchLightDict : 0);
    if (in.light_dict_present) {
        trace.add(WorkbenchInitCall::ArtificialLightAlloc, 0);
        trace.add(WorkbenchInitCall::ObjectForKeyLightDict, kWorkbenchLightDict);
        trace.add(WorkbenchInitCall::LightInitWithWorld, 0);
        store_word(kWorkbenchOffsetLight, in.light_answer);
        trace.add(WorkbenchInitCall::MacroTiles, 0);
        trace.add(WorkbenchInitCall::MacroTiles, 1);   // worldWidthMacro #1
        trace.add(WorkbenchInitCall::MacroTiles, 1);   // worldWidthMacro #2
    }

    trace.add(WorkbenchInitCall::InitSubDerivedItems, 0);

    out.return_value = in.self_ptr;
    out.calls = trace.calls;
    return out;
}

}  // namespace blockheads::recovered
