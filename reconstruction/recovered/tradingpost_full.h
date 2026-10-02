// TradingPost loader (type 48): own keys static (UPPERMID15) + the executed
// sellSlot restoration hook.
//
// Original chain:
//   DynamicObject base (executed)
//   InteractionObject (352w)  [STATIC only — stated boundary]
//   TradingPost initWithWorld:dynamicWorld:saveDict:cache: (0x005E4xxx,
//     223w, static level-A UPPERMID15): own keys {coinCount, priceTier,
//     sellerClientID, sellerClientName} (the save side stores
//     sellerClientName DIRECT, priceTier/coinCount as numberWithInt:).
//   TradingPost initSlotsWithSaveDict: (0x005E4914, 243w)  [EXECUTED]:
//     sellSlot@100 = NSMutableArray; per item of [saveDict
//     objectForKey:@"sellSlot"] -> [[InventoryItem alloc]
//     initWithSaveData:], the itemType != 11 filter, addObject.
//     Offline: counts only (item payload decode is InventoryItem's domain),
//     the filter is therefore reported as not applied.
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include <cstdint>
#include <string>

namespace bh176 {

struct TradingPostFullState {
    // base loader
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    float float_pos_x = 0.0f;
    float float_pos_y = 0.0f;
    bool has_float_pos = false;
    // own keys (static UPPERMID15)
    bool has_coin_count = false;
    std::int32_t coin_count = 0;      // @104
    bool has_price_tier = false;
    std::int32_t price_tier = 0;      // @108
    bool has_seller_client_id = false;    // object slot
    bool has_seller_client_name = false;  // object slot (save side DIRECT)
    // sellSlot hook (executed): raw item count, no decode, filter not applied
    bool has_sell_slot = false;
    std::size_t sell_slot_item_count = 0;
    bool item_decode_performed = false;   // always false offline (stated)
    // InteractionObject static boundary
    bool interaction_static_keys_present = false;
};

TradingPostFullState tradingpost_full_load(const SaveDict& entry);

ClientDynamicObject tradingpost_full_factory(int type_id,
                                             const SaveDict& entry,
                                             TradingPostFullState* out_state,
                                             std::string* error);

}  // namespace bh176
