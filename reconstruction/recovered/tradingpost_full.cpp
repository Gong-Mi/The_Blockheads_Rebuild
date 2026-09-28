// TradingPost loader implementation. See tradingpost_full.h.
#include "tradingpost_full.h"

namespace bh176 {

TradingPostFullState tradingpost_full_load(const SaveDict& entry) {
    TradingPostFullState state;

    // --- DynamicObject base loader (executed contract) ---
    state.unique_id =
        static_cast<std::uint64_t>(SaveDict::unsignedLongValue(
            entry.objectForKey("uniqueID")));
    state.pos_x = static_cast<std::int32_t>(
        SaveDict::intValue(entry.objectForKey("pos_x")));
    state.pos_y = static_cast<std::int32_t>(
        SaveDict::intValue(entry.objectForKey("pos_y")));
    const SaveValue* float_pos = entry.objectForKey("floatPos");
    if (SaveDict::count(float_pos) >= 2) {
        state.float_pos_x =
            SaveDict::floatValue(entry.objectAtIndex(float_pos, 0));
        state.float_pos_y =
            SaveDict::floatValue(entry.objectAtIndex(float_pos, 1));
        state.has_float_pos = true;
    }

    // --- own keys (static UPPERMID15 table) ---
    if (const SaveValue* v = entry.objectForKey("coinCount")) {
        state.has_coin_count = true;
        state.coin_count = static_cast<std::int32_t>(SaveDict::intValue(v));
    }
    if (const SaveValue* v = entry.objectForKey("priceTier")) {
        state.has_price_tier = true;
        state.price_tier = static_cast<std::int32_t>(SaveDict::intValue(v));
    }
    state.has_seller_client_id =
        entry.objectForKey("sellerClientID") != nullptr;
    state.has_seller_client_name =
        entry.objectForKey("sellerClientName") != nullptr;

    // --- sellSlot hook (executed): counts only, no item decode -----------
    const SaveValue* sell_slot = entry.objectForKey("sellSlot");
    if (sell_slot != nullptr && sell_slot->isArray()) {
        state.has_sell_slot = true;
        state.sell_slot_item_count = SaveDict::count(sell_slot);
    }
    state.item_decode_performed = false;

    // --- InteractionObject static boundary ---
    state.interaction_static_keys_present =
        entry.objectForKey("flipped") != nullptr ||
        entry.objectForKey("paintColor") != nullptr ||
        entry.objectForKey("ownerID") != nullptr;
    return state;
}

ClientDynamicObject tradingpost_full_factory(int type_id,
                                             const SaveDict& entry,
                                             TradingPostFullState* out_state,
                                             std::string* error) {
    if (error) error->clear();
    const TradingPostFullState state = tradingpost_full_load(entry);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        "tradingpost full chain: DynamicObject base + own keys coinCount/"
        "priceTier/sellerClientID/sellerClientName-static (UPPERMID15) + "
        "sellSlot counts (executed hook; item decode not performed, "
        "itemType!=11 filter not applied) + InteractionObject super keys "
        "static-only (not loaded)";
    return object;
}

}  // namespace bh176
