// TradePortal loader implementation. See tradeportal_full.h.
#include "tradeportal_full.h"

#include "trade_portal_price_offsets.h"

namespace bh176 {

TradePortalFullState tradeportal_full_load(const SaveDict& entry) {
    TradePortalFullState state;

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
    if (const SaveValue* level = entry.objectForKey("level")) {
        state.has_level = true;
        state.level = static_cast<std::int32_t>(SaveDict::intValue(level));
    }
    state.light_present = entry.objectForKey("lightDict") != nullptr;

    // --- localPriceOffsets: raw entries + the executed clamp (b4i) ---
    // The clamp helper is the recovered contract's own function (VFP branch
    // semantics, [0.5, 2.0]).
    if (const SaveValue* offsets = entry.objectForKey("localPriceOffsets")) {
        if (offsets->isDict()) {
            state.has_local_price_offsets = true;
            for (const auto& kv : offsets->dict) {
                const double raw = SaveDict::doubleValue(&kv.second);
                state.price_offsets_raw.emplace_back(kv.first, raw);
                state.price_offsets_clamped.emplace_back(
                    kv.first,
                    blockheads::recovered::clamp_price_offset(raw));
            }
        }
    }

    // --- InteractionObject static boundary ---
    state.interaction_static_keys_present =
        entry.objectForKey("flipped") != nullptr ||
        entry.objectForKey("paintColor") != nullptr ||
        entry.objectForKey("ownerID") != nullptr;
    return state;
}

ClientDynamicObject tradeportal_full_factory(int type_id,
                                             const SaveDict& entry,
                                             TradePortalFullState* out_state,
                                             std::string* error) {
    if (error) error->clear();
    const TradePortalFullState state = tradeportal_full_load(entry);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        "tradeportal full chain: DynamicObject base + own keys level/"
        "lightDict-static (UPPERMID15; ArtificialLight body not recovered) + "
        "localPriceOffsets clamped by the executed b4i contract (call-site "
        "binding static-level) + InteractionObject super keys static-only "
        "(not loaded)";
    return object;
}

}  // namespace bh176
