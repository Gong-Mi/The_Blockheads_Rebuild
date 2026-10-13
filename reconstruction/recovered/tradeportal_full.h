// TradePortal loader (type 50): own keys static (UPPERMID15) + the executed
// price-offset normalization hook (b4i).
//
// Original chain:
//   DynamicObject base (executed)
//   InteractionObject (352w)  [STATIC only — the usual stated boundary]
//   TradePortal initWithWorld:dynamicWorld:saveDict:cache: (0x00d382fc,
//     281w, static level-A UPPERMID15): own keys {level, lightDict,
//     localPriceOffsets}; constructs a child ArtificialLight from lightDict
//     (5-arg variant — the ArtificialLight body is NOT recovered: presence
//     only) and creates the NSMutableDictionary for localPriceOffsets.
//   TradePortal loadPriceOffsets: (0x00d37a78, 197w)  [EXECUTED b4i]:
//     normalize a source dictionary into localPriceOffsets:
//       per key: doubleValue -> clamp [0.5, 2.0] -> store
//     The call-site argument BINDING of the init is static-level; this
//     loader runs the executed clamp over the record's own localPriceOffsets
//     entries (the save side writes exactly that key) and states so.
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include <cstdint>
#include <string>
#include <vector>

namespace bh176 {

struct TradePortalFullState {
    // base loader
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    float float_pos_x = 0.0f;
    float float_pos_y = 0.0f;
    bool has_float_pos = false;
    // own keys (static UPPERMID15)
    bool has_level = false;
    std::int32_t level = 0;
    bool light_present = false;      // ArtificialLight body not recovered
    // localPriceOffsets: raw entries + the EXECUTED clamp (b4i)
    bool has_local_price_offsets = false;
    std::vector<std::pair<std::string, double>> price_offsets_raw;
    std::vector<std::pair<std::string, double>> price_offsets_clamped;
    // InteractionObject static boundary
    bool interaction_static_keys_present = false;
};

TradePortalFullState tradeportal_full_load(const SaveDict& entry);

ClientDynamicObject tradeportal_full_factory(int type_id,
                                             const SaveDict& entry,
                                             TradePortalFullState* out_state,
                                             std::string* error);

}  // namespace bh176
