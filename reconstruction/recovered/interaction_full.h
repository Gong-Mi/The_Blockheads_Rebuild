// InteractionObject-family loader (types 15 and 64): drives the EXECUTED
// init contract (interaction_object_init, 352w, 8-case differential) over a
// real save record and reads the resulting state back out of the contract's
// image — the same "run the contract, read the image" pattern as the other
// families.
//
// Type coverage:
//   15 InteractionObject — the mid-chain node itself; its record carries the
//      six keys {currentBlockheadIndex, flipped, isInUse, ownerID, ownerName,
//      paintColor}.
//   64 Mirror — zero own keys (its init is a 71-word [super] +
//      [self initSubDerivedItems] forwarder, no key read, no ivar write), so
//      its whole record domain is the InteractionObject key set.
//
// Offline boundary (stated): the world tail needs [dynamicWorld isServer]
// and getOwnerNameForObjectOwnerID: — both world state, NOT evaluable
// offline; the contract runs with is_server=false, which leaves the
// key-loaded ownerName untouched (the third gate never opens).
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include <cstdint>
#include <string>

namespace bh176 {

struct InteractionFullState {
    // base loader
    std::uint64_t unique_id = 0;
    std::int32_t pos_x = 0;
    std::int32_t pos_y = 0;
    float float_pos_x = 0.0f;
    float float_pos_y = 0.0f;
    bool has_float_pos = false;
    // the six keys, read back from the executed contract's image
    bool is_in_use = false;            // @68 byte
    bool flipped = false;              // @69 byte
    bool has_owner_id = false;         // @36 retained slot
    bool has_owner_name = false;       // @84 retained slot
    std::uint16_t paint_color = 0;     // @88 halfword (strh truncation)
    std::int32_t saved_blockhead_index = -1;  // @80 (-1 default honored)
    bool had_blockhead_index = false;  // the probe result
    // the world tail was not evaluable offline (always true, stated)
    bool world_tail_not_run = true;
};

InteractionFullState interaction_full_load(const SaveDict& entry);

ClientDynamicObject interaction_full_factory(int type_id,
                                             const SaveDict& entry,
                                             InteractionFullState* out_state,
                                             std::string* error);

}  // namespace bh176
