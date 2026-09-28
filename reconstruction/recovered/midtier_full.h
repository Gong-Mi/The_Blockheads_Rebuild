// Mid-tier static loader family (types 19, 20, 30, 31, 32, 38, 40, 53, 54):
// table-driven "objectForKey -> conversion -> sized ivar store" loaders whose
// key tables and store widths are decoded from the per-class annotated
// listings (emit_annotated_method.py over the pinned ELF; coverage gates OK).
//
// Read order and nesting are ARM-attested (the differential pins the call
// sequence): 7 of the 10 flat classes read their keys in a different order
// than the first listing pass suggested, and Egg reads breed through its
// genesDict child.
//
// Decoded per class (key / conversion / store):
// Orders below are the ARM-attested read order (tools/test_midtier_arm.py);
// the first listing pass had a different order for seven of them and those
// are corrected here.
//   31 Window : itemType int->word@56 ; ownerID retain->word@36
//   40 Rail   : itemType int->word@56 ; ownedByStation bool->STRB@65 ;
//               configuration int->word@60
//   32 Boat   : currentBlockheadIndex PROBE (savedBlockheadIndex@120 = -1
//               default first, intValue overwrite when non-nil) ;
//               ownerID retain->word@36 ; [self loadDerivedStuff] tail hook
//   19 Ladder : itemType int->word@56 ; paintColor unsignedInt->STRH@60 ;
//               ownerID retain->word@36
//   30 Egg    : hatchTimer float->word@64 ; genesDict retain->word@56 ;
//               breed int->STRH@60 read INSIDE genesDict (nested: the body
//               goes through self->genesDict; a top-level breed is not read)
//   53 Column : itemType int->word@56 ; configuration int->word@64 ;
//               paintColor unsignedInt->STRH@60 ; ownerID retain->word@36
//   54 Stairs : itemType int->word@56 ; configuration int->word@60 ;
//               ownerID retain->word@36 ; paintColor unsignedInt->STRH@64
//   20 Door   : itemType int->word@64 ; blocked bool->STRB@68 ;
//               ironPlaceClientID retain->word@72 ; ownerID retain->word@36
//   38 Wire   : itemType int->word@56 ; configuration int->word@60 ;
//               solidConfiguration int->word@64 ; ownerID retain->word@36
//   56 ElevatorShaft : itemType int->w@56 ; lastKnownMotorPos.x w@60 ;
//               .y w@64 ; ownerID o@36 ; paintColor UINT->STRH@84
//   55 ElevatorMotor : itemType int->w@56 ; availableElectricity UINT->STRH@60 ;
//               minY UINT->w@64 ; maxY UINT->w@68 ; ownerID o@36
//   22 SurfaceBlock / 29 SnowSurfaceBlock: ZERO own keys — the forwarder5b
//               pure super forwarders (57w super-only / 71w + initSubDerived
//               Items); their whole record domain is the DynamicObject base.
// All nine end with [self initSubDerivedItems] (no save state).
#pragma once

#include "../../app/src/main/cpp/dynamic_object_registry.h"
#include "../../app/src/main/cpp/original_save_dict.h"

#include <cstdint>
#include <map>
#include <string>

namespace bh176 {

struct MidtierKeySpec {
    const char* key;
    enum class Conv { Int, Bool, UInt, Float, Object } conv;
    enum class Width { Word, Half, Byte } width;
    int offset;
    // Non-null when the body reads this key from a CHILD dictionary (the
    // parent key's value) instead of the record root — e.g. Egg's breed is
    // read as [[self->genesDict] objectForKey:@"breed"], which the ARM
    // differential (tools/test_midtier_arm.py) pinned. Absent parent =>
    // absent nested key.
    const char* nested_in = nullptr;
};

struct MidtierTypeSpec {
    int type_id;
    const MidtierKeySpec* keys;
    std::size_t key_count;
    bool blockhead_probe_default;  // Boat: @120 -1 default + probe overwrite
    const char* tail_hook;         // informational (initSubDerivedItems / loadDerivedStuff)
    bool zero_own_keys = false;    // forwarder5b zeros: record domain = base only
};

struct MidtierFullState {
    // numbers: converted int/uint/float/bool values, keyed by the save key
    std::map<std::string, double> numbers;
    // object slots: presence only (the boxed/retained body is Foundation's)
    std::map<std::string, bool> objects;
    std::map<std::string, bool> present;
    // Boat's probe surface
    std::int32_t saved_blockhead_index = -1;
    bool had_blockhead_index = false;
    std::string tail_hook;   // the listing's tail [self <hook>]
};

// The per-class spec table lookup (nullptr when the type is not mid-tier).
const MidtierTypeSpec* midtierTypeSpec(int type_id);

MidtierFullState midtier_full_load(const SaveDict& entry, const MidtierTypeSpec& spec);

ClientDynamicObject midtier_full_factory(int type_id, const SaveDict& entry,
                                         MidtierFullState* out_state,
                                         std::string* error);

}  // namespace bh176
