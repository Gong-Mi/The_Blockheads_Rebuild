// Optional ARM differential bridge for the "special" loaders whose bodies are
// not flat key tables (tools/test_specials_arm.py). Incremental: classes are
// added here as their dumps get modelled and pinned.
//
// Modelled so far:
//   SteamTrain 42 (0x00d18834, super = TrainCar): its own body reads, in this
//     order — fuelFraction (floatValue -> word @260), hasFuel (boolValue ->
//     STRB @268), goingRight (boolValue -> STRB @252), stopped (boolValue ->
//     STRB @325) — and calls NO post-init hook (the loadDerivedStuff hook
//     belongs to the TrainCar super chain, which the stub super2 stands for).
#include <cstdint>
#include <cstring>
#include <string>

#include "../reconstruction/recovered/ui_control.h"
#include "../reconstruction/recovered/ui_touch_router.h"

namespace {

enum Conv { C_INT, C_BOOL, C_UINT, C_FLOAT, C_OBJECT };

struct Row {
    const char* key;
    Conv conv;
    int width;   // bytes actually stored
    int offset;
};

const Row kSteamTrain[] = {
    {"fuelFraction", C_FLOAT, 4, 260},
    {"hasFuel", C_BOOL, 1, 268},
    {"goingRight", C_BOOL, 1, 252},
    {"stopped", C_BOOL, 1, 325},
};

struct ClassRows {
    int type_id;
    const Row* rows;
    int count;
    const char* hook;            // nullptr when the body has no own hook
    const char* extras;          // comma-joined extra selectors the stub serves
    bool gated_reads;            // true: a nil probe skips the value read (w/h)
    int default_value;           // stored before the reads (OwnershipSign: 30)
    int clamp_lo;                // 0 = no clamp (OwnershipSign w/h: 1..30)
    int clamp_hi;
};

// Painting 52 (0x00aa81e8, super = DynamicObject): own body, ARM-attested by
// the per-case dumps + the annotated listing's cell map —
//   5 key reads in order: itemType (intValue -> word @56), outputImageData
//     (retain -> @60), hasVerifiedImageData (boolValue -> STRB @79), ownerID
//     (retain -> @36), ownerName (retain -> @64);
//   gate 1 [self->dynamicWorld isServer]: when true AND ownerID != nil AND
//     ownerName == nil -> [dynamicWorld getOwnerNameForObjectOwnerID:ownerID]
//     -> retain -> stored back into ownerName @64;
//   gate 2 [self->dynamicWorld isServer]: when true ->
//     [dynamicWorld playerIsBannedWithID:ownerID] -> STRB @77;
//   [self initSubDerivedItems] tail hook.
//
// OwnershipSign 60 (0x00a34b18, super = Sign): its own body, ARM-attested
// by the differential's per-case dump —
//   * the w/h radii get a DEFAULT of 15 (movw lr, #0xf; two stores) before
//     any read;
//   * `ofk:landOwnerID` is a probe: only when it is non-nil does the object
//     block run — [old autorelease] x2 (the stale ivar values, nil on a
//     fresh object), then [[saveDict objectForKey:@"landOwnerID"] retain]
//     stored @124 and [[saveDict objectForKey:@"landOwnerName"] retain]
//     stored @128 (the name is read inside the same block);
//   * each radius then probes its own key: non-nil -> a SECOND read +
//     intValue + the float clamp helper (0x4BE068 = clampf(x, 1.0, 30.0),
//     runs natively in the harness) lands the value; nil -> the 15 stays;
//   * finally [self updateText] (a declared extra selector).
const Row kOwnershipSign[] = {
    {"landOwnerID", C_OBJECT, 4, 124},
    {"landOwnerName", C_OBJECT, 4, 128},
    {"w", C_INT, 4, 132},
    {"h", C_INT, 4, 136},
};

const Row kPainting[] = {
    {"itemType", C_INT, 4, 56},
    {"outputImageData", C_OBJECT, 4, 60},
    {"hasVerifiedImageData", C_BOOL, 1, 79},
    {"ownerID", C_OBJECT, 4, 36},
    {"ownerName", C_OBJECT, 4, 64},
};

// DropBear 25 (0x0079d538, super = NPC): own body, ARM-attested by the dump —
//   8 own keys in order: provokeMeter float @300, courageMeter float @304,
//   dropping STRB @308, dropSpeed float @312, onGround STRB @344,
//   dropPos.x int @348, dropPos.y int @352, goalTreeDirection int @356;
//   then the AGE STEP: saveTime floatValue + [world worldTime] (read as a
//   DOUBLE via vmov d1, r0, r1) -> age@88 += (worldTime - saveTime); then
//   [self maxAge] compared against age: age > maxAge -> [self
//   removeFromMacroBlock] + [self release] + return NIL (dies of old age);
//   else [self loadDerivedStuff] + return self.
const Row kDropBear[] = {
    {"provokeMeter", C_FLOAT, 4, 300},
    {"courageMeter", C_FLOAT, 4, 304},
    {"dropping", C_BOOL, 1, 308},
    {"dropSpeed", C_FLOAT, 4, 312},
    {"onGround", C_BOOL, 1, 344},
    {"dropPos.x", C_INT, 4, 348},
    {"dropPos.y", C_INT, 4, 352},
    {"goalTreeDirection", C_INT, 4, 356},
    {"saveTime", C_FLOAT, 0, 0},      // read-only: feeds the age step
};

// CaveTroll 39 (0x00d538cc, super = NPC): own body, ARM-attested by the
// dump — super, then the coordinate-wrap helper queries [world
// worldWidthMacro] (via the in-ELF helper at 0xA12F64), then the reads:
// defendSquare.x intValue -> word @356, defendSquare.y intValue -> word @360,
// state -> [bytes]/[length] -> memcpy (PLT veneer 0x1C2894, GOT slot
// 0x105FB40) into the @208 blob, dead boolValue -> STRB @56; then the wrap
// helper runs again around the tail [self initSubDerivedStuffStuff]. The
// world-derived movement slots (travelSpeed@312 = 4.0f, travelFraction@400 =
// 1.0f) are pinned to the harness's worldWidthMacro=4 stub.
const Row kCaveTroll[] = {   // drives the key list / presence indices only
    {"defendSquare.x", C_INT, 4, 356},
    {"defendSquare.y", C_INT, 4, 360},
    {"state", C_OBJECT, 4, 208},
    {"dead", C_BOOL, 1, 56},
};

// TrainCar (the family chain, executed as type 43's body — the freight/
// hand/passenger cars all forward into it): own body, ARM-attested —
//   * the rider loop: `for (i = 0; i < [self maxNumberOfRiders]; i++)` with
//     the bound RE-EVALUATED per iteration (2 riders -> 3 bound calls):
//     [NSString stringWithFormat:@"currentBlockheadIndex_%d", i] ->
//     objectForKey: -> unsignedLongLongValue -> a u32 stored at @84 + i*4;
//   * rightCarID -> unsignedLongLongValue -> u64 @144 ;
//     leftCarID -> @152 ; engineCarID -> @160 ;
//   * engineIsRight boolValue -> STRB @180 ;
//   * ownerID retain -> @36 ; [self loadDerivedStuff] tail.
// Harness stub constants the model pins: maxNumberOfRiders = 2,
// unsignedLongLongValue -> 0x1122334455667788.
const Row kTrainCar[] = {   // the chain's own keys (rider keys are stub-made)
    {"rightCarID", C_UINT, 8, 152},   // the two u64 slots confirmed swapped:
    {"leftCarID", C_UINT, 8, 144},    // left -> @144, right -> @152
    {"engineCarID", C_UINT, 8, 160},
    {"engineIsRight", C_BOOL, 1, 180},
    {"ownerID", C_OBJECT, 4, 36},
};

// ArtificialLight 21 (0x00a93c64, super = DynamicObject): own body,
// ARM-attested by the per-case dump + the memory-write trace —
//   [self isClient] (true -> [self release] + nil); super; then EIGHT int
//   reads stored in order: maxRed@64, maxGreen@68, maxBlue@72, maxHeat@76,
//   radius@80, contributionGridOrigin.x@84, .y@88, lightDirection@96; the
//   `downlight` boolValue read does NOT store its own field — a true value
//   OVERWRITES lightDirection@96 with 1 (cell 0xffffef30 = lightDirection,
//   store at 0xA94130 after the bool test);
//   diameter@92 = radius << 1; two __wrap_calloc calls fill
//   contributionGrid@56 / addedGrid@60 (stub returns 0); parentObject@100
//   is the 5th ARGUMENT (zero under the harness); [self addToTiles] tail.
const Row kArtificialLight[] = {
    {"maxRed", C_INT, 4, 64},
    {"maxGreen", C_INT, 4, 68},
    {"maxBlue", C_INT, 4, 72},
    {"maxHeat", C_INT, 4, 76},
    {"radius", C_INT, 4, 80},
    {"contributionGridOrigin.x", C_INT, 4, 84},
    {"contributionGridOrigin.y", C_INT, 4, 88},
    {"lightDirection", C_INT, 4, 96},
    {"downlight", C_BOOL, 0, 0},     // read-only gate (no own store)
};

const ClassRows kClasses[] = {
    {42, kSteamTrain, 4, nullptr, "", false, 0, 0, 0},
    {60, kOwnershipSign, 4, nullptr, "updateText", true, 15, 1, 30},
    {52, kPainting, 5, "initSubDerivedItems", "initSubDerivedItems", false, 0, 0, 0},
    {25, kDropBear, 9, "loadDerivedStuff",
     "loadDerivedStuff,removeFromMacroBlock,release", false, 0, 0, 0},
    {39, kCaveTroll, 4, "initSubDerivedStuffStuff",
     "initSubDerivedStuffStuff,macroTiles", false, 0, 0, 0},
    {43, kTrainCar, 5, "loadDerivedStuff", "loadDerivedStuff", false, 0, 0, 0},
    {21, kArtificialLight, 9, "addToTiles", "isClient,addToTiles",
     false, 0, 0, 0},
};

const ClassRows* specOf(int type_id) {
    for (const ClassRows& c : kClasses) {
        if (c.type_id == type_id) return &c;
    }
    return nullptr;
}

const char* convLabel(Conv conv) {
    switch (conv) {
        case C_INT: return "int";
        case C_BOOL: return "bool";
        case C_UINT: return "uint";
        case C_FLOAT: return "float";
        case C_OBJECT: return "retain";
    }
    return "?";
}

std::uint32_t valueOf(const Row& row, int index, std::uint32_t token_base) {
    switch (row.conv) {
        case C_INT: return 0x00012345u;
        case C_BOOL: return 1u;
        case C_UINT: return 0x0001FFF1u;
        case C_FLOAT: return 0x3FC00000u;   // 1.5f
        case C_OBJECT: return token_base + static_cast<std::uint32_t>(index) * 0x10u;
    }
    return 0;
}

bool presentFor(int case_id, int index) {
    switch (case_id) {
        case 0: return true;
        case 1: return index % 2 == 0;
        case 3: return index % 2 == 1;
        default: return false;   // case 2: nil super, no reads
    }
}

}  // namespace

extern "C" {

const char* recovered_specials_key_list(int type_id) {
    static std::string buffer;
    buffer.clear();
    const ClassRows* spec = specOf(type_id);
    if (spec == nullptr) return buffer.c_str();
    for (int i = 0; i < spec->count; ++i) {
        if (i != 0) buffer += ',';
        buffer += spec->rows[i].key;
    }
    return buffer.c_str();
}

const char* recovered_specials_extra(int type_id) {
    const ClassRows* spec = specOf(type_id);
    return (spec != nullptr) ? spec->extras : "";
}

const char* recovered_specials_sequence(int type_id, int case_id) {
    static std::string buffer;
    buffer = "super";
    const ClassRows* spec = specOf(type_id);
    if (spec == nullptr) return buffer.c_str();
    if (case_id == 2 && type_id != 21) {
        return buffer.c_str();   // nil guard: nothing else runs (type 21 keeps
                                 // its pre-super isClient gate)
    }
    if (type_id == 21) {
        buffer = "isClient,super";   // the isClient gate runs BEFORE super
        if (case_id == 2) return buffer.c_str();
        for (int i = 0; i < spec->count; ++i) {
            if (spec->rows[i].conv == C_BOOL) continue;   // the gate: no store
            buffer += ",ofk:";
            buffer += spec->rows[i].key;
            buffer += ",int:";
            buffer += spec->rows[i].key;
        }
        buffer += ",ofk:downlight,bool:downlight";
        buffer += ",import(__wrap_calloc),import(__wrap_calloc),addToTiles";
        return buffer.c_str();
    }
    if (type_id == 43) {
        // the TrainCar chain: rider loop (bound re-read per iteration)
        const int riders = 2;
        for (int i = 0; i < riders; ++i) {
            const std::string idx = std::to_string(i);
            buffer += ",maxNumberOfRiders,format->currentBlockheadIndex_" + idx;
            buffer += ",ofk:currentBlockheadIndex_" + idx;
            buffer += ",ull:currentBlockheadIndex_" + idx;
        }
        buffer += ",maxNumberOfRiders";
        // the car-ID conversions are NIL-GUARDED by the body (an absent key
        // yields ofk only; the store never happens)
        const char* car_keys[3] = {"rightCarID", "leftCarID", "engineCarID"};
        for (int k = 0; k < 3; ++k) {
            buffer += ",ofk:";
            buffer += car_keys[k];
            if (presentFor(case_id, k)) {
                buffer += ",ull:";
                buffer += car_keys[k];
            }
        }
        buffer += ",ofk:engineIsRight,bool:engineIsRight";
        buffer += ",ofk:ownerID,retain";
        buffer += ",loadDerivedStuff";
        return buffer.c_str();
    }
    if (type_id == 39) {
        const bool state_present = presentFor(case_id, 2);
        buffer += ",worldWidthMacro,macroTiles,worldWidthMacro,worldWidthMacro";
        buffer += ",ofk:defendSquare.x,int:defendSquare.x";
        buffer += ",ofk:defendSquare.y,int:defendSquare.y";
        buffer += ",ofk:state";
        if (state_present) {
            buffer += ",bytes,length,memcpy";
        }
        buffer += ",ofk:dead,bool:dead";
        // the second wrap group runs only when the state blob was present
        // (the movement-state re-init block sits behind it; per-case dump:
        // case 0/1 with state -> group, case 3 without state -> no group)
        if (presentFor(case_id, 2)) {
            buffer += ",worldWidthMacro,macroTiles,worldWidthMacro,worldWidthMacro";
        }
        buffer += ",initSubDerivedStuffStuff";
        return buffer.c_str();
    }
    if (type_id == 25) {
        for (int i = 0; i < spec->count; ++i) {
            const Row& row = spec->rows[i];
            buffer += ",ofk:";
            buffer += row.key;
            buffer += ',';
            if (row.conv == C_OBJECT) {
                buffer += "retain";
            } else {
                buffer += convLabel(row.conv);
                buffer += ':';
                buffer += row.key;
            }
        }
        buffer += ",worldTime,maxAge";
        if (case_id == 4) {
            buffer += ",removeFromMacroBlock,release";   // dies of old age
        } else {
            buffer += ",loadDerivedStuff";
        }
        return buffer.c_str();
    }
    if (type_id == 52) {
        // the five reads, then the two [dynamicWorld isServer] gates; object
        // reads label as a bare `retain` (the harness's conversion label)
        for (int i = 0; i < spec->count; ++i) {
            buffer += ",ofk:";
            buffer += spec->rows[i].key;
            buffer += ',';
            if (spec->rows[i].conv == C_OBJECT) {
                buffer += "retain";
            } else {
                buffer += convLabel(spec->rows[i].conv);
                buffer += ':';
                buffer += spec->rows[i].key;
            }
        }
        buffer += ",isServer";
        // resolve only when ownerID != nil && ownerName == nil
        if (presentFor(case_id, 3) && !presentFor(case_id, 4)) {
            buffer += ",resolveOwnerName,retain";
        }
        buffer += ",isServer,playerIsBanned,initSubDerivedItems";
        return buffer.c_str();
    }
    if (type_id == 60) {
        // the ID probe gates the whole object block (per-case dump)
        buffer += ",ofk:landOwnerID";
        if (presentFor(case_id, 0)) {
            buffer += ",autorelease,autorelease,ofk:landOwnerID,retain";
            buffer += ",ofk:landOwnerName,retain";
        }
        for (int i = 2; i < spec->count; ++i) {
            buffer += ",ofk:";
            buffer += spec->rows[i].key;
            if (presentFor(case_id, i)) {
                buffer += ",ofk:";
                buffer += spec->rows[i].key;
                buffer += ",int:";
                buffer += spec->rows[i].key;
            }
        }
        buffer += ",updateText";
        return buffer.c_str();
    }
    for (int i = 0; i < spec->count; ++i) {
        buffer += ",ofk:";
        buffer += spec->rows[i].key;
        buffer += ',';
        buffer += convLabel(spec->rows[i].conv);
        buffer += ':';
        buffer += spec->rows[i].key;
    }
    if (spec->hook != nullptr) buffer += ",hook";
    return buffer.c_str();
}

int recovered_specials_image(int type_id, int case_id, std::uint32_t token_base,
                             unsigned char* out, int n) {
    if (out == nullptr || n <= 0) return -1;
    std::memset(out, 0, static_cast<std::size_t>(n));
    const ClassRows* spec = specOf(type_id);
    if (spec == nullptr) return -1;
    if (case_id == 2) return n;
    if (type_id == 21) {
        for (int i = 0; i < spec->count; ++i) {
            const Row& row = spec->rows[i];
            if (row.conv == C_BOOL || row.width == 0) continue;  // the gate
            if (!presentFor(case_id, i)) continue;
            const std::uint32_t v = 0x00012345u;
            for (int b2 = 0; b2 < 4; ++b2) {
                out[row.offset + b2] = static_cast<unsigned char>((v >> (8 * b2)) & 0xFF);
            }
        }
        // the downlight gate: true -> a WORD store of 1 into lightDirection@96
        if (presentFor(case_id, 8)) {
            for (int b2 = 0; b2 < 4; ++b2) {
                out[96 + b2] = static_cast<unsigned char>((1u >> (8 * b2)) & 0xFF);
            }
        }
        // diameter@92 = radius << 1 (radius present -> 2*0x12345)
        const std::uint32_t diameter = presentFor(case_id, 4) ? 0x0002468Au : 0u;
        for (int b2 = 0; b2 < 4; ++b2) {
            out[92 + b2] = static_cast<unsigned char>((diameter >> (8 * b2)) & 0xFF);
        }
        // contributionGrid@56 / addedGrid@60 / parentObject@100 stay zero
        return n;
    }
    if (type_id == 43) {
        // riders: u32 at @84 + i*4 (0x55667788), always present (stub-made)
        for (int i = 0; i < 2; ++i) {
            const std::uint32_t v = 0x55667788u;
            for (int b = 0; b < 4; ++b) {
                out[84 + i * 4 + b] =
                    static_cast<unsigned char>((v >> (8 * b)) & 0xFFu);
            }
        }
        // car IDs: u64 per case presence at @144/@152/@160
        const int offs[3] = {152, 144, 160};   // right, left, engine
        for (int k = 0; k < 3; ++k) {
            if (!presentFor(case_id, k)) continue;
            std::uint32_t lo = 0x55667788u, hi = 0x11223344u;
            for (int b = 0; b < 4; ++b) {
                out[offs[k] + b] = static_cast<unsigned char>((lo >> (8 * b)) & 0xFFu);
                out[offs[k] + 4 + b] = static_cast<unsigned char>((hi >> (8 * b)) & 0xFFu);
            }
        }
        if (presentFor(case_id, 3)) out[180] = 1;            // engineIsRight
        if (presentFor(case_id, 4)) {                        // ownerID token
            const std::uint32_t tok = token_base + 0x60u;    // stub token base
            for (int b = 0; b < 4; ++b) {
                out[36 + b] = static_cast<unsigned char>((tok >> (8 * b)) & 0xFFu);
            }
        }
        return n;
    }
    if (type_id == 39) {
        // dead STRB @56
        if (presentFor(case_id, 3)) out[56] = 1;
        // defendSquare.x/.y words @356/@360
        const std::uint32_t dv = 0x00012345u;
        if (presentFor(case_id, 0)) {
            for (int b = 0; b < 4; ++b)
                out[356 + b] = static_cast<unsigned char>((dv >> (8 * b)) & 0xFF);
        }
        if (presentFor(case_id, 1)) {
            for (int b = 0; b < 4; ++b)
                out[360 + b] = static_cast<unsigned char>((dv >> (8 * b)) & 0xFF);
        }
        // the state blob @208 (the harness fixture's 4 bytes) when present
        if (presentFor(case_id, 2)) {
            out[208] = 0xAA; out[209] = 0xBB; out[210] = 0xCC; out[211] = 0xDD;
        }
        // world-derived movement slots under the worldWidthMacro=4 stub
        const std::uint32_t speed = 0x40800000u;     // 4.0f
        const std::uint32_t frac = 0x3F800000u;      // 1.0f
        for (int b = 0; b < 4; ++b) {
            out[312 + b] = static_cast<unsigned char>((speed >> (8 * b)) & 0xFF);
            out[400 + b] = static_cast<unsigned char>((frac >> (8 * b)) & 0xFF);
        }
        return n;
    }
    if (type_id == 25) {
        // the age step: age@88 = 0 + (worldTime 1000.0 - saveTime), where the
        // harness's floatValue stub gives 1.5 when the saveTime key is present
        // and 0.0 when absent -> 998.5f (0x4479A000) or 1000.0f (0x447A0000).
        const std::uint32_t age = presentFor(case_id, 8) ? 0x4479A000u
                                                         : 0x447A0000u;
        for (int b = 0; b < 4; ++b) {
            out[88 + b] = static_cast<unsigned char>((age >> (8 * b)) & 0xFFu);
        }
    }
    if (spec->default_value != 0) {
        for (int i = 0; i < spec->count; ++i) {
            const Row& row = spec->rows[i];
            if (row.conv != C_INT) continue;
            const std::uint32_t dv = static_cast<std::uint32_t>(spec->default_value);
            for (int b = 0; b < row.width; ++b) {
                out[row.offset + b] = static_cast<unsigned char>((dv >> (8 * b)) & 0xFF);
            }
        }
    }
    for (int i = 0; i < spec->count; ++i) {
        const Row& row = spec->rows[i];
        if (spec->rows[i].width == 0) continue;   // read-only row (saveTime)
        bool is_present = presentFor(case_id, i);
        if (type_id == 52 && i == 4 && presentFor(case_id, 3) && !is_present) {
            // resolved name lands in ownerName @64 (fixed token)
            const std::uint32_t resolved = token_base + 0x100u;
            for (int b = 0; b < 4; ++b) {
                out[row.offset + b] =
                    static_cast<unsigned char>((resolved >> (8 * b)) & 0xFFu);
            }
            continue;
        }
        if (type_id == 60 && i == 1) {
            // the name is read (and retained) only inside the ID-gated block
            is_present = is_present && presentFor(case_id, 0);
        }
        std::uint32_t value =
            is_present ? valueOf(row, i, token_base) : 0u;
        if (spec->default_value != 0 && row.conv == C_INT && !presentFor(case_id, i)) {
            continue;   // the default survives the absent probe
        }
        if (spec->clamp_hi != 0 && row.conv == C_INT && presentFor(case_id, i)) {
            const std::int32_t v = static_cast<std::int32_t>(value);
            const std::int32_t lo = spec->clamp_lo;
            const std::int32_t hi = spec->clamp_hi;
            const std::int32_t clamped = v < lo ? lo : (v > hi ? hi : v);
            value = static_cast<std::uint32_t>(clamped);
        }
        if (row.offset < 0 || row.offset + 4 > n) return -2;
        for (int b = 0; b < row.width; ++b) {
            out[row.offset + b] =
                static_cast<unsigned char>((value >> (8 * b)) & 0xFFu);
        }
    }
    return n;
}

// ---- the UI front: MJControl's press lifecycle -------------------------
// The model IS the production module (reconstruction/recovered/ui_control.h),
// included here so the differential verifies the shipped code rather than a
// copy. Cases (observed on the ARM first, then encoded):
//   0: inside, enabled  -> super + the sound + hover/received/timer writes, ret 1
//   1: outside          -> no calls, no writes, ret 0
//   2: disabled         -> no calls, no writes, ret 0
}  // extern "C"

namespace {
using blockheads::ui::Control;
using blockheads::ui::Point;

Control ui_case_control(int case_id) {
    Control c;
    c.event_frame = {0.0f, 0.0f, 100.0f, 100.0f};
    c.enabled = (case_id != 2);
    return c;
}
Point ui_case_point(int case_id) {
    return case_id == 1 ? Point{500.0f, 500.0f} : Point{50.0f, 50.0f};
}
void ui_put_word(unsigned char* out, int off, std::uint32_t v) {
    for (int b = 0; b < 4; ++b) {
        out[off + b] = static_cast<unsigned char>((v >> (8 * b)) & 0xFFu);
    }
}

// --- the UIManager router's differential inputs --------------------------
// The receivers the harness seeds and the replies its UI_CASES fixture pins
// (tools/test_specials_arm.py): the model walks the decoded block chain
// (ui_touch_router.h) with exactly those replies. The seed words mirror the
// harness's --seed writes; the only observable write the body makes is
// currentTouchIsInAnyButtons@154.
const blockheads::ui::Receiver kStubReply{};              // answers 0
const blockheads::ui::Receiver kHandles{true, false, false, false};
const blockheads::ui::Receiver kHandlesPaused{false, true, false, false};
const blockheads::ui::Receiver kShownOnly{false, false, true, false};
const blockheads::ui::Receiver kShownHandles{true, false, true, false};
const blockheads::ui::Receiver kShownInView{false, false, true, true};

blockheads::ui::RouterInputs ui_router_case(int case_id) {
    blockheads::ui::RouterInputs in;
    switch (case_id) {
        case 0: in.tc_ui = &kStubReply; break;
        case 1: in.tc_ui = &kStubReply; in.world_ui = &kStubReply; break;
        case 2: in.world_ui = &kStubReply; in.pause_ui = &kStubReply;
                in.tc_ui = &kStubReply; in.dpad = &kStubReply;
                in.camera_ui = &kStubReply; break;
        case 3: in.tc_ui_displayed = true; in.tc_ui = &kStubReply;
                in.world_ui = &kStubReply; break;
        case 4: in.pause_ui = &kStubReply; in.hide_pause_ui = true; break;
        case 5: in.camera_ui = &kStubReply; break;
        case 6: in.world_ui = &kStubReply; in.map_displayed = true; break;
        case 7: in.tc_ui_displayed = true; in.tc_ui = &kHandles;
                in.world_ui = &kStubReply; break;
        case 8: in.camera_ui = &kHandles; break;
        case 9: in.dpad = &kShownOnly; in.world_ui = &kStubReply; break;
        case 10: in.dpad = &kShownHandles; break;
        case 11: in.world_ui = &kHandles; break;
        case 12: in.world_ui = &kStubReply;
                 in.ui_views = {&kStubReply}; break;
        case 13: in.world_ui = &kStubReply;
                 in.ui_views = {&kShownHandles}; break;
        case 14: in.world_ui = &kStubReply;
                 in.ui_views = {&kShownInView}; break;
        case 15: in.world_ui = &kStubReply;
                 in.ui_views = {&kShownOnly}; break;
        case 16: in.camera_ui = &kStubReply;
                 in.world_ui = &kHandlesPaused; break;
        case 17: in.world_ui = &kStubReply;
                 in.ui_views = {&kStubReply, &kShownHandles}; break;
        case 18: in.world_ui = &kStubReply;
                 in.ui_views = {&kShownInView, &kShownHandles}; break;
        default: break;
    }
    return in;
}

void ui_router_seeds(unsigned char* out, int case_id) {
    // the same seed words the harness writes into the ARM instance — they
    // are part of the compared image
    ui_put_word(out, 4, 0x60000100u);
    ui_put_word(out, 8, 0x60000200u);
    switch (case_id) {
        case 0: ui_put_word(out, 32, 0x60020200u); break;
        case 1: ui_put_word(out, 32, 0x60020200u);
                ui_put_word(out, 20, 0x60020000u); break;
        case 2: ui_put_word(out, 20, 0x60020000u);
                ui_put_word(out, 24, 0x60020100u);
                ui_put_word(out, 32, 0x60020200u);
                ui_put_word(out, 36, 0x60020300u);
                ui_put_word(out, 100, 0x60020400u); break;
        case 3: ui_put_word(out, 40, 1u);
                ui_put_word(out, 32, 0x60020200u);
                ui_put_word(out, 20, 0x60020000u); break;
        case 4: ui_put_word(out, 24, 0x60020100u);
                ui_put_word(out, 148, 1u); break;
        case 5: ui_put_word(out, 100, 0x60020400u); break;
        case 6: ui_put_word(out, 20, 0x60020000u);
                ui_put_word(out, 152, 1u); break;
        case 7: ui_put_word(out, 40, 1u);
                ui_put_word(out, 32, 0x60020200u);
                ui_put_word(out, 20, 0x60020000u); break;
        case 8: ui_put_word(out, 100, 0x60020400u); break;
        case 9: ui_put_word(out, 36, 0x60020300u);
                ui_put_word(out, 20, 0x60020000u); break;
        case 10: ui_put_word(out, 36, 0x60020300u); break;
        case 11: ui_put_word(out, 20, 0x60020000u); break;
        case 12: case 13: case 14: case 15:
        case 17: case 18:
            ui_put_word(out, 20, 0x60020000u);
            ui_put_word(out, 140, 0x60020500u); break;
        case 16: ui_put_word(out, 100, 0x60020400u);
                 ui_put_word(out, 20, 0x60020000u); break;
    }
}

// --- the CraftUI panel's differential inputs ------------------------------
// The seeds mirror the harness's frame() fixture: windowInfo = self_ptr
// (0x60001000) so the words at +8/+0xc read back as the window floats, and
// translationOffset = the floats at 212/216; the three child pointers sit at
// 148/208/164 (scrollingButtons / craftButton / countSlider). The children's
// replies are the fixture's, like every Receiver reply.
const blockheads::ui::ChildReply kChildMiss{};
const blockheads::ui::ChildReply kChildInUi{true, false};
const blockheads::ui::ChildReply kChildHandles{false, true};

std::uint32_t float_bits(float v) {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &v, sizeof(bits));
    return bits;
}

blockheads::ui::Point craftui_point(int case_id) {
    switch (case_id) {   // the CraftUIRect cases' points
        case 1: return {200.0f, 50.0f};
        case 2: return {-130.0f, 50.0f};
        case 3: return {50.0f, 0.0f};
        case 4: return {50.0f, 302.0f};
        case 5: return {150.0f, 90.0f};
        default: return {50.0f, 50.0f};
    }
}

blockheads::ui::PanelFrame craftui_frame(int case_id) {
    if (case_id == 5) {   // window (100,60), offset (30,20) -> local (20,10)
        return {100.0f, 60.0f, 30.0f, 20.0f};
    }
    return {};
}

const blockheads::ui::ChildReply* craftui_child(int which, int slot,
                                                int case_id) {
    // slot 0/1/2 = scrollingButtons / craftButton / countSlider; the cases
    // 1/2/3 pin that child's reply to 1
    if (which == 74) return (case_id == slot + 1) ? &kChildInUi : &kChildMiss;
    if (which == 75) {
        return (case_id == slot + 1) ? &kChildHandles : &kChildMiss;
    }
    return &kChildMiss;   // moveTouch:/endTouch: are void
}

blockheads::ui::PanelTrace craftui_trace(int which, int case_id) {
    const auto* sb = craftui_child(which, 0, case_id);
    const auto* cb = craftui_child(which, 1, case_id);
    const auto* cs = craftui_child(which, 2, case_id);
    if (which == 74) return blockheads::ui::craftui_touch_is_in_ui(sb, cb, cs);
    if (which == 75) return blockheads::ui::craftui_start_touch(sb, cb, cs);
    if (which == 76) return blockheads::ui::craftui_move_touch(sb, cb, cs);
    return blockheads::ui::craftui_end_touch(sb, cb, cs);
}

void craftui_seeds(unsigned char* out, int which, int case_id) {
    // the same seed words the harness writes (part of the compared image)
    ui_put_word(out, 4, 0x60000100u);
    ui_put_word(out, 8, 0x60000200u);
    ui_put_word(out, 128, 0x60001000u);      // windowInfo = self_ptr
    const auto f = craftui_frame(which == 73 ? case_id : 0);
    ui_put_word(out, 8, float_bits(f.window_x));
    ui_put_word(out, 12, float_bits(f.window_y));
    ui_put_word(out, 212, float_bits(f.offset_x));
    ui_put_word(out, 216, float_bits(f.offset_y));
    if (which != 73) {                       // the touch methods read children
        ui_put_word(out, 148, 0x60020600u);
        ui_put_word(out, 208, 0x60020700u);
        ui_put_word(out, 164, 0x60020800u);
    }
}

// --- the DPad panel's differential inputs ---------------------------------
// The seeds mirror the harness's dpad_frame fixture: windowInfo = self_ptr,
// the five window fields at 8/12/16/20/28 and rightSide@160.
blockheads::ui::DPadFrame dpad_frame_for(int case_id) {
    switch (case_id) {
        case 5: return {0.0f, 0.0f, 40.0f, 0.0f, 0.0f, false};
        case 6: return {0.0f, 0.0f, 0.0f, 0.0f, 25.0f, false};
        case 7: case 8: return {50.0f, 7.0f, 0.0f, 30.0f, 0.0f, true};
        default: return {};
    }
}

blockheads::ui::Point dpad_point_for(int case_id) {
    switch (case_id) {
        case 1: return {165.96194458007812f, 194.2462158203125f};
        case 2: return {74.03805541992188f, 194.2462158203125f};
        case 3: return {120.0f, 197.78173828125f};
        case 4: return {120.0f, 240.20816040039062f};
        case 5: return {215.86143493652344f, 175.86143493652344f};
        case 6: return {64.13856506347656f, 200.86143493652344f};
        case 7: return {-50.0f, 120.0f};
        case 8: return {-4.038055419921875f, 194.2462158203125f};
        default: return {120.0f, 120.0f};
    }
}

void dpad_seeds(unsigned char* out, int case_id) {
    ui_put_word(out, 112, 0x60001000u);      // windowInfo = self_ptr
    const auto f = dpad_frame_for(case_id);
    ui_put_word(out, 8, float_bits(f.window_x));
    ui_put_word(out, 12, float_bits(f.window_y));
    ui_put_word(out, 16, float_bits(f.w10));
    ui_put_word(out, 20, float_bits(f.w14));
    ui_put_word(out, 28, float_bits(f.w1c));
    ui_put_word(out, 160, f.right_side ? 1u : 0u);
}

// --- the BlockheadUI panel's differential inputs --------------------------
// The seeds mirror the harness's blockhead_frame / bh_seeds fixtures.
// the sd cases differ per type family: 80-82 use 3/4/5, 83/84 use 1
bool blockhead_sd(int which, int case_id) {
    if (which == 83 || which == 84) return case_id == 1;
    return case_id == 3 || case_id == 4 || case_id == 5;
}

blockheads::ui::BlockheadFrame blockhead_frame_for(int case_id) {
    switch (case_id) {
        case 5: return {0.0f, 0.0f, 5.0f, 0.0f};
        case 6: return {20.0f, 0.0f, 0.0f, 0.0f};
        case 7: return {0.0f, 20.0f, 0.0f, 0.0f};
        default: return {};
    }
}

blockheads::ui::Point blockhead_point_for(int case_id) {
    switch (case_id) {
        case 1: return {120.0f, 0.0f};
        case 2: return {-120.0f, 0.0f};
        case 3: return {0.0f, -144.0f};
        case 4: return {0.0f, 142.0f};
        case 5: return {122.0f, 0.0f};
        case 6: return {137.0f, 0.0f};
        case 7: return {0.0f, 159.0f};
        default: return {0.0f, 0.0f};
    }
}

void blockhead_seeds(unsigned char* out, int which, int case_id) {
    ui_put_word(out, 176, 0x60001000u);      // windowInfo = self_ptr
    if (which == 80) {
        const auto f = blockhead_frame_for(case_id);
        ui_put_word(out, 8, float_bits(f.window_x));
        ui_put_word(out, 12, float_bits(f.window_y));
        ui_put_word(out, 184, float_bits(f.offset_x));
        ui_put_word(out, 188, float_bits(f.offset_y));
        return;
    }
    // 81..84: stopButtonDisplayed@76 + the five child pointers
    const bool sd = blockhead_sd(which, case_id);
    ui_put_word(out, 76, sd ? 1u : 0u);
    ui_put_word(out, 80, 0x60020600u);   // getWorkbenchButton
    ui_put_word(out, 96, 0x60020700u);   // nameEditButton
    ui_put_word(out, 92, 0x60020800u);   // stopButton
    ui_put_word(out, 84, 0x60020900u);   // sleepButton
    ui_put_word(out, 88, 0x60020A00u);   // meditateButton
}

blockheads::ui::BlockheadChildren blockhead_children_for(int case_id,
                                                         bool press,
                                                         bool sd) {
    blockheads::ui::BlockheadChildren c;
    c.stop_displayed = sd;
    const auto* yes = press ? &kChildHandles : &kChildInUi;
    if (case_id == 1 || case_id == 5) c.workbench = yes;
    if (case_id == 2) c.name_edit = yes;
    if (case_id == 3) c.stop = yes;
    if (case_id == 6) c.sleep = yes;
    if (case_id == 7) c.meditate = yes;
    return c;
}

// --- the constant-verdict panels' differential inputs ---------------------
// windowInfo = self_ptr (the dead rebase reads land in the instance); the
// constants themselves live in ui_touch_router.h.
int constant_panel_window_offset(int type_id) {
    return (type_id == 95 || type_id == 96) ? 128 : 96;  // MainMenuUI
}

void constant_panel_seeds(unsigned char* out, int type_id) {
    ui_put_word(out, constant_panel_window_offset(type_id), 0x60001000u);
    ui_put_word(out, 8, 0u);
    ui_put_word(out, 12, 0u);
}

int constant_panel_ret(int type_id) {
    switch (type_id) {
        case 85: return blockheads::ui::kMapUiRect ? 1 : 0;
        case 86: return blockheads::ui::kMapUiInUi ? 1 : 0;
        case 87: return blockheads::ui::kMapUiPress;
        case 90: return blockheads::ui::kOptionsUiRect ? 1 : 0;
        case 91: return blockheads::ui::kOptionsUiInUi ? 1 : 0;
        case 92: return blockheads::ui::kShareUiRect ? 1 : 0;
        case 93: return blockheads::ui::kShareUiInUi ? 1 : 0;
        case 94: return blockheads::ui::kPauseUiRect ? 1 : 0;
        case 95: return blockheads::ui::kMainMenuUiRect ? 1 : 0;
        case 96: return blockheads::ui::kMainMenuUiInUi ? 1 : 0;
        default: return 0;   // 88/89: the void stubs
    }
}

// --- the WorkbenchProgressBarUI panel's differential inputs ---------------
blockheads::ui::PanelFrame wpb_frame(int case_id) {
    switch (case_id) {
        case 5: return {0.0f, 0.0f, 5.0f, 0.0f};
        case 6: return {20.0f, 0.0f, 0.0f, 0.0f};
        default: return {};
    }
}

blockheads::ui::Point wpb_point(int case_id) {
    switch (case_id) {
        case 1: return {120.0f, 51.0f};
        case 2: return {-120.0f, 51.0f};
        case 3: return {0.0f, 0.0f};
        case 4: return {0.0f, 102.0f};
        case 5: return {122.0f, 51.0f};
        case 6: return {137.0f, 51.0f};
        default: return {0.0f, 51.0f};
    }
}

void wpb_seeds_for(unsigned char* out, int case_id) {
    ui_put_word(out, 96, 0x60001000u);       // windowInfo = self_ptr
    const auto f = wpb_frame(case_id);
    ui_put_word(out, 8, float_bits(f.window_x));
    ui_put_word(out, 12, float_bits(f.window_y));
    ui_put_word(out, 120, float_bits(f.offset_x));
    ui_put_word(out, 124, float_bits(f.offset_y));
}

// --- the CameraUI panel's differential inputs -----------------------------
void cam_seeds_for(unsigned char* out) {
    ui_put_word(out, 96, 0x60001000u);       // windowInfo = self_ptr
    ui_put_word(out, 8, 0u);
    ui_put_word(out, 12, 0u);
    ui_put_word(out, 104, 0x60020600u);      // cancelButton
    ui_put_word(out, 108, 0x60020700u);      // takePhotoButton
}

// --- the PetUI panel's differential inputs --------------------------------
blockheads::ui::PanelFrame pet_frame(int case_id) {
    switch (case_id) {
        case 5: return {0.0f, 0.0f, 5.0f, 0.0f};
        case 6: return {20.0f, 0.0f, 0.0f, 0.0f};
        default: return {};
    }
}

blockheads::ui::Point pet_point(int case_id) {
    switch (case_id) {
        case 1: return {120.0f, 49.0f};
        case 2: return {-120.0f, 49.0f};
        case 3: return {0.0f, -16.0f};
        case 4: return {0.0f, 114.0f};
        case 5: return {122.0f, 49.0f};
        case 6: return {137.0f, 49.0f};
        default: return {0.0f, 49.0f};
    }
}

void pet_seeds_for(unsigned char* out, int case_id) {
    ui_put_word(out, 128, 0x60001000u);      // windowInfo = self_ptr
    const auto f = pet_frame(case_id);
    ui_put_word(out, 8, float_bits(f.window_x));
    ui_put_word(out, 12, float_bits(f.window_y));
    ui_put_word(out, 136, float_bits(f.offset_x));
    ui_put_word(out, 140, float_bits(f.offset_y));
    ui_put_word(out, 52, 0x60020600u);       // nameEditButton
}

// --- the WearUI panel's differential inputs -------------------------------
struct WearFrame { float w, h; };

WearFrame wear_frame(int case_id) {
    switch (case_id) {
        case 6: return {100.0f, 50.0f};
        case 7: return {200.0f, 200.0f};
        default: return {200.0f, 100.0f};
    }
}

blockheads::ui::Point wear_point(int case_id) {
    switch (case_id) {
        case 1: return {100.0f, 49.0f};
        case 2: return {-100.0f, 49.0f};
        case 3: return {0.0f, 0.0f};
        case 4: return {0.0f, 84.0f};
        case 5: return {99.0f, 83.0f};
        case 6: return {50.0f, 25.0f};
        case 7: return {0.0f, 183.5f};
        default: return {0.0f, 49.0f};
    }
}

void wear_seeds_for(unsigned char* out, int case_id) {
    ui_put_word(out, 144, 0x60001000u);      // windowInfo = self_ptr
    ui_put_word(out, 8, 0u);
    ui_put_word(out, 12, 0u);
    ui_put_word(out, 152, 0u);
    ui_put_word(out, 156, 0u);
    const auto f = wear_frame(case_id);
    ui_put_word(out, 28, float_bits(f.w));   // frameSize (embedded)
    ui_put_word(out, 32, float_bits(f.h));
    ui_put_word(out, 60, 0x60020600u);       // wearButton
}

// --- the RegenerateUI panel's differential inputs -------------------------
constexpr unsigned REGEN_DB = 0x60020600u;
constexpr unsigned REGEN_CB = 0x60020700u;

blockheads::ui::Point regen_point(int case_id) {
    switch (case_id) {
        case 1: return {120.0f, 92.0f};
        case 2: return {-120.0f, 92.0f};
        case 3: return {0.0f, 0.0f};
        case 4: return {0.0f, 184.0f};
        case 5: return {119.0f, 183.0f};
        default: return {0.0f, 92.0f};
    }
}

// --- the AddCreditUI panel's differential inputs --------------------------
constexpr unsigned AC_CAN = 0x60020600u;
constexpr unsigned AC_WK = 0x60020700u;
constexpr unsigned AC_MO = 0x60020800u;

bool ac_in_progress(int which, int case_id) {
    return ((which == 144 || which == 145 || which == 146)
            && case_id == 1);
}

void ac_seeds_for(unsigned char* out, int which, int case_id) {
    ui_put_word(out, 112, 0x60001000u);
    ui_put_word(out, 8, 0u);
    ui_put_word(out, 12, 0u);
    ui_put_word(out, 128, AC_CAN);
    ui_put_word(out, 132, AC_WK);
    ui_put_word(out, 136, AC_MO);
    if (ac_in_progress(which, case_id)) ui_put_word(out, 160, 1u);
}

// --- the FreeOfferUI panel's differential inputs --------------------------
constexpr unsigned FOF_EX = 0x60020600u;
constexpr unsigned FOF_B0 = 0x60020700u;
constexpr unsigned FOF_B1 = 0x60020800u;
constexpr unsigned FOF_B2 = 0x60020900u;

void fof_seeds_for(unsigned char* out) {
    ui_put_word(out, 144, 0x60001000u);
    ui_put_word(out, 8, 0u);
    ui_put_word(out, 12, 0u);
    ui_put_word(out, 152, FOF_EX);
    ui_put_word(out, 36, FOF_B0);   // buyButton[0]
    ui_put_word(out, 40, FOF_B1);   // buyButton[1]
    ui_put_word(out, 44, FOF_B2);   // buyButton[2]
    ui_put_word(out, 156, 3u);      // offerCount
}

bool fof_exit_answers(int case_id) { return case_id == 1; }
int fof_buy_answers(int case_id) { return case_id == 2 ? 1 : -1; }

void fof_buys(int case_id, const blockheads::ui::ChildReply** out) {
    out[0] = &kChildMiss;
    out[1] = &kChildMiss;
    out[2] = &kChildMiss;
    const int hit = fof_buy_answers(case_id);
    if (hit >= 0) out[hit] = &kChildHandles;
}

// --- the InventoryFullUI panel's differential inputs ----------------------
blockheads::ui::Point inv_point(int case_id) {
    switch (case_id) {
        case 1: return {120.0f, 63.0f};
        case 2: return {-120.0f, 63.0f};
        case 3: return {0.0f, 0.0f};
        case 4: return {0.0f, 126.0f};
        case 5: return {119.0f, 125.0f};
        default: return {0.0f, 63.0f};
    }
}

void inv_seeds_for(unsigned char* out) {
    ui_put_word(out, 112, 0x60001000u);
    ui_put_word(out, 8, 0u);
    ui_put_word(out, 12, 0u);
    ui_put_word(out, 120, 0u);
    ui_put_word(out, 124, 0u);
}

// --- the SoundOptionsUI panel's differential inputs -----------------------
constexpr unsigned SND_OK = 0x60020600u;
constexpr unsigned SND_MU = 0x60020700u;
constexpr unsigned SND_SO = 0x60020800u;

void snd_seeds_for(unsigned char* out) {
    ui_put_word(out, 96, 0x60001000u);
    ui_put_word(out, 8, 0u);
    ui_put_word(out, 12, 0u);
    ui_put_word(out, 104, SND_OK);
    ui_put_word(out, 112, SND_MU);
    ui_put_word(out, 120, SND_SO);
}

// --- the TradingPostBuyUI panel's differential inputs ---------------------
constexpr unsigned TPB_SL = 0x60020600u;
constexpr unsigned TPB_BUY = 0x60020700u;

blockheads::ui::Point tpb_point(int case_id) {
    switch (case_id) {
        case 1: return {82.0f, 87.0f};
        case 2: return {-82.0f, 87.0f};
        case 3: return {0.0f, -16.0f};
        case 4: return {0.0f, 190.0f};
        case 5: return {81.0f, 189.0f};
        default: return {0.0f, 87.0f};
    }
}

bool tpb_gate_closed(int which, int case_id) {
    // 123/124 case 3 and 125/126 case 1 seed the closed byte
    if ((which == 123 || which == 124) && case_id == 3) return true;
    if ((which == 125 || which == 126) && case_id == 1) return true;
    return false;
}

void tpb_seeds_for(unsigned char* out, int case_id, int which) {
    ui_put_word(out, 144, 0x60001000u);
    ui_put_word(out, 8, 0u);
    ui_put_word(out, 12, 0u);
    ui_put_word(out, 152, 0u);
    ui_put_word(out, 156, 0u);
    ui_put_word(out, 164, TPB_SL);
    ui_put_word(out, 192, TPB_BUY);
    if (tpb_gate_closed(which, case_id)) {
        ui_put_word(out, 172, 1u);
    }
}

const blockheads::ui::ChildReply* tpb_child(int which, int slot,
                                            int case_id) {
    // 123/124: case 1 pins countSlider, case 2 pins buyButton. The inUI
    // answers through the in_ui family; the press and the inUI's
    // startTouch: fall-through both answer through the handles family.
    if ((which == 123 || which == 124) && case_id >= 1 && case_id <= 2) {
        if (slot == 0 && case_id == 1) {
            return (which == 124) ? &kChildHandles : &kChildInUi;
        }
        if (slot == 1 && case_id == 2) {
            return &kChildHandles;
        }
    }
    return &kChildMiss;
}

const blockheads::ui::ChildReply* regen_child(int which, int slot,
                                              int case_id) {
    // 118/119: case 1 pins dieButton, case 2 pins completeButton
    if ((which == 118 || which == 119) && case_id >= 1) {
        if (slot == 0 && case_id == 1) {
            return (which == 119) ? &kChildHandles : &kChildInUi;
        }
        if (slot == 1 && case_id == 2) {
            return (which == 119) ? &kChildHandles : &kChildInUi;
        }
    }
    return &kChildMiss;
}

const blockheads::ui::ChildReply* wear_child(int which, int case_id) {
    // 113/114: case 1 pins the child's reply
    if ((which == 113 || which == 114) && case_id == 1) {
        return (which == 114) ? &kChildHandles : &kChildInUi;
    }
    return &kChildMiss;
}

const blockheads::ui::ChildReply* pet_child(int which, int case_id) {
    // 108/109: case 1 pins the child's reply
    if ((which == 108 || which == 109) && case_id == 1) {
        return (which == 109) ? &kChildHandles : &kChildInUi;
    }
    return &kChildMiss;
}

const blockheads::ui::ChildReply* cam_child(int which, int slot,
                                            int case_id) {
    // 103/104: case 1 pins the cancelButton, case 2 the takePhotoButton;
    // 105/106 are void (the replies are unused)
    if (which == 103 || which == 104) {
        const auto* yes = (which == 104) ? &kChildHandles : &kChildInUi;
        if (case_id == 1 && slot == 0) return yes;
        if (case_id == 2 && slot == 1) return yes;
    }
    return &kChildMiss;
}
}  // namespace

extern "C" {
const char* recovered_ui_seq(int type_id, int case_id) {
    static thread_local std::string s;
    s.clear();
    if (type_id == 70) {  // MJControl -startTouch:
        Control c = ui_case_control(case_id);
        const auto o = blockheads::ui::control_start_touch(c,
                                                           ui_case_point(case_id));
        if (o.engaged) {
            s = "super(startTouch:),instance,multiSoundNamed:,play";
        }
    } else if (type_id == 72) {  // UIManager -startTouch:tapCount:index:
        // The router's FULL semantic model (ui_touch_router.h): the block
        // chain decoded from disasm_uimanager_starttouch.txt, walked with
        // the case's receiver replies (ui_router_case above). The trace's
        // selector sequence is what the ARM records — no case-fitted
        // strings remain.
        const auto trace = blockheads::ui::run_ui_router(
            ui_router_case(case_id), blockheads::ui::Point{50.0f, 50.0f});
        for (const char* c : trace.calls) {
            if (!s.empty()) s += ',';
            s += c;
        }
    } else if (type_id >= 73 && type_id <= 77) {  // the CraftUI panel methods
        // The panel's decoded semantics (ui_touch_router.h): 73 is the
        // own-rect test (no calls — the return is the artifact), 74/75 the
        // children OR in the SB, CB, CS order, 76/77 ALL THREE children in
        // the CB, CS, SB order.
        if (type_id != 73) {
            const auto t = craftui_trace(type_id, case_id);
            for (const char* c : t.calls) {
                if (!s.empty()) s += ',';
                s += c;
            }
        }
    } else if (type_id == 78) {
        // DPad -touchIsInUI: — the pure forward's one call
        s = "touchIsInViewAtAll:";
    } else if (type_id == 79) {
        // DPad -touchIsInViewAtAll: — the rotation's two PLT calls (the
        // rest of the body is direct .text helpers, not recorded)
        s = "import(sinf),import(cosf)";
    } else if (type_id == 80) {
        // BlockheadUI -touchIsInViewAtAll: — no calls (the rect test)
    } else if (type_id >= 81 && type_id <= 84) {
        // BlockheadUI's delegation chains (the trace's labels); 81 answers
        // via touchIsInUI:, 82 via the one-arg startTouch:, 83/84 void
        const bool press = (type_id == 82);
        const auto ch = blockhead_children_for(case_id, press,
                                               blockhead_sd(type_id, case_id));
        blockheads::ui::PanelTrace t;
        if (type_id == 81) {
            t = blockheads::ui::blockheadui_touch_is_in_ui(
                ch, blockheads::ui::Point{50.0f, 50.0f});
        } else if (type_id == 82) {
            t = blockheads::ui::blockheadui_start_touch(
                ch, blockheads::ui::Point{50.0f, 50.0f});
        } else if (type_id == 83) {
            t = blockheads::ui::blockheadui_move_touch(
                ch, blockheads::ui::Point{50.0f, 50.0f});
        } else {
            t = blockheads::ui::blockheadui_end_touch(
                ch, blockheads::ui::Point{50.0f, 50.0f});
        }
        for (const char* c : t.calls) {
            if (!s.empty()) s += ',';
            s += c;
        }
    } else if (type_id >= 85 && type_id <= 96) {
        // the constant-verdict panels: no calls (the literal verdicts)
    } else if (type_id >= 97 && type_id <= 101) {
        // the WorkbenchProgressBarUI panel: no calls (rect + constants)
    } else if (type_id >= 142 && type_id <= 146) {
        // the AddCreditUI panel: const rect/inUI + the gated triples
        const bool ip = ac_in_progress(type_id, case_id);
        blockheads::ui::PanelTrace t;
        if (type_id == 144) {
            t = blockheads::ui::addcredit_ui_start_touch(
                ip, &kChildMiss, &kChildMiss, &kChildMiss);
        } else if (type_id == 145) {
            t = blockheads::ui::addcredit_ui_move_touch(
                ip, &kChildMiss, &kChildMiss, &kChildMiss);
        } else if (type_id == 146) {
            t = blockheads::ui::addcredit_ui_end_touch(
                ip, &kChildMiss, &kChildMiss, &kChildMiss);
        }
        for (const char* c : t.calls) {
            if (!s.empty()) s += ',';
            s += c;
        }
    } else if (type_id >= 137 && type_id <= 141) {
        // the FreeOfferUI panel: const rect/inUI + the button walks
        const blockheads::ui::ChildReply* buys[3];
        fof_buys(case_id, buys);
        const auto* ex = fof_exit_answers(case_id) ? &kChildHandles
                                                   : &kChildMiss;
        blockheads::ui::PanelTrace t;
        if (type_id == 139) {
            t = blockheads::ui::freeofferui_start_touch(ex, buys, 3);
        } else if (type_id == 140) {
            t = blockheads::ui::freeofferui_move_touch(ex, buys, 3);
        } else if (type_id == 141) {
            t = blockheads::ui::freeofferui_end_touch(ex, buys, 3);
        }
        for (const char* c : t.calls) {
            if (!s.empty()) s += ',';
            s += c;
        }
    } else if (type_id >= 132 && type_id <= 136) {
        // the InventoryFullUI panel: no calls at all
    } else if (type_id >= 127 && type_id <= 131) {
        // the SoundOptionsUI panel: const rect/inUI + three-child chains
        blockheads::ui::PanelTrace t;
        if (type_id == 129) {
            t = blockheads::ui::soundoptionsui_start_touch(
                &kChildMiss, &kChildMiss, &kChildMiss);
        } else if (type_id == 130) {
            t = blockheads::ui::soundoptionsui_move_touch(
                &kChildMiss, &kChildMiss, &kChildMiss);
        } else if (type_id == 131) {
            t = blockheads::ui::soundoptionsui_end_touch(
                &kChildMiss, &kChildMiss, &kChildMiss);
        }
        for (const char* c : t.calls) {
            if (!s.empty()) s += ',';
            s += c;
        }
    } else if (type_id >= 122 && type_id <= 126) {
        // the TradingPostBuyUI panel: closed-gated chains (122 no calls)
        const bool closed = tpb_gate_closed(type_id, case_id);
        const auto* sl = tpb_child(type_id, 0, case_id);
        const auto* buy = tpb_child(type_id, 1, case_id);
        blockheads::ui::PanelTrace t;
        if (type_id == 123) {
            t = blockheads::ui::tpbuyui_touch_is_in_ui(closed, sl, buy);
        } else if (type_id == 124) {
            t = blockheads::ui::tpbuyui_start_touch(closed, sl, buy);
        } else if (type_id == 125) {
            t = blockheads::ui::tpbuyui_move_touch(closed, sl, buy);
        } else if (type_id == 126) {
            t = blockheads::ui::tpbuyui_end_touch(closed, sl, buy);
        }
        for (const char* c : t.calls) {
            if (!s.empty()) s += ',';
            s += c;
        }
    } else if (type_id >= 117 && type_id <= 121) {
        // the RegenerateUI panel: the two-button chains (117 no calls)
        const auto* db = regen_child(type_id, 0, case_id);
        const auto* cb = regen_child(type_id, 1, case_id);
        blockheads::ui::PanelTrace t;
        if (type_id == 118) {
            t = blockheads::ui::regenerateui_touch_is_in_ui(db, cb);
        } else if (type_id == 119) {
            t = blockheads::ui::regenerateui_start_touch(db, cb);
        } else if (type_id == 120) {
            t = blockheads::ui::regenerateui_move_touch(db, cb);
        } else if (type_id == 121) {
            t = blockheads::ui::regenerateui_end_touch(db, cb);
        }
        for (const char* c : t.calls) {
            if (!s.empty()) s += ',';
            s += c;
        }
    } else if (type_id >= 112 && type_id <= 116) {
        // the WearUI panel: the single-child chains (112 makes no calls)
        const auto* wb = wear_child(type_id, case_id);
        blockheads::ui::PanelTrace t;
        if (type_id == 113) {
            t = blockheads::ui::wearui_touch_is_in_ui(wb);
        } else if (type_id == 114) {
            t = blockheads::ui::wearui_start_touch(wb);
        } else if (type_id == 115) {
            t = blockheads::ui::wearui_move_touch(wb);
        } else if (type_id == 116) {
            t = blockheads::ui::wearui_end_touch(wb);
        }
        for (const char* c : t.calls) {
            if (!s.empty()) s += ',';
            s += c;
        }
    } else if (type_id >= 107 && type_id <= 111) {
        // the PetUI panel: the single-child chains (107 makes no calls)
        const auto* ne = pet_child(type_id, case_id);
        blockheads::ui::PanelTrace t;
        if (type_id == 108) {
            t = blockheads::ui::petui_touch_is_in_ui(ne);
        } else if (type_id == 109) {
            t = blockheads::ui::petui_start_touch(ne);
        } else if (type_id == 110) {
            t = blockheads::ui::petui_move_touch(ne);
        } else if (type_id == 111) {
            t = blockheads::ui::petui_end_touch(ne);
        }
        for (const char* c : t.calls) {
            if (!s.empty()) s += ',';
            s += c;
        }
    } else if (type_id >= 102 && type_id <= 106) {
        // the CameraUI panel: the two-button chains (102 makes no calls)
        const auto* cb = cam_child(type_id, 0, case_id);
        const auto* tpb = cam_child(type_id, 1, case_id);
        blockheads::ui::PanelTrace t;
        if (type_id == 103) {
            t = blockheads::ui::cameraui_touch_is_in_ui(cb, tpb);
        } else if (type_id == 104) {
            t = blockheads::ui::cameraui_start_touch(cb, tpb);
        } else if (type_id == 105) {
            t = blockheads::ui::cameraui_move_touch(cb, tpb);
        } else if (type_id == 106) {
            t = blockheads::ui::cameraui_end_touch(cb, tpb);
        }
        for (const char* c : t.calls) {
            if (!s.empty()) s += ',';
            s += c;
        }
    } else if (type_id == 71) {  // MJView -touchIsInUI: — the GATE cases
        // The frame test's coordinate space is still being decoded; the
        // gates are verified: hidden@4 short-circuits first, then
        // ignoreEvents@56, both answered from the instance.
        if (case_id == 0 || case_id == 1) {
            // empty subviews: the gates pass, then the enumeration's first
            // call (memset clears the state) returns nothing — the method
            // returns 0 without ever looking at the point.
            s = "hidden,ignoreEvents,import(memset),"
                "countByEnumeratingWithState:objects:count:";
        } else if (case_id == 2) {
            s = "hidden";
        } else if (case_id == 3) {
            s = "hidden,ignoreEvents";
        }
    }
    return s.c_str();
}

extern "C" int recovered_ui_img(int type_id, int case_id,
                                unsigned token_base, void* buf, int n) {
    (void)token_base;
    auto* out = static_cast<unsigned char*>(buf);
    if (n < 512) return -1;
    if (type_id == 72) {  // UIManager: the seeds + the @154 write
        std::memset(out, 0, static_cast<std::size_t>(n));
        ui_router_seeds(out, case_id);
        // the model's observable write: the currentTouchIsInAnyButtons@154
        // byte (a 0 write is a no-op on the zeroed image)
        const auto trace = blockheads::ui::run_ui_router(
            ui_router_case(case_id), blockheads::ui::Point{50.0f, 50.0f});
        if (trace.current_touch_is_in_any_buttons) out[154] = 1;
        return n;
    }
    if (type_id >= 73 && type_id <= 77) {  // CraftUI: the seeds only
        std::memset(out, 0, static_cast<std::size_t>(n));
        craftui_seeds(out, type_id, case_id);
        return n;
    }
    if (type_id == 78 || type_id == 79) {  // DPad: the base slots + frame
        std::memset(out, 0, static_cast<std::size_t>(n));
        ui_put_word(out, 4, 0x60000100u);
        ui_put_word(out, 8, 0x60000200u);
        if (type_id == 79) dpad_seeds(out, case_id);
        return n;
    }
    if (type_id >= 80 && type_id <= 84) {  // BlockheadUI: the base slots +
        std::memset(out, 0, static_cast<std::size_t>(n));  // the fixture
        ui_put_word(out, 4, 0x60000100u);
        ui_put_word(out, 8, 0x60000200u);
        blockhead_seeds(out, type_id, case_id);
        return n;
    }
    if (type_id >= 85 && type_id <= 96) {  // the constant-verdict panels
        std::memset(out, 0, static_cast<std::size_t>(n));
        ui_put_word(out, 4, 0x60000100u);
        ui_put_word(out, 8, 0x60000200u);
        constant_panel_seeds(out, type_id);
        return n;
    }
    if (type_id >= 97 && type_id <= 101) {  // WorkbenchProgressBarUI
        std::memset(out, 0, static_cast<std::size_t>(n));
        ui_put_word(out, 4, 0x60000100u);
        ui_put_word(out, 8, 0x60000200u);
        wpb_seeds_for(out, case_id);
        return n;
    }
    if (type_id >= 142 && type_id <= 146) {  // AddCreditUI
        std::memset(out, 0, static_cast<std::size_t>(n));
        ui_put_word(out, 4, 0x60000100u);
        ui_put_word(out, 8, 0u);
        ui_put_word(out, 12, 0u);
        ac_seeds_for(out, type_id, case_id);
        return n;
    }
    if (type_id >= 137 && type_id <= 141) {  // FreeOfferUI
        std::memset(out, 0, static_cast<std::size_t>(n));
        ui_put_word(out, 4, 0x60000100u);
        ui_put_word(out, 8, 0u);
        ui_put_word(out, 12, 0u);
        fof_seeds_for(out);
        return n;
    }
    if (type_id >= 132 && type_id <= 136) {  // InventoryFullUI
        std::memset(out, 0, static_cast<std::size_t>(n));
        ui_put_word(out, 4, 0x60000100u);
        ui_put_word(out, 8, 0u);
        ui_put_word(out, 12, 0u);
        inv_seeds_for(out);
        return n;
    }
    if (type_id >= 127 && type_id <= 131) {  // SoundOptionsUI
        std::memset(out, 0, static_cast<std::size_t>(n));
        ui_put_word(out, 4, 0x60000100u);
        ui_put_word(out, 8, 0u);
        ui_put_word(out, 12, 0u);
        snd_seeds_for(out);
        return n;
    }
    if (type_id >= 122 && type_id <= 126) {  // TradingPostBuyUI
        std::memset(out, 0, static_cast<std::size_t>(n));
        ui_put_word(out, 4, 0x60000100u);
        ui_put_word(out, 8, 0u);
        ui_put_word(out, 12, 0u);
        tpb_seeds_for(out, case_id, type_id);
        return n;
    }
    if (type_id >= 117 && type_id <= 121) {  // RegenerateUI
        std::memset(out, 0, static_cast<std::size_t>(n));
        ui_put_word(out, 4, 0x60000100u);
        ui_put_word(out, 8, 0u);             // window floats
        ui_put_word(out, 12, 0u);            // (offsets 8/12)
        ui_put_word(out, 96, 0x60001000u);
        ui_put_word(out, 120, static_cast<unsigned>(REGEN_DB));
        ui_put_word(out, 124, static_cast<unsigned>(REGEN_CB));
        return n;
    }
    if (type_id >= 112 && type_id <= 116) {  // WearUI
        std::memset(out, 0, static_cast<std::size_t>(n));
        ui_put_word(out, 4, 0x60000100u);
        ui_put_word(out, 8, 0x60000200u);
        wear_seeds_for(out, case_id);
        return n;
    }
    if (type_id >= 107 && type_id <= 111) {  // PetUI
        std::memset(out, 0, static_cast<std::size_t>(n));
        ui_put_word(out, 4, 0x60000100u);
        ui_put_word(out, 8, 0x60000200u);
        pet_seeds_for(out, case_id);
        return n;
    }
    if (type_id >= 102 && type_id <= 106) {  // CameraUI
        std::memset(out, 0, static_cast<std::size_t>(n));
        ui_put_word(out, 4, 0x60000100u);
        ui_put_word(out, 8, 0x60000200u);
        cam_seeds_for(out);
        return n;
    }
    if (type_id == 71) {  // MJView: the gate cases write nothing
        std::memset(out, 0, static_cast<std::size_t>(n));
        ui_put_word(out, 4, 0x60000100u);    // the harness's base slots
        ui_put_word(out, 8, 0x60000200u);
        ui_put_word(out, 8, 0u);
        ui_put_word(out, 12, 0u);
        ui_put_word(out, 16, 0x42C80000u);   // frame (0,0,100,100)
        ui_put_word(out, 20, 0x42C80000u);
        ui_put_word(out, 52, 0x6000F000u);   // windowInfo (the zero region)
        // the seeds land as whole-word writes (the harness's --seed), so
        // they override the base slot at @4 exactly as on the ARM side
        ui_put_word(out, 4, (case_id == 2) ? 1u : 0u);   // hidden@4
        if (case_id == 3) out[56] = 1;       // ignoreEvents@56
        (void)case_id;
        return n;
    }
    if (type_id != 70) return -1;
    std::memset(out, 0, static_cast<std::size_t>(n));
    // the same seed the harness writes into the ARM instance
    ui_put_word(out, 4, 0x60000100u);                  // the base slots
    ui_put_word(out, 8, 0x60000200u);
    ui_put_word(out, 60, 0x60030000u);                 // target@60
    out[71] = (case_id != 2) ? 1 : 0;                  // enabled@71
    ui_put_word(out, 88, 0x42C80000u);                 // eventFrame (0,0,100,100)
    ui_put_word(out, 92, 0x42C80000u);
    Control c = ui_case_control(case_id);
    const auto o = blockheads::ui::control_start_touch(c,
                                                       ui_case_point(case_id));
    if (o.engaged) {
        out[68] = c.hover ? 1 : 0;                     // hover@68
        out[70] = c.received_touch_start ? 1 : 0;      // receivedTouchStart@70
        ui_put_word(out, 96, 0x3F800000u);             // the timer float = 1.0
    }
    return n;
}

int recovered_ui_ret(int type_id, int case_id) {
    if (type_id == 72) {
        return blockheads::ui::run_ui_router(
            ui_router_case(case_id),
            blockheads::ui::Point{50.0f, 50.0f}).handled;
    }
    if (type_id == 73) {
        return blockheads::ui::craftui_touch_is_in_view_at_all(
            craftui_point(case_id), craftui_frame(case_id)) ? 1 : 0;
    }
    if (type_id == 74 || type_id == 75) {
        return craftui_trace(type_id, case_id).handled;
    }
    if (type_id == 76 || type_id == 77) return 0;  // void (not compared)
    if (type_id == 78) {  // the forward: the fixture's reply on self
        return blockheads::ui::dpad_touch_is_in_ui(case_id == 1) ? 1 : 0;
    }
    if (type_id == 79) {
        return blockheads::ui::dpad_touch_is_in_view_at_all(
            dpad_point_for(case_id), dpad_frame_for(case_id)) ? 1 : 0;
    }
    if (type_id == 80) {
        return blockheads::ui::blockheadui_touch_is_in_view_at_all(
            blockhead_point_for(case_id),
            blockhead_frame_for(case_id)) ? 1 : 0;
    }
    if (type_id == 81) {
        return blockheads::ui::blockheadui_touch_is_in_ui(
            blockhead_children_for(case_id, false,
                                   blockhead_sd(type_id, case_id)),
            blockheads::ui::Point{50.0f, 50.0f}).handled;
    }
    if (type_id == 82) {
        return blockheads::ui::blockheadui_start_touch(
            blockhead_children_for(case_id, true,
                                   blockhead_sd(type_id, case_id)),
            blockheads::ui::Point{50.0f, 50.0f}).handled;
    }
    if (type_id == 83 || type_id == 84) return 0;  // void (not compared)
    if (type_id >= 85 && type_id <= 96) return constant_panel_ret(type_id);
    if (type_id == 97) {
        return blockheads::ui::wbpbarui_touch_is_in_view_at_all(
            wpb_point(case_id), wpb_frame(case_id)) ? 1 : 0;
    }
    if (type_id == 98) return blockheads::ui::kWorkbenchProgressBarInUi ? 1 : 0;
    if (type_id == 99) return blockheads::ui::kWorkbenchProgressBarPress;
    if (type_id == 100 || type_id == 101) return 0;  // void (not compared)
    if (type_id == 102) return blockheads::ui::kCameraUiRect ? 1 : 0;
    if (type_id == 103) {
        return blockheads::ui::cameraui_touch_is_in_ui(
            cam_child(103, 0, case_id), cam_child(103, 1, case_id)).handled;
    }
    if (type_id == 104) {
        return blockheads::ui::cameraui_start_touch(
            cam_child(104, 0, case_id), cam_child(104, 1, case_id)).handled;
    }
    if (type_id == 105 || type_id == 106) return 0;  // void (not compared)
    if (type_id == 107) {
        return blockheads::ui::petui_touch_is_in_view_at_all(
            pet_point(case_id), pet_frame(case_id)) ? 1 : 0;
    }
    if (type_id == 108) {
        return blockheads::ui::petui_touch_is_in_ui(
            pet_child(108, case_id)).handled;
    }
    if (type_id == 109) {
        return blockheads::ui::petui_start_touch(
            pet_child(109, case_id)).handled;
    }
    if (type_id == 110 || type_id == 111) return 0;  // void (not compared)
    if (type_id == 112) {
        const auto f = wear_frame(case_id);
        return blockheads::ui::wearui_touch_is_in_view_at_all(
            wear_point(case_id), {}, f.w, f.h) ? 1 : 0;
    }
    if (type_id == 113) {
        return blockheads::ui::wearui_touch_is_in_ui(
            wear_child(113, case_id)).handled;
    }
    if (type_id == 114) {
        return blockheads::ui::wearui_start_touch(
            wear_child(114, case_id)).handled;
    }
    if (type_id == 115 || type_id == 116) return 0;  // void (not compared)
    if (type_id == 117) {
        return blockheads::ui::regenerateui_touch_is_in_view_at_all(
            regen_point(case_id), {}) ? 1 : 0;
    }
    if (type_id == 118) {
        return blockheads::ui::regenerateui_touch_is_in_ui(
            regen_child(118, 0, case_id), regen_child(118, 1, case_id))
            .handled;
    }
    if (type_id == 119) {
        return blockheads::ui::regenerateui_start_touch(
            regen_child(119, 0, case_id), regen_child(119, 1, case_id))
            .handled;
    }
    if (type_id == 120 || type_id == 121) return 0;  // void (not compared)
    if (type_id == 122) {
        return blockheads::ui::tpbuyui_touch_is_in_view_at_all(
            tpb_point(case_id), {}) ? 1 : 0;
    }
    if (type_id == 123) {
        return blockheads::ui::tpbuyui_touch_is_in_ui(
            tpb_gate_closed(123, case_id), tpb_child(123, 0, case_id),
            tpb_child(123, 1, case_id)).handled;
    }
    if (type_id == 124) {
        return blockheads::ui::tpbuyui_start_touch(
            tpb_gate_closed(124, case_id), tpb_child(124, 0, case_id),
            tpb_child(124, 1, case_id)).handled;
    }
    if (type_id >= 125 && type_id <= 126) return 0;  // void (not compared)
    if (type_id == 127) {
        return blockheads::ui::kSoundOptionsUiRect ? 1 : 0;
    }
    if (type_id == 128) {
        return blockheads::ui::kSoundOptionsUiInUi;
    }
    if (type_id == 129) {
        return blockheads::ui::soundoptionsui_start_touch(
            &kChildMiss, &kChildMiss, &kChildMiss).handled;
    }
    if (type_id == 130 || type_id == 131) return 0;  // void (not compared)
    if (type_id == 132) {
        return blockheads::ui::inventoryfullui_touch_is_in_view_at_all(
            inv_point(case_id), {}) ? 1 : 0;
    }
    if (type_id == 133) return blockheads::ui::kInventoryFullUiInUi;
    if (type_id == 134) return blockheads::ui::kInventoryFullUiPress;
    if (type_id == 135 || type_id == 136) return 0;  // void (not compared)
    if (type_id == 137) return blockheads::ui::kFreeOfferUiRect ? 1 : 0;
    if (type_id == 138) return blockheads::ui::kFreeOfferUiInUi;
    if (type_id == 139) {
        const blockheads::ui::ChildReply* buys[3];
        fof_buys(case_id, buys);
        const auto* ex = fof_exit_answers(case_id) ? &kChildHandles
                                                   : &kChildMiss;
        return blockheads::ui::freeofferui_start_touch(ex, buys, 3).handled;
    }
    if (type_id == 140 || type_id == 141) return 0;  // void (not compared)
    if (type_id == 142) return blockheads::ui::kAddCreditUiRect ? 1 : 0;
    if (type_id == 143) return blockheads::ui::kAddCreditUiInUi;
    if (type_id == 144) {
        return blockheads::ui::addcredit_ui_start_touch(
            ac_in_progress(144, case_id), &kChildMiss, &kChildMiss,
            &kChildMiss).handled;
    }
    if (type_id == 145 || type_id == 146) return 0;  // void (not compared)
    if (type_id == 71) return 0;             // the gate cases return 0
    if (type_id != 70) return -1;
    Control c = ui_case_control(case_id);
    const auto o = blockheads::ui::control_start_touch(c,
                                                       ui_case_point(case_id));
    return o.engaged ? 1 : 0;
}

}  // extern "C"
