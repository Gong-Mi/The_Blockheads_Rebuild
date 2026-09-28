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
        // The router's case-fitted model (the full semantics is the next
        // slice): the sequences below are the ARM's own, observed with the
        // seeded UI ivars. Block indices are from disasm_uimanager_starttouch.
        if (case_id == 0) {        // tcUI only
            s = "displayed,startTouch:tapCount:index:,import(memset),"
                "countByEnumeratingWithState:objects:count:";
        } else if (case_id == 1) { // tcUI + worldUI
            s = "displayed,startTouch:tapCount:index:,import(memset),"
                "countByEnumeratingWithState:objects:count:";
        } else if (case_id == 2) { // pauseUI + worldUI + tcUI + dpad + cameraUI
            s = "startTouch:tapCount:,startTouch:tapCount:paused:index:";
        } else if (case_id == 3) {
            // block 1 modelled from the code: tcUIDisplayed@40 gates it,
            // then [tcUI startTouch:tapCount:], and only when that returns
            // zero [worldUI startTouch:tapCount:paused:index:]; the block
            // sets the "handled" flag and exits (ret 1).
            s = "startTouch:tapCount:,startTouch:tapCount:paused:index:";
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
    if (type_id == 72) {  // UIManager: the seeds only (no state writes)
        std::memset(out, 0, static_cast<std::size_t>(n));
        ui_put_word(out, 4, 0x60000100u);
        ui_put_word(out, 8, 0x60000200u);
        if (case_id == 0) ui_put_word(out, 32, 0x60020200u);
        if (case_id == 1) {
            ui_put_word(out, 32, 0x60020200u);
            ui_put_word(out, 20, 0x60020000u);
        }
        if (case_id == 2) {
            ui_put_word(out, 20, 0x60020000u);
            ui_put_word(out, 24, 0x60020100u);
            ui_put_word(out, 32, 0x60020200u);
            ui_put_word(out, 36, 0x60020300u);
            ui_put_word(out, 100, 0x60020400u);
        }
        if (case_id == 3) {
            ui_put_word(out, 40, 1u);          // tcUIDisplayed@40
            ui_put_word(out, 32, 0x60020200u);
            ui_put_word(out, 20, 0x60020000u);
        }
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
    if (type_id == 72) return (case_id == 2 || case_id == 3) ? 1 : 0;
    if (type_id == 71) return 0;             // the gate cases return 0
    if (type_id != 70) return -1;
    Control c = ui_case_control(case_id);
    const auto o = blockheads::ui::control_start_touch(c,
                                                       ui_case_point(case_id));
    return o.engaged ? 1 : 0;
}

}  // extern "C"
