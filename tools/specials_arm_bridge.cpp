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

const ClassRows kClasses[] = {
    {42, kSteamTrain, 4, nullptr, "", false, 0, 0, 0},
    {60, kOwnershipSign, 4, nullptr, "updateText", true, 15, 1, 30},
    {52, kPainting, 5, "initSubDerivedItems", "initSubDerivedItems", false, 0, 0, 0},
    {25, kDropBear, 9, "loadDerivedStuff",
     "loadDerivedStuff,removeFromMacroBlock,release", false, 0, 0, 0},
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
    if (case_id == 2) return buffer.c_str();   // nil guard: nothing else runs
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

}  // extern "C"
