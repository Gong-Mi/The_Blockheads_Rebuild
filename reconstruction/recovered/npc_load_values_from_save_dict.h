// Recovered semantics of -[NPC loadValuesFromSaveDict:]
// (0x00643b20, 603 words) — the NPC state load that the b3g/b4a loader calls
// via [self loadValuesFromSaveDict:saveDict].
//
// Decoded from the pinned ARM binary (batch b3n) and verified bit-exactly
// against the original instructions executed under Unicorn
// (tools/test_npc_loadvalues_arm.py, batch b4f):
//
//   G1 (probe objectForKey:"fullness" != nil) gates the group
//      { fullness@68   word    (floatValue, vstr)
//        layTimer@80   word    (floatValue, vstr)
//        damage@54     halfword(intValue,   strh — truncates to 16 bits)
//        age@88        word    (floatValue, vstr) }
//      The probe key is looked up AGAIN inside the group, so a present
//      layTimer/damage/age is NOT read back when fullness is absent.
//   G2 (probe objectForKey:"layCooldownTimer" != nil) gates the group
//      { layCooldownTimer@84 word (floatValue)
//        tameCooldownTimer@72 word, mateCooldownTimer@76 word,
//        hasBred@100 byte, hasBeenFedByBlockheadOrChest@101 byte (boolValue),
//        mateBreed@98 halfword (intValue, strh truncation) }
//   G3 (probe objectForKey:"breed" != nil) gates
//      { breed@96 halfword (unsignedIntegerValue, strh truncation) }
//   Ungated block (ALWAYS runs, even for a missing key — nil is stored):
//      tamedClientID@108 = retain(objectForKey:"tamedClientID")   (may be nil)
//      [old name autorelease]; name@92 = retain(objectForKey:"name")
//      [old tameCountsByClientID autorelease]; tameCountsByClientID@104 = nil
//      if objectForKey:"tameCountsByClientID" != nil:
//          tameCountsByClientID@104 =
//              retain([NSMutableDictionary dictionaryWithDictionary:dict])
//   savedBlockheadIndex@136 = -1 unconditionally, then
//   G4 (probe objectForKey:"currentBlockheadIndex" != nil) may overwrite it
//      with intValue (full word store).
//
// This module is a contract for that slice only. It is not Foundation, not
// the original-app runtime, and not a replacement for the whole method: the
// save dictionary, the boxed values, retain/autorelease bookkeeping and the
// mutable-dictionary copy live outside this contract (the harness models
// them synthetically; the copy is represented by the fixed token
// kNpcLoadDictCopyToken agreed between the harness stub and this module).
#pragma once

#include <cstdint>
#include <vector>

namespace blockheads::recovered {

// Fixed token the synthetic dictionaryWithDictionary: stub returns (and
// retain passes through) in the ARM harness; the contract stores the same
// value so the memory images compare byte-for-byte.
inline constexpr std::uint32_t kNpcLoadDictCopyToken = 0x00D1C700u;

// Size of the zero-initialised instance image the contract fills in. The
// highest store is savedBlockheadIndex@136 (+4), so 160 covers every write.
inline constexpr std::size_t kNpcLoadImageSize = 160;
inline constexpr std::size_t kNpcLoadMaxTrace = 64;

enum class NpcLoadKey : int {
    Fullness = 0,
    LayTimer,
    Damage,
    Age,
    LayCooldownTimer,
    TameCooldownTimer,
    MateCooldownTimer,
    HasBred,
    HasBeenFedByBlockheadOrChest,
    MateBreed,
    Breed,
    TamedClientID,
    Name,
    TameCountsByClientID,
    CurrentBlockheadIndex,
    Count
};

// Call-trace codes, one per (selector, key) semantic site. Conversion codes
// are generic (FloatValue/IntValue/...); the position in the sequence
// disambiguates which key they convert.
enum class NpcLoadCall : std::uint8_t {
    ObjectForKeyFullness = 0,
    ObjectForKeyLayTimer,
    ObjectForKeyDamage,
    ObjectForKeyAge,
    ObjectForKeyLayCooldownTimer,
    ObjectForKeyTameCooldownTimer,
    ObjectForKeyMateCooldownTimer,
    ObjectForKeyHasBred,
    ObjectForKeyHasBeenFedByBlockheadOrChest,
    ObjectForKeyMateBreed,
    ObjectForKeyBreed,
    ObjectForKeyTamedClientID,
    Retain,
    Autorelease,
    ObjectForKeyName,
    ObjectForKeyTameCountsByClientID,
    DictionaryWithDictionary,
    ObjectForKeyCurrentBlockheadIndex,
    FloatValue,
    IntValue,
    BoolValue,
    UnsignedIntegerValue,
};

struct NpcLoadValuesInputs {
    // Per-key presence in the save dictionary (probe result != nil).
    bool present[static_cast<int>(NpcLoadKey::Count)] = {};
    // Per-key payload, fixed interpretation per key kind:
    //   float keys (Fullness, LayTimer, Age, LayCooldownTimer,
    //               TameCooldownTimer, MateCooldownTimer): IEEE-754 bits
    //   int keys   (Damage, MateBreed, CurrentBlockheadIndex): int32 bits
    //   bool keys  (HasBred, HasBeenFedByBlockheadOrChest): 0/1
    //   uint key   (Breed): uint32 bits
    //   object keys(TamedClientID, Name, TameCountsByClientID): object token
    // In the ARM harness object payloads are the boxed-value addresses and
    // the tame-counts copy stores kNpcLoadDictCopyToken, so both sides agree.
    std::uint32_t bits[static_cast<int>(NpcLoadKey::Count)] = {};
    // Initial contents of the name@92 / tameCountsByClientID@104 ivars (0 =
    // nil). Only the autorelease calls observe them; both are overwritten or
    // cleared by the body on every path.
    std::uint32_t old_name = 0;
    std::uint32_t old_tame_counts = 0;
};

struct NpcLoadValuesResult {
    // Zero-initialised instance memory with the decoded stores applied at
    // their exact widths (little-endian, as the ARM str/strh/strb/vstr left
    // them). Bytes no store touched stay zero.
    std::uint8_t image[kNpcLoadImageSize] = {};
    std::vector<NpcLoadCall> calls;
};

NpcLoadValuesResult npc_load_values_run(const NpcLoadValuesInputs& inputs);

}  // namespace blockheads::recovered
