// Contract test for the recovered NPC loadValuesFromSaveDict: slice
// (reconstruction/recovered/npc_load_values_from_save_dict.cpp). Runs in
// CTest so CI exercises the contract without needing the original ELF.
//
// The expectations below are the same cases the ARM differential
// (tools/test_npc_loadvalues_arm.py) executes against the original
// instructions; keep the two in sync.
#include "npc_load_values_from_save_dict.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

using blockheads::recovered::NpcLoadCall;
using blockheads::recovered::NpcLoadKey;
using blockheads::recovered::NpcLoadValuesInputs;
using blockheads::recovered::NpcLoadValuesResult;
using blockheads::recovered::kNpcLoadDictCopyToken;
using blockheads::recovered::npc_load_values_run;

int failures = 0;

void expect(bool condition, const char* what) {
    if (!condition) {
        std::printf("FAIL: %s\n", what);
        ++failures;
    }
}

std::uint32_t word_at(const NpcLoadValuesResult& r, std::size_t off) {
    std::uint32_t v = 0;
    std::memcpy(&v, &r.image[off], sizeof(v));
    return v;
}

std::uint16_t half_at(const NpcLoadValuesResult& r, std::size_t off) {
    std::uint16_t v = 0;
    std::memcpy(&v, &r.image[off], sizeof(v));
    return v;
}

bool has_call(const NpcLoadValuesResult& r, NpcLoadCall code) {
    for (const auto c : r.calls) {
        if (c == code) {
            return true;
        }
    }
    return false;
}

NpcLoadValuesInputs make_all_present() {
    NpcLoadValuesInputs in;
    for (int i = 0; i < static_cast<int>(NpcLoadKey::Count); ++i) {
        in.present[i] = true;
    }
    in.bits[static_cast<int>(NpcLoadKey::Fullness)] = 0x3F8CCCCDu;  // 1.1f
    in.bits[static_cast<int>(NpcLoadKey::LayTimer)] = 0x41200000u;  // 10.0f
    in.bits[static_cast<int>(NpcLoadKey::Damage)] = 70000;
    in.bits[static_cast<int>(NpcLoadKey::Age)] = 0x42200000u;       // 40.0f
    in.bits[static_cast<int>(NpcLoadKey::LayCooldownTimer)] = 0x3FC00000u;
    in.bits[static_cast<int>(NpcLoadKey::TameCooldownTimer)] = 0x40200000u;
    in.bits[static_cast<int>(NpcLoadKey::MateCooldownTimer)] = 0x40600000u;
    in.bits[static_cast<int>(NpcLoadKey::HasBred)] = 1;
    in.bits[static_cast<int>(NpcLoadKey::HasBeenFedByBlockheadOrChest)] = 1;
    in.bits[static_cast<int>(NpcLoadKey::MateBreed)] = 0xFFFFFFFFu;  // -1
    in.bits[static_cast<int>(NpcLoadKey::Breed)] = 0x12345678u;
    in.bits[static_cast<int>(NpcLoadKey::TamedClientID)] = 0x51CE0001u;
    in.bits[static_cast<int>(NpcLoadKey::Name)] = 0x51CE0002u;
    in.bits[static_cast<int>(NpcLoadKey::TameCountsByClientID)] = 0x51CE0003u;
    in.bits[static_cast<int>(NpcLoadKey::CurrentBlockheadIndex)] = 7;
    return in;
}

}  // namespace

int main() {
    // Case 1: everything present, old name/tameCounts nil. Full trace:
    // probe+read pairs for the gated groups, the ungated taming block with
    // the dictionary copy, and the -1 default overwritten by intValue.
    {
        const NpcLoadValuesResult r = npc_load_values_run(make_all_present());
        expect(word_at(r, 68) == 0x3F8CCCCDu, "fullness@68 = 1.1f bits");
        expect(word_at(r, 80) == 0x41200000u, "layTimer@80 = 10.0f bits");
        expect(half_at(r, 54) == 4464, "damage@54 strh truncates 70000");
        expect(word_at(r, 88) == 0x42200000u, "age@88 = 40.0f bits");
        expect(word_at(r, 84) == 0x3FC00000u, "layCooldownTimer@84");
        expect(word_at(r, 72) == 0x40200000u, "tameCooldownTimer@72");
        expect(word_at(r, 76) == 0x40600000u, "mateCooldownTimer@76");
        expect(r.image[100] == 1, "hasBred@100 byte");
        expect(r.image[101] == 1, "hasBeenFed@101 byte");
        expect(half_at(r, 98) == 0xFFFFu, "mateBreed@98 strh keeps -1 low bits");
        expect(half_at(r, 96) == 0x5678u, "breed@96 strh truncates 0x12345678");
        expect(word_at(r, 108) == 0x51CE0001u, "tamedClientID@108 word");
        expect(word_at(r, 92) == 0x51CE0002u, "name@92 word");
        expect(word_at(r, 104) == kNpcLoadDictCopyToken,
               "tameCounts@104 = dictionary copy token");
        expect(word_at(r, 136) == 7u, "savedBlockheadIndex@136 = intValue");
        // Trace: 37 calls when all present
        // (group1 9 + group2 13 + breed 3 + tamedClientID 2 + name 3 +
        //  tameCounts 4 + currentBlockheadIndex 3).
        expect(r.calls.size() == 37, "all-present trace has 37 calls");
        expect(r.calls.front() == NpcLoadCall::ObjectForKeyFullness,
               "first call is the fullness probe");
        expect(r.calls.back() == NpcLoadCall::IntValue,
               "last call is currentBlockheadIndex intValue");
        expect(has_call(r, NpcLoadCall::DictionaryWithDictionary),
               "dictionary copy call present");
        expect(has_call(r, NpcLoadCall::Autorelease),
               "old-value autoreleases present");
    }

    // Case 3 analog: fullness absent -> the WHOLE first group is skipped,
    // even though layTimer/damage/age are present in the dictionary.
    {
        NpcLoadValuesInputs in = make_all_present();
        in.present[static_cast<int>(NpcLoadKey::Fullness)] = false;
        const NpcLoadValuesResult r = npc_load_values_run(in);
        expect(word_at(r, 68) == 0, "no fullness -> @68 untouched");
        expect(word_at(r, 80) == 0, "no fullness -> layTimer not read back");
        expect(half_at(r, 54) == 0, "no fullness -> damage not read back");
        expect(word_at(r, 88) == 0, "no fullness -> age not read back");
        expect(!has_call(r, NpcLoadCall::ObjectForKeyLayTimer),
               "no fullness -> no layTimer lookup in the trace");
        // Later groups still ran.
        expect(word_at(r, 84) == 0x3FC00000u, "group 2 still loaded");
        expect(word_at(r, 136) == 7u, "currentBlockheadIndex still loaded");
    }

    // Case 6 analog: currentBlockheadIndex absent -> the -1 default store
    // survives (full-word 0xffffffff, not a halfword truncation).
    {
        NpcLoadValuesInputs in = make_all_present();
        in.present[static_cast<int>(NpcLoadKey::CurrentBlockheadIndex)] = false;
        const NpcLoadValuesResult r = npc_load_values_run(in);
        expect(word_at(r, 136) == 0xFFFFFFFFu, "absent index -> -1 default");
    }

    // Case 7 analog: tameCountsByClientID absent -> no dictionary copy, the
    // ivar ends nil, but tamedClientID/name are still stored.
    {
        NpcLoadValuesInputs in = make_all_present();
        in.present[static_cast<int>(NpcLoadKey::TameCountsByClientID)] = false;
        const NpcLoadValuesResult r = npc_load_values_run(in);
        expect(word_at(r, 104) == 0, "no tameCounts -> @104 nil");
        expect(!has_call(r, NpcLoadCall::DictionaryWithDictionary),
               "no tameCounts -> no dictionaryWithDictionary:");
        expect(word_at(r, 108) == 0x51CE0001u, "tamedClientID still stored");
        expect(word_at(r, 92) == 0x51CE0002u, "name still stored");
    }

    if (failures == 0) {
        std::printf("recovered_npc_load_values: PASS\n");
    }
    return failures == 0 ? 0 : 1;
}
