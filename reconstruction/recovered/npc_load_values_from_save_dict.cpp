#include "npc_load_values_from_save_dict.h"

#include <cstring>

namespace blockheads::recovered {

namespace {

using Key = NpcLoadKey;

void store_word(std::uint8_t* image, std::size_t offset, std::uint32_t value) {
    std::memcpy(image + offset, &value, sizeof(value));
}

void store_halfword(std::uint8_t* image, std::size_t offset, std::uint32_t value) {
    const std::uint16_t truncated = static_cast<std::uint16_t>(value & 0xffffu);
    std::memcpy(image + offset, &truncated, sizeof(truncated));
}

void store_byte(std::uint8_t* image, std::size_t offset, std::uint32_t value) {
    image[offset] = static_cast<std::uint8_t>(value & 0xffu);
}

}  // namespace

NpcLoadValuesResult npc_load_values_run(const NpcLoadValuesInputs& inputs) {
    NpcLoadValuesResult result;
    const bool* present = inputs.present;
    const std::uint32_t* bits = inputs.bits;
    auto& calls = result.calls;
    std::uint8_t* image = result.image;

    // ---- Group 1: gated by the fullness probe (0x643b70 -> beq 0x643d34).
    calls.push_back(NpcLoadCall::ObjectForKeyFullness);
    if (present[static_cast<int>(Key::Fullness)]) {
        calls.push_back(NpcLoadCall::ObjectForKeyFullness);
        calls.push_back(NpcLoadCall::FloatValue);
        store_word(image, 68, bits[static_cast<int>(Key::Fullness)]);

        calls.push_back(NpcLoadCall::ObjectForKeyLayTimer);
        calls.push_back(NpcLoadCall::FloatValue);
        store_word(image, 80, bits[static_cast<int>(Key::LayTimer)]);

        calls.push_back(NpcLoadCall::ObjectForKeyDamage);
        calls.push_back(NpcLoadCall::IntValue);
        store_halfword(image, 54, bits[static_cast<int>(Key::Damage)]);

        calls.push_back(NpcLoadCall::ObjectForKeyAge);
        calls.push_back(NpcLoadCall::FloatValue);
        store_word(image, 88, bits[static_cast<int>(Key::Age)]);
    }

    // ---- Group 2: gated by the layCooldownTimer probe
    //      (0x643d70 -> beq 0x644008).
    calls.push_back(NpcLoadCall::ObjectForKeyLayCooldownTimer);
    if (present[static_cast<int>(Key::LayCooldownTimer)]) {
        calls.push_back(NpcLoadCall::ObjectForKeyLayCooldownTimer);
        calls.push_back(NpcLoadCall::FloatValue);
        store_word(image, 84, bits[static_cast<int>(Key::LayCooldownTimer)]);

        calls.push_back(NpcLoadCall::ObjectForKeyTameCooldownTimer);
        calls.push_back(NpcLoadCall::FloatValue);
        store_word(image, 72, bits[static_cast<int>(Key::TameCooldownTimer)]);

        calls.push_back(NpcLoadCall::ObjectForKeyMateCooldownTimer);
        calls.push_back(NpcLoadCall::FloatValue);
        store_word(image, 76, bits[static_cast<int>(Key::MateCooldownTimer)]);

        calls.push_back(NpcLoadCall::ObjectForKeyHasBred);
        calls.push_back(NpcLoadCall::BoolValue);
        store_byte(image, 100, bits[static_cast<int>(Key::HasBred)]);

        calls.push_back(NpcLoadCall::ObjectForKeyHasBeenFedByBlockheadOrChest);
        calls.push_back(NpcLoadCall::BoolValue);
        store_byte(image, 101,
                   bits[static_cast<int>(Key::HasBeenFedByBlockheadOrChest)]);

        calls.push_back(NpcLoadCall::ObjectForKeyMateBreed);
        calls.push_back(NpcLoadCall::IntValue);
        store_halfword(image, 98, bits[static_cast<int>(Key::MateBreed)]);
    }

    // ---- breed: own probe (0x644044 -> beq 0x6440d0).
    calls.push_back(NpcLoadCall::ObjectForKeyBreed);
    if (present[static_cast<int>(Key::Breed)]) {
        calls.push_back(NpcLoadCall::ObjectForKeyBreed);
        calls.push_back(NpcLoadCall::UnsignedIntegerValue);
        store_halfword(image, 96, bits[static_cast<int>(Key::Breed)]);
    }

    // ---- Ungated taming block: runs even when the keys are absent (nil is
    //      stored). tamedClientID first, then the name swap, then the
    //      tameCounts swap with the dictionary copy.
    calls.push_back(NpcLoadCall::ObjectForKeyTamedClientID);
    calls.push_back(NpcLoadCall::Retain);
    store_word(image, 108,
               present[static_cast<int>(Key::TamedClientID)]
                   ? bits[static_cast<int>(Key::TamedClientID)]
                   : 0u);

    calls.push_back(NpcLoadCall::Autorelease);  // old name
    calls.push_back(NpcLoadCall::ObjectForKeyName);
    calls.push_back(NpcLoadCall::Retain);
    store_word(image, 92, present[static_cast<int>(Key::Name)]
                             ? bits[static_cast<int>(Key::Name)]
                             : 0u);

    calls.push_back(NpcLoadCall::Autorelease);  // old tameCountsByClientID
    // tameCountsByClientID@104 = nil happens here (image is already zero).
    calls.push_back(NpcLoadCall::ObjectForKeyTameCountsByClientID);
    if (present[static_cast<int>(Key::TameCountsByClientID)]) {
        calls.push_back(NpcLoadCall::DictionaryWithDictionary);
        calls.push_back(NpcLoadCall::Retain);
        store_word(image, 104, kNpcLoadDictCopyToken);
    }

    // ---- savedBlockheadIndex: -1 default store (plain str, not a call),
    //      then the currentBlockheadIndex probe (0x644354 -> beq 0x6443e0).
    store_word(image, 136, 0xffffffffu);
    calls.push_back(NpcLoadCall::ObjectForKeyCurrentBlockheadIndex);
    if (present[static_cast<int>(Key::CurrentBlockheadIndex)]) {
        calls.push_back(NpcLoadCall::ObjectForKeyCurrentBlockheadIndex);
        calls.push_back(NpcLoadCall::IntValue);
        store_word(image, 136,
                   bits[static_cast<int>(Key::CurrentBlockheadIndex)]);
    }

    (void)inputs.old_name;
    (void)inputs.old_tame_counts;
    return result;
}

}  // namespace blockheads::recovered
