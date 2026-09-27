// Full NPC-family loader implementation (bucket B). See npc_full.h.
#include "npc_full.h"

#include <cstring>

namespace bh176 {
namespace {

// Read a little-endian scalar out of the contract's instance image at the
// original ivar offset — exactly the bits the ARM str/strh/strb/vstr left.
std::uint32_t loadWord(const std::uint8_t* image, std::size_t offset) {
    std::uint32_t value = 0;
    std::memcpy(&value, image + offset, sizeof(value));
    return value;
}

std::uint16_t loadHalf(const std::uint8_t* image, std::size_t offset) {
    std::uint16_t value = 0;
    std::memcpy(&value, image + offset, sizeof(value));
    return value;
}

float bitsToFloat(std::uint32_t bits) {
    float value = 0.0f;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

}  // namespace

NpcFullState npc_full_load(const SaveDict& entry) {
    using blockheads::recovered::NpcLoadKey;
    using blockheads::recovered::NpcLoadValuesInputs;
    using blockheads::recovered::npc_load_values_run;

    NpcFullState state;

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

    // --- NPC loadValuesFromSaveDict: (executed contract) ---
    // Map the entry dictionary onto the contract's probe/bits inputs. The
    // probe semantics are objectForKey != nil; the payload interpretations
    // follow the contract's per-key kinds.
    NpcLoadValuesInputs inputs;
    const auto set = [&](NpcLoadKey key, const char* name) {
        const SaveValue* value = entry.objectForKey(name);
        const int idx = static_cast<int>(key);
        if (value == nullptr) return;
        inputs.present[idx] = true;
        switch (key) {
            case NpcLoadKey::Fullness:
            case NpcLoadKey::LayTimer:
            case NpcLoadKey::Age:
            case NpcLoadKey::LayCooldownTimer:
            case NpcLoadKey::TameCooldownTimer:
            case NpcLoadKey::MateCooldownTimer: {
                const float f = SaveDict::floatValue(value);
                std::uint32_t bits = 0;
                std::memcpy(&bits, &f, sizeof(bits));
                inputs.bits[idx] = bits;
                break;
            }
            case NpcLoadKey::Damage:
            case NpcLoadKey::MateBreed:
            case NpcLoadKey::CurrentBlockheadIndex:
                inputs.bits[idx] =
                    static_cast<std::uint32_t>(SaveDict::intValue(value));
                break;
            case NpcLoadKey::Breed:
                inputs.bits[idx] = static_cast<std::uint32_t>(
                    SaveDict::unsignedLongValue(value));
                break;
            case NpcLoadKey::HasBred:
            case NpcLoadKey::HasBeenFedByBlockheadOrChest:
                inputs.bits[idx] =
                    SaveDict::boolValue(value) ? 1u : 0u;
                break;
            case NpcLoadKey::TamedClientID:
            case NpcLoadKey::Name:
            case NpcLoadKey::TameCountsByClientID:
                // object slots: presence is all the offline chain preserves
                // (the harness stores boxed addresses; offline we mark only)
                inputs.bits[idx] = 1u;
                break;
            case NpcLoadKey::Count:
                break;
        }
    };
    set(NpcLoadKey::Fullness, "fullness");
    set(NpcLoadKey::LayTimer, "layTimer");
    set(NpcLoadKey::Damage, "damage");
    set(NpcLoadKey::Age, "age");
    set(NpcLoadKey::LayCooldownTimer, "layCooldownTimer");
    set(NpcLoadKey::TameCooldownTimer, "tameCooldownTimer");
    set(NpcLoadKey::MateCooldownTimer, "mateCooldownTimer");
    set(NpcLoadKey::HasBred, "hasBred");
    set(NpcLoadKey::HasBeenFedByBlockheadOrChest,
        "hasBeenFedByBlockheadOrChest");
    set(NpcLoadKey::MateBreed, "mateBreed");
    set(NpcLoadKey::Breed, "breed");
    set(NpcLoadKey::TamedClientID, "tamedClientID");
    set(NpcLoadKey::Name, "name");
    set(NpcLoadKey::TameCountsByClientID, "tameCountsByClientID");
    set(NpcLoadKey::CurrentBlockheadIndex, "currentBlockheadIndex");

    const auto result = npc_load_values_run(inputs);
    const std::uint8_t* image = result.image;

    // read the executed stores back out of the image
    state.g1_present = inputs.present[static_cast<int>(NpcLoadKey::Fullness)];
    state.fullness = bitsToFloat(loadWord(image, 68));
    state.lay_timer = bitsToFloat(loadWord(image, 80));
    state.damage = loadHalf(image, 54);
    state.age = bitsToFloat(loadWord(image, 88));

    state.g2_present =
        inputs.present[static_cast<int>(NpcLoadKey::LayCooldownTimer)];
    state.lay_cooldown_timer = bitsToFloat(loadWord(image, 84));
    state.tame_cooldown_timer = bitsToFloat(loadWord(image, 72));
    state.mate_cooldown_timer = bitsToFloat(loadWord(image, 76));
    state.has_bred = image[100] != 0;
    state.has_been_fed = image[101] != 0;
    state.mate_breed = loadHalf(image, 98);

    state.breed = loadHalf(image, 96);

    state.has_tamed_client_id =
        inputs.present[static_cast<int>(NpcLoadKey::TamedClientID)];
    state.has_name = inputs.present[static_cast<int>(NpcLoadKey::Name)];
    state.has_tame_counts =
        inputs.present[static_cast<int>(NpcLoadKey::TameCountsByClientID)];
    state.saved_blockhead_index =
        static_cast<std::int32_t>(loadWord(image, 136));

    return state;
}

ClientDynamicObject npc_full_factory(int type_id, const SaveDict& entry,
                                     NpcFullState* out_state,
                                     std::string* error) {
    if (error) error->clear();
    // the recovered chain runs for real on construction
    const NpcFullState state = npc_full_load(entry);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        "npc full chain executed: DynamicObject base + NPC "
        "initWithWorld/loadValuesFromSaveDict (executed b3g/b4f)";
    return object;
}

}  // namespace bh176
