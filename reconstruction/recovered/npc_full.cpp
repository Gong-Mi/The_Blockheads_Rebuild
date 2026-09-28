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

NpcFullState npc_full_load(const SaveDict& entry, int type_id) {
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

    // --- Yak own keys (ownkey5 executed: milk@1136 then hair@1140, each
    // floatValue into its own ivar; the updateTextures tail hook carries no
    // save state). Presence-gated: only Yak records carry these keys. ---
    if (const SaveValue* milk = entry.objectForKey("milk")) {
        state.has_milk = true;
        state.milk = SaveDict::floatValue(milk);
    }
    if (const SaveValue* hair = entry.objectForKey("hair")) {
        state.has_hair = true;
        state.hair = SaveDict::floatValue(hair);
    }

    // --- DropBear 25 own body (annotated-listing decode: eight own keys +
    // saveTime; the own age step and the loadDerivedStuff tail hook carry no
    // extra save state beyond these reads) ---
    if (type_id == 25) {
        if (const SaveValue* v = entry.objectForKey("courageMeter")) {
            state.has_courage_meter = true;
            state.courage_meter = SaveDict::floatValue(v);   // @304
        }
        if (const SaveValue* v = entry.objectForKey("provokeMeter")) {
            state.has_provoke_meter = true;
            state.provoke_meter = SaveDict::floatValue(v);   // @300
        }
        if (const SaveValue* v = entry.objectForKey("dropSpeed")) {
            state.has_drop_speed = true;
            state.drop_speed = SaveDict::floatValue(v);      // @312
        }
        const SaveValue* dropping = entry.objectForKey("dropping");
        if (dropping != nullptr) state.dropping = SaveDict::boolValue(dropping);  // @308
        const SaveValue* on_ground = entry.objectForKey("onGround");
        if (on_ground != nullptr) state.on_ground = SaveDict::boolValue(on_ground);  // @344
        const SaveValue* dx = entry.objectForKey("dropPos.x");
        const SaveValue* dy = entry.objectForKey("dropPos.y");
        if (dx != nullptr && dy != nullptr) {
            state.has_drop_pos = true;
            state.drop_pos_x = static_cast<std::int32_t>(SaveDict::intValue(dx));  // @348
            state.drop_pos_y = static_cast<std::int32_t>(SaveDict::intValue(dy));  // @352
        }
        if (const SaveValue* v = entry.objectForKey("goalTreeDirection")) {
            state.has_goal_tree_direction = true;
            state.goal_tree_direction =
                static_cast<std::int32_t>(SaveDict::intValue(v));  // @356
        }
        if (const SaveValue* v = entry.objectForKey("saveTime")) {
            state.has_save_time = true;
            state.save_time = SaveDict::floatValue(v);
        }
        state.own_body_listing_decoded = true;
    }
    // --- CaveTroll 39 own body (annotated-listing decode: dead byte +
    // defendSquare.x/.y int words + the state data blob; the
    // initSubDerivedStuffStuff tail hook carries no save state) ---
    if (type_id == 39) {
        const SaveValue* dead = entry.objectForKey("dead");
        if (dead != nullptr) state.dead = SaveDict::boolValue(dead);  // NPC.dead@56
        const SaveValue* fx = entry.objectForKey("defendSquare.x");
        const SaveValue* fy = entry.objectForKey("defendSquare.y");
        if (fx != nullptr && fy != nullptr) {
            state.has_defend_square = true;
            state.defend_square_x =
                static_cast<std::int32_t>(SaveDict::intValue(fx));  // @356
            state.defend_square_y =
                static_cast<std::int32_t>(SaveDict::intValue(fy));  // @360
        }
        if (const SaveValue* v = entry.objectForKey("state")) {
            state.has_state = true;
            state.state_bytes = v->text.size() / 2;  // Data is kept as hex
            state.state_hex = v->text;
        }
        state.own_body_listing_decoded = true;
    }

    return state;
}

ClientDynamicObject npc_full_factory(int type_id, const SaveDict& entry,
                                     NpcFullState* out_state,
                                     std::string* error) {
    if (error) error->clear();
    // the recovered chain runs for real on construction
    const NpcFullState state = npc_full_load(entry, type_id);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        "npc full chain executed: DynamicObject base + NPC "
        "initWithWorld/loadValuesFromSaveDict (executed b3g/b4f)";
    if (type_id == 63) {
        object.status_reason +=
            "; Yak own keys milk/hair (ownkey5 executed, presence-gated); "
            "the updateTextures tail hook carries no save state";
    }
    if (type_id == 25) {
        object.status_reason +=
            "; DropBear own body (EXECUTED differential "
            "tools/test_specials_arm.py: read order + the age step + the "
            "death branch): provokeMeter float@300/courageMeter float@304/"
            "dropSpeed float@312, dropping STRB@308/onGround STRB@344, "
            "dropPos.x/.y @348/@352, goalTreeDirection@356, then "
            "age@88 += ([world worldTime] - saveTime); when "
            "age > [self maxAge] the body calls removeFromMacroBlock + release "
            "and RETURNS NIL (dies of old age), else it calls "
            "loadDerivedStuff — the world inputs are not evaluable offline";
    }
    if (type_id == 39) {
        object.status_reason +=
            "; CaveTroll own body (listing decode): dead byte, "
            "defendSquare.x/.y@356/@360, the state data blob (hex+size); the "
            "initSubDerivedStuffStuff tail hook and the world calls "
            "(removeFromMacroBlock/interactingTile) carry no save state";
    }
    return object;
}

}  // namespace bh176
