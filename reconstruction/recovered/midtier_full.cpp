// Mid-tier static loader family implementation. See midtier_full.h.
#include "midtier_full.h"

namespace bh176 {

namespace {

using K = MidtierKeySpec;

// The per-class key tables (decoded from the annotated listings; see the
// header for the per-class source lines).
const K kWindow[] = {
    {"itemType", K::Conv::Int, K::Width::Word, 56},
    {"ownerID", K::Conv::Object, K::Width::Word, 36},
};
const K kRail[] = {
    {"configuration", K::Conv::Int, K::Width::Word, 60},
    {"ownedByStation", K::Conv::Bool, K::Width::Byte, 65},
    {"itemType", K::Conv::Int, K::Width::Word, 56},
};
const K kBoat[] = {
    {"currentBlockheadIndex", K::Conv::Int, K::Width::Word, 120},
    {"ownerID", K::Conv::Object, K::Width::Word, 36},
};
const K kLadder[] = {
    {"ownerID", K::Conv::Object, K::Width::Word, 36},
    {"paintColor", K::Conv::UInt, K::Width::Half, 60},
    {"itemType", K::Conv::Int, K::Width::Word, 56},
};
const K kEgg[] = {
    {"genesDict", K::Conv::Object, K::Width::Word, 56},
    {"breed", K::Conv::Int, K::Width::Half, 60},
    {"hatchTimer", K::Conv::Float, K::Width::Word, 64},
};
const K kColumn[] = {
    {"ownerID", K::Conv::Object, K::Width::Word, 36},
    {"configuration", K::Conv::Int, K::Width::Word, 64},
    {"paintColor", K::Conv::UInt, K::Width::Half, 60},
    {"itemType", K::Conv::Int, K::Width::Word, 56},
};
const K kStairs[] = {
    {"ownerID", K::Conv::Object, K::Width::Word, 36},
    {"configuration", K::Conv::Int, K::Width::Word, 60},
    {"itemType", K::Conv::Int, K::Width::Word, 56},
    {"paintColor", K::Conv::UInt, K::Width::Half, 64},
};
const K kDoor[] = {
    {"ownerID", K::Conv::Object, K::Width::Word, 36},
    {"blocked", K::Conv::Bool, K::Width::Byte, 68},
    {"ironPlaceClientID", K::Conv::Object, K::Width::Word, 72},
    {"itemType", K::Conv::Int, K::Width::Word, 64},
};
const K kElevatorShaft[] = {
    {"itemType", K::Conv::Int, K::Width::Word, 56},
    {"ownerID", K::Conv::Object, K::Width::Word, 36},
    {"lastKnownMotorPos.x", K::Conv::Int, K::Width::Word, 60},
    {"lastKnownMotorPos.y", K::Conv::Int, K::Width::Word, 64},
    {"paintColor", K::Conv::UInt, K::Width::Half, 84},
};
const K kElevatorMotor[] = {
    {"itemType", K::Conv::Int, K::Width::Word, 56},
    {"ownerID", K::Conv::Object, K::Width::Word, 36},
    {"availableElectricity", K::Conv::Int, K::Width::Word, 60},
    {"minY", K::Conv::Int, K::Width::Word, 64},
    {"maxY", K::Conv::UInt, K::Width::Half, 68},
};
const K kWire[] = {
    {"itemType", K::Conv::Int, K::Width::Word, 56},
    {"configuration", K::Conv::Int, K::Width::Word, 60},
    {"solidConfiguration", K::Conv::Int, K::Width::Word, 64},
    {"ownerID", K::Conv::Object, K::Width::Word, 36},
};

}  // namespace

const MidtierTypeSpec* midtierTypeSpec(int type_id) {
    static const MidtierTypeSpec specs[] = {
        {31, kWindow, 2, false, "initSubDerivedItems"},
        {40, kRail, 3, false, "initSubDerivedItems"},
        {32, kBoat, 2, true, "loadDerivedStuff"},
        {19, kLadder, 3, false, "initSubDerivedItems"},
        {30, kEgg, 3, false, "initSubDerivedItems"},
        {53, kColumn, 4, false, "initSubDerivedItems"},
        {54, kStairs, 4, false, "initSubDerivedItems"},
        {20, kDoor, 4, false, "initSubDerivedItems"},
        {38, kWire, 4, false, "initSubDerivedItems"},
        {56, kElevatorShaft, 5, false, "initSubDerivedItems"},
        {55, kElevatorMotor, 5, false, "initSubDerivedItems"},
        {22, nullptr, 0, false, "", true},
        {29, nullptr, 0, false, "initSubDerivedItems", true},
    };
    for (const auto& spec : specs) {
        if (spec.type_id == type_id) return &spec;
    }
    return nullptr;
}

MidtierFullState midtier_full_load(const SaveDict& entry,
                                   const MidtierTypeSpec& spec) {
    MidtierFullState state;
    state.tail_hook = spec.tail_hook;

    for (std::size_t i = 0; spec.keys != nullptr && i < spec.key_count; ++i) {
        const MidtierKeySpec& key = spec.keys[i];
        const SaveValue* value = entry.objectForKey(key.key);
        state.present[key.key] = value != nullptr;
        if (key.conv == K::Conv::Object) {
            state.objects[key.key] = value != nullptr;  // presence only
            continue;
        }
        double converted = 0.0;
        switch (key.conv) {
            case K::Conv::Int:
                converted = static_cast<double>(SaveDict::intValue(value));
                break;
            case K::Conv::UInt:
                converted = static_cast<double>(
                    SaveDict::unsignedLongValue(value));
                break;
            case K::Conv::Bool:
                converted = SaveDict::boolValue(value) ? 1.0 : 0.0;
                break;
            case K::Conv::Float:
                converted = static_cast<double>(SaveDict::floatValue(value));
                break;
            case K::Conv::Object:
                break;
        }
        if (key.width == K::Width::Half) {
            converted = static_cast<double>(
                static_cast<std::uint16_t>(static_cast<std::uint32_t>(
                    static_cast<std::int32_t>(converted) & 0xFFFF)));
        } else if (key.width == K::Width::Byte) {
            converted = (converted != 0.0) ? 1.0 : 0.0;
        }
        state.numbers[key.key] = converted;
    }

    // Boat's probe surface: savedBlockheadIndex@120 = -1 unconditionally,
    // then the intValue overwrite when the probe key is non-nil.
    if (spec.blockhead_probe_default) {
        const SaveValue* probe = entry.objectForKey("currentBlockheadIndex");
        state.had_blockhead_index = probe != nullptr;
        state.saved_blockhead_index =
            probe != nullptr
                ? static_cast<std::int32_t>(SaveDict::intValue(probe))
                : -1;
    }
    return state;
}

ClientDynamicObject midtier_full_factory(int type_id, const SaveDict& entry,
                                         MidtierFullState* out_state,
                                         std::string* error) {
    if (error) error->clear();
    const MidtierTypeSpec* spec = midtierTypeSpec(type_id);
    if (spec == nullptr) {
        if (error != nullptr) *error = "no mid-tier spec for type";
        return DynamicObjectRegistry::baseStub(type_id, entry);
    }
    const MidtierFullState state = midtier_full_load(entry, *spec);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        spec->zero_own_keys
            ? "midtier zero-own-key forwarder (forwarder5b, EXECUTED "
              "differential tools/test_forwarder5b_arm.py): DynamicObject "
              "base only; the class contributes no save keys (super "
              "forward + optional initSubDerivedItems hook)"
            : "midtier full chain: DynamicObject base + the per-class key "
              "table decoded from the annotated listing (sized ivar stores); "
              "tail hook stated (no save state)";
    return object;
}

}  // namespace bh176
