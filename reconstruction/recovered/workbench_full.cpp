// Full Workbench loader implementation. See workbench_full.h.
#include "workbench_full.h"

#include <cstring>

namespace bh176 {
namespace {

std::uint32_t readWord(const std::vector<std::uint8_t>& image,
                       std::uint32_t offset) {
    std::uint32_t value = 0;
    std::memcpy(&value, image.data() + offset, sizeof(value));
    return value;
}

std::uint16_t readHalf(const std::vector<std::uint8_t>& image,
                      std::uint32_t offset) {
    std::uint16_t value = 0;
    std::memcpy(&value, image.data() + offset, sizeof(value));
    return value;
}

std::uint8_t readByte(const std::vector<std::uint8_t>& image,
                      std::uint32_t offset) {
    return image[offset];
}

float bitsToFloat(std::uint32_t bits) {
    float value = 0.0f;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

double bitsToDouble(std::uint32_t low, std::uint32_t high) {
    std::uint64_t bits = (static_cast<std::uint64_t>(high) << 32) | low;
    double value = 0.0;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

}  // namespace

WorkbenchFullState workbench_full_load(const SaveDict& entry) {
    using blockheads::recovered::WorkbenchInitInputs;
    using blockheads::recovered::workbench_init_with_world;

    WorkbenchFullState state;

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

    // --- Workbench initWithWorld (executed b4q) -------------------------
    // Map the entry dictionary onto the contract's input shape. The b4q run
    // freezes the 16-key walk; every key is objectForKey-probed and the
    // conversion follows the executed per-key kind.
    WorkbenchInitInputs in;
    in.workbench_type_value = static_cast<std::uint32_t>(
        SaveDict::intValue(entry.objectForKey("workbenchType")));
    in.selected_index_value = static_cast<std::uint32_t>(
        SaveDict::intValue(entry.objectForKey("selectedIndex")));
    in.x_scroll_value = SaveDict::floatValue(entry.objectForKey("xScroll"));
    in.level_value = static_cast<std::uint32_t>(
        SaveDict::intValue(entry.objectForKey("level")));
    in.craft_progress_value =
        SaveDict::floatValue(entry.objectForKey("craftProgressCount"));
    in.hurry_timer_value =
        SaveDict::floatValue(entry.objectForKey("hurryTimer"));
    in.hurry_seconds_value =
        SaveDict::floatValue(entry.objectForKey("hurrySeconds"));
    in.hurrying_value =
        SaveDict::boolValue(entry.objectForKey("hurrying")) ? 1u : 0u;
    in.hurry_cost_value = static_cast<std::uint32_t>(
        SaveDict::intValue(entry.objectForKey("hurryCost")));
    in.fire_spread_value =
        SaveDict::floatValue(entry.objectForKey("fireSpreadTimer"));
    in.fuel_fraction_value =
        SaveDict::floatValue(entry.objectForKey("fuelFraction"));
    in.has_fuel_value =
        SaveDict::boolValue(entry.objectForKey("hasFuel")) ? 1u : 0u;
    in.last_world_time_value =
        SaveDict::doubleValue(entry.objectForKey("lastWorldTime"));
    in.is_in_use_fuel_value =
        SaveDict::boolValue(entry.objectForKey("isInUseFuel")) ? 1u : 0u;
    in.available_elec_value = static_cast<std::uint32_t>(
        SaveDict::unsignedLongValue(entry.objectForKey("availableElectricity")));
    in.blockhead_index_fuel_value = SaveDict::intValue(
        entry.objectForKey("currentBlockheadIndexFuel"));
    // the offline record carries isInUse=false: the crafting/fuel wiring
    // gates stay closed, matching the snapshot's non-crafting workbench
    in.is_in_use = SaveDict::boolValue(entry.objectForKey("isInUse")) ? 1u : 0u;
    in.is_in_use_fuel_value =
        SaveDict::boolValue(entry.objectForKey("isInUseFuel")) ? 1u : 0u;
    // lightDict presence (the ArtificialLight body is outside the contract)
    in.light_dict_present =
        entry.objectForKey("lightDict") != nullptr;

    const auto result = workbench_init_with_world(in);
    const auto& image = result.image;

    // read the executed stores back out at the original ivar offsets
    state.workbench_type =
        static_cast<std::int32_t>(readWord(image, 120));
    state.selected_index =
        static_cast<std::int32_t>(readWord(image, 136));
    state.x_scroll = bitsToFloat(readWord(image, 172));
    state.level = static_cast<std::int32_t>(readWord(image, 176));
    state.craft_progress_count = bitsToFloat(readWord(image, 188));
    state.hurry_timer = bitsToFloat(readWord(image, 192));
    state.hurry_seconds = bitsToFloat(readWord(image, 196));
    state.hurrying = readByte(image, 200) != 0;
    state.hurry_cost = static_cast<std::int32_t>(readWord(image, 204));
    state.fire_spread_timer = bitsToFloat(readWord(image, 208));
    state.fuel_fraction = bitsToFloat(readWord(image, 212));
    state.has_fuel = readByte(image, 220) != 0;
    state.last_world_time =
        bitsToDouble(readWord(image, 256), readWord(image, 260));
    state.is_in_use_fuel = readByte(image, 112) != 0;
    state.available_electricity = readHalf(image, 222);
    state.saved_blockhead_index_fuel =
        static_cast<std::int32_t>(readWord(image, 116));
    state.light_present = in.light_dict_present;

    // --- the InteractionObject static boundary --------------------------
    // flipped/paintColor/ownerID/ownerName/currentBlockheadIndex have
    // static evidence only (UPPERMID15) and NO recovered module — reported,
    // never silently zeroed or loaded from a guess.
    state.interaction_static_keys_present =
        entry.objectForKey("flipped") != nullptr ||
        entry.objectForKey("paintColor") != nullptr ||
        entry.objectForKey("ownerID") != nullptr;
    return state;
}

ClientDynamicObject workbench_full_factory(int type_id, const SaveDict& entry,
                                           WorkbenchFullState* out_state,
                                           std::string* error) {
    if (error) error->clear();
    const WorkbenchFullState state = workbench_full_load(entry);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        "workbench full chain: DynamicObject base + Workbench b4q executed "
        "(16 scalars + lightDict presence); InteractionObject super keys "
        "static-only (not loaded); saveTime write-only";
    return object;
}

}  // namespace bh176
