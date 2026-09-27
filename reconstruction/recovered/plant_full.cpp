// Full Plant-family loader implementation (batch b5b). See plant_full.h.
#include "plant_full.h"

#include "plant_load_save_dict.h"

#include <utility>
namespace bh176 {
namespace {

// 0x004c0b70 executed helper, reused from the recovered contract.
std::int32_t clamp16(std::int32_t value, std::int32_t low, std::int32_t high) {
    const auto truncate16 = [](std::int32_t v) {
        return static_cast<std::int32_t>(static_cast<std::uint16_t>(v));
    };
    std::int32_t out = truncate16(value);
    if (out > high) out = high;
    if (out < low) out = low;
    return out;
}

}  // namespace

PlantFullState plant_full_load(const PlantFullInputs& inputs) {
    const SaveDict& entry = inputs.entry;
    PlantFullState state;

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

    // --- Plant loadSaveDictValues: (executed contract, 9 keys + gate) ---
    state.season_offset = SaveDict::intValue(entry.objectForKey("seasonOffset"));
    state.age = SaveDict::floatValue(entry.objectForKey("age"));
    state.gather_progress =
        SaveDict::intValue(entry.objectForKey("gatherProgress"));
    state.has_flowered =
        SaveDict::boolValue(entry.objectForKey("hasFloweredThisSeason"));
    state.flowering = SaveDict::boolValue(entry.objectForKey("flowering"));
    state.frozen = SaveDict::boolValue(entry.objectForKey("frozen"));
    state.max_age_gene = static_cast<std::uint16_t>(clamp16(
        SaveDict::intValue(entry.objectForKey("maxAgeGene")), 1, 255));
    state.growth_rate_gene = static_cast<std::uint16_t>(clamp16(
        SaveDict::intValue(entry.objectForKey("growthRateGene")), 1, 255));
    // saveTime is probed but never stored; it only feeds the season gate.
    const double save_time =
        SaveDict::doubleValue(entry.objectForKey("saveTime"));
    if (inputs.world_time - save_time > 1800.0) {
        state.has_flowered = false;
        state.season_gate_fired = true;
    }

    // --- TulipPlant own keys (b3k static; present only on TulipPlant) ---
    if (entry.objectForKey("colorGenes") != nullptr ||
        entry.objectForKey("mixGenes") != nullptr ||
        entry.objectForKey("mateColorGenes") != nullptr ||
        entry.objectForKey("availableFood") != nullptr) {
        state.tulip.present = true;
        state.tulip.available_food =
            SaveDict::floatValue(entry.objectForKey("availableFood"));
        state.tulip.color_genes = static_cast<std::uint16_t>(
            SaveDict::intValue(entry.objectForKey("colorGenes")));
        state.tulip.mate_color_genes = static_cast<std::uint16_t>(
            SaveDict::intValue(entry.objectForKey("mateColorGenes")));
        state.tulip.mix_genes = static_cast<std::uint16_t>(
            SaveDict::intValue(entry.objectForKey("mixGenes")));
    }
    return state;
}

ClientDynamicObject plant_full_factory(int type_id, const SaveDict& entry,
                                       double world_time,
                                       PlantFullState* out_state,
                                       std::string* error) {
    if (error) error->clear();
    // The recovered chain runs for real on construction; the caller decides
    // where the per-type state lives (the registry object stays identity-only).
    const PlantFullState state = plant_full_load({entry, world_time});
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        "plant full chain executed: DynamicObject base + Plant "
        "loadSaveDictValues (executed) + TulipPlant own keys (static)";
    return object;
}

}  // namespace bh176
