// Full Tree-family loader implementation. See tree_full.h.
#include "tree_full.h"

namespace bh176 {

TreeFullState tree_full_load(const SaveDict& entry, bool is_static_tree) {
    using blockheads::recovered::TreeLoadInputs;
    using blockheads::recovered::tree_load_save_dict_stage1;

    TreeFullState state;

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

    // --- Tree loadSaveDictValues stage 1 (executed contract, b4d) ---
    TreeLoadInputs stage1;
    stage1.season_offset =
        SaveDict::intValue(entry.objectForKey("treeSeasonOffset"));
    stage1.dead = SaveDict::boolValue(entry.objectForKey("dead"));
    stage1.time_died = SaveDict::doubleValue(entry.objectForKey("timeDied"));
    stage1.remove_check_count =
        SaveDict::floatValue(entry.objectForKey("removeCheckCount"));
    stage1.height = SaveDict::intValue(entry.objectForKey("height"));
    stage1.age = SaveDict::floatValue(entry.objectForKey("age"));
    const SaveValue* tree_fruit = entry.objectForKey("treeFruit");
    stage1.fruit_array_count = static_cast<int>(SaveDict::count(tree_fruit));
    stage1.is_static_tree = is_static_tree;

    const auto stage1_fields = tree_load_save_dict_stage1(stage1);
    state.tree_season_offset = stage1_fields.tree_season_offset;
    state.dead = stage1_fields.dead != 0;
    state.time_died = stage1_fields.time_died;
    state.remove_check_count = stage1_fields.remove_check_count;
    state.height = stage1_fields.height;
    state.age = stage1_fields.age;
    state.fruit_count = stage1_fields.fruit_count;
    state.static_gate_fired = stage1_fields.gene_block_skipped;

    // --- gene/growth block (static decode b3a; gated by isStaticTree) ---
    // The gate mirrors the ARM bne at 0x4c3570: static trees skip the block.
    // All keys are objectForKey-probed; a missing key decodes as nil (0).
    if (!is_static_tree) {
        state.max_height_reached =
            SaveDict::intValue(entry.objectForKey("maxHeightReached"));
        state.growth_rate_gene = static_cast<std::uint16_t>(
            SaveDict::intValue(entry.objectForKey("growthRateGene")));
        state.max_height_gene = static_cast<std::uint16_t>(
            SaveDict::intValue(entry.objectForKey("maxHeightGene")));
        state.max_height =
            SaveDict::floatValue(entry.objectForKey("maxHeight"));
        state.growth_rate =
            SaveDict::floatValue(entry.objectForKey("growthRate"));
        state.growth_counter =
            SaveDict::floatValue(entry.objectForKey("growthCounter"));
        state.max_age = SaveDict::floatValue(entry.objectForKey("maxAge"));
    }

    // --- AppleTree/PineTree own key (ownkey5 static: availableFood -> @136);
    // presence-gated exactly like the Tulip own-key block ---
    if (entry.objectForKey("availableFood") != nullptr) {
        state.has_available_food = true;
        state.available_food =
            SaveDict::floatValue(entry.objectForKey("availableFood"));
    }
    return state;
}

ClientDynamicObject tree_full_factory(int type_id, const SaveDict& entry,
                                      TreeFullState* out_state,
                                      std::string* error) {
    if (error) error->clear();
    // A loaded tree record is a real tree: [self isStaticTree] is false and
    // the gene/growth block runs (the static-gate control lives in the test).
    const TreeFullState state = tree_full_load(entry, /*is_static_tree=*/false);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        "tree full chain: DynamicObject base + Tree stage1 (executed b4d) + "
        "gene/growth block (static b3a offsets) + availableFood own key "
        "(static, presence-gated)";
    return object;
}

}  // namespace bh176
