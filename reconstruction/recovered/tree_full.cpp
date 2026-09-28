// Full Tree-family loader implementation. See tree_full.h.
#include "tree_full.h"

namespace bh176 {

TreeFullState tree_full_load(const SaveDict& entry, bool is_static_tree,
                             int type_id) {
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

    // b4e stage-2 upgrade: decode the per-fruit KEY values. The record
    // writing is gated on the world tile identity check, which needs world
    // state and is NOT evaluable offline — the decoded entries are exposed
    // and tree_write_fruit_records() remains the contract for a world-aware
    // caller (its identity_matches input is exactly that gate).
    if (tree_fruit != nullptr && tree_fruit->isArray()) {
        const std::size_t fruit_n = SaveDict::count(tree_fruit);
        state.fruits_read.reserve(fruit_n);
        for (std::size_t i = 0; i < fruit_n; ++i) {
            const SaveValue* elem = entry.objectAtIndex(tree_fruit, i);
            if (elem == nullptr || !elem->isDict()) continue;
            const SaveDict fruit(*elem);
            TreeFullState::FruitEntry fe;
            fe.pos_x = static_cast<std::int32_t>(
                SaveDict::intValue(fruit.objectForKey("pos.x")));
            fe.pos_y = static_cast<std::int32_t>(
                SaveDict::intValue(fruit.objectForKey("pos.y")));
            fe.has_created_free_block =
                SaveDict::boolValue(fruit.objectForKey("hasCreatedFreeBlockThisSeason"));
            state.fruits_read.push_back(fe);
        }
    }

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

    // --- per-class own keys (b3b read-back tables, static) ----------------
    // CactusTree 5: read order super-then-own; availableFood lands at @148
    // (a DIFFERENT ivar than the fruit trees' @136), plus splitHeightA@136,
    // splitHeightB@140, splitDirection@144.
    const bool is_cactus = (type_id == 5);
    if (is_cactus) {
        const SaveValue* a = entry.objectForKey("splitHeightA");
        const SaveValue* b = entry.objectForKey("splitHeightB");
        const SaveValue* d = entry.objectForKey("splitDirection");
        const SaveValue* food = entry.objectForKey("availableFood");
        if (a != nullptr || b != nullptr || d != nullptr || food != nullptr) {
            state.has_cactus_own = true;
            state.split_height_a = static_cast<std::int32_t>(
                SaveDict::intValue(a));
            state.split_height_b = static_cast<std::int32_t>(
                SaveDict::intValue(b));
            state.split_direction = SaveDict::boolValue(d);
            state.cactus_available_food = SaveDict::floatValue(food);
        }
    } else {
        // AppleTree 1 / PineTree 4 (and the generic unit-test path): the
        // availableFood own key maps to @136. Presence-gated exactly like
        // the Tulip own-key block.
        if (entry.objectForKey("availableFood") != nullptr) {
            state.has_available_food = true;
            state.available_food =
                SaveDict::floatValue(entry.objectForKey("availableFood"));
        }
    }
    // GemTree 57: read order own-then-super; gemTreeType@136, fruitYear@140.
    {
        const SaveValue* t = entry.objectForKey("gemTreeType");
        const SaveValue* y = entry.objectForKey("fruitYear");
        if (t != nullptr || y != nullptr) {
            state.has_gem_own = true;
            state.gem_tree_type =
                static_cast<std::int32_t>(SaveDict::intValue(t));
            state.fruit_year =
                static_cast<std::int32_t>(SaveDict::intValue(y));
        }
    }
    return state;
}

ClientDynamicObject tree_full_factory(int type_id, const SaveDict& entry,
                                      TreeFullState* out_state,
                                      std::string* error) {
    if (error) error->clear();
    // A loaded tree record is a real tree: [self isStaticTree] is false and
    // the gene/growth block runs (the static-gate control lives in the test).
    const TreeFullState state =
        tree_full_load(entry, /*is_static_tree=*/false, type_id);
    if (out_state != nullptr) *out_state = state;
    ClientDynamicObject object =
        DynamicObjectRegistry::baseStub(type_id, entry);
    object.status = ObjectLoadStatus::Recovered;
    object.status_reason =
        "tree full chain: DynamicObject base + Tree stage1 (executed b4d) + "
        "gene/growth block (static b3a offsets) + own keys (b3b read-back "
        "static, presence-gated) + fruit entries decoded (b4e stage-2); the "
        "fruit WRITE gate is the world tile identity check (not evaluable "
        "offline)";
    return object;
}

}  // namespace bh176
