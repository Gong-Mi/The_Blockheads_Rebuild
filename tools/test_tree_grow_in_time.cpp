// Contract test for the recovered Tree growInTimeSinceSaved: slice
// (reconstruction/recovered/tree_grow_in_time.cpp, stage 1 nil-tile path).
// Runs in CTest so CI exercises the contract without the original ELF.
//
// The numeric expectations below are the same cases the ARM differential
// (tools/test_tree_grow_arm.py) executes against the original instructions;
// keep the two lists in sync.
#include "tree_grow_in_time.h"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

using blockheads::recovered::TreeGrowCall;
using blockheads::recovered::TreeGrowInputs;
using blockheads::recovered::TreeGrowResult;
using blockheads::recovered::tree_grow_in_time_since_saved;

int failures = 0;

void expect(bool condition, const char* what) {
    if (!condition) {
        std::printf("FAIL: %s\n", what);
        ++failures;
    }
}

float f32(std::uint32_t bits) {
    float f = 0.0f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

std::uint32_t bits32(float value) {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
}

std::uint32_t word_at(const TreeGrowResult& r, std::size_t off) {
    std::uint32_t v = 0;
    std::memcpy(&v, &r.image[off], sizeof(v));
    return v;
}

float float_at(const TreeGrowResult& r, std::size_t off) {
    return f32(word_at(r, off));
}

double double_at(const TreeGrowResult& r, std::size_t off) {
    double v = 0;
    std::memcpy(&v, &r.image[off], sizeof(v));
    return v;
}

bool has(const TreeGrowResult& r, TreeGrowCall code) {
    for (const auto& c : r.calls) {
        if (c.first == code) {
            return true;
        }
    }
    return false;
}

TreeGrowInputs base() {
    TreeGrowInputs in;
    in.world_token = 0x51CE0004;
    in.dynamic_world_token = 0x51CE0005;
    in.pos_x = 7;
    in.pos_y = 11;
    in.max_age = 100.0f;
    in.age = 10.0f;
    in.growth_counter = 0.2f;
    in.growth_rate = 1.0f;
    in.max_height = 10;
    in.height = 5;
    in.max_height_reached = 5;
    return in;
}

}  // namespace

int main() {
    // Case: static tree returns after the first message, image untouched
    // except the fixture echo.
    {
        TreeGrowInputs in = base();
        in.is_static_tree = 1;
        const TreeGrowResult r = tree_grow_in_time_since_saved(in);
        expect(r.calls.size() == 1 && r.calls[0].first == TreeGrowCall::IsStaticTree,
               "static tree: only isStaticTree");
        expect(float_at(r, 96) == 10.0f, "static tree: age untouched");
        expect(word_at(r, 4) == 0x51CE0004u, "fixture world token echoed");
    }

    // Case: dead at entry -> no worldTime, no updateGrowth.
    {
        TreeGrowInputs in = base();
        in.dead = 1;
        const TreeGrowResult r = tree_grow_in_time_since_saved(in);
        expect(r.calls.size() == 1, "dead entry: only isStaticTree");
        expect(!has(r, TreeGrowCall::WorldTime), "dead entry: no worldTime");
        expect(!has(r, TreeGrowCall::UpdateGrowthNo),
               "dead entry: no updateGrowth");
        expect(r.image[104] == 1, "dead still set");
    }

    // Case: partial growth (growthTime >= elapsed) -> growthCounter moves,
    // tail updateGrowth:0, age unchanged.
    {
        TreeGrowInputs in = base();
        in.world_time = 50.0;
        in.time_since_saved = 10.0;  // elapsed 40
        const TreeGrowResult r = tree_grow_in_time_since_saved(in);
        expect(has(r, TreeGrowCall::WorldTime), "partial: worldTime sent");
        expect(!has(r, TreeGrowCall::IncrementHeight),
               "partial: no increment");
        expect(has(r, TreeGrowCall::UpdateGrowthNo), "partial: tail call");
        expect(float_at(r, 96) == 10.0f, "partial: age unchanged");
        const float gc = float_at(r, 68);
        expect(gc > 0.2f && gc < 0.3f, "partial: growthCounter advanced");
        expect(r.image[104] == 0, "partial: still alive");
    }

    // Case: two increments then partial; the second iteration uses the
    // spilled timeToGrow = 1.0f (NOT 1-growthCounter again).
    {
        TreeGrowInputs in = base();
        in.max_age = 1000.0f;
        in.growth_counter = 0.9f;
        in.growth_rate = 10.0f;
        in.height = 3;
        in.max_height_reached = 3;
        in.world_time = 100.0;
        in.time_since_saved = 0.0;
        const TreeGrowResult r = tree_grow_in_time_since_saved(in);
        int increments = 0;
        for (const auto& c : r.calls) {
            if (c.first == TreeGrowCall::IncrementHeight) {
                ++increments;
            }
        }
        expect(increments == 2, "double increment loop ran twice");
        expect(!has(r, TreeGrowCall::UpdateGrowthNo),
               "grew -> tail returns without updateGrowth:0");
        expect(float_at(r, 96) > 80.0f, "age accumulated");
        expect(float_at(r, 68) > 0.0f, "partial step after the increments");
    }

    // Case: scripted increment bumps height to maxHeight -> loop exits by
    // the height check, maxHeightReached = max(height, mhr) after reload.
    {
        TreeGrowInputs in = base();
        in.max_age = 1000.0f;
        in.growth_rate = 10.0f;
        in.height_after_increment = 10;  // == maxHeight
        in.max_height_reached_after_increment = 6;
        in.world_time = 100.0;
        in.time_since_saved = 0.0;
        const TreeGrowResult r = tree_grow_in_time_since_saved(in);
        expect(has(r, TreeGrowCall::IncrementHeight), "scripted: one increment");
        expect(word_at(r, 64) == 10u,
               "maxHeightReached = max(reloaded height 10, mhr 6)");
        expect(word_at(r, 60) == 10u, "height kept the scripted value");
    }

    // Case: old path + compost clamps age to maxAge.
    {
        TreeGrowInputs in = base();
        in.age = 95.0f;
        in.world_time = 200.0;
        in.time_since_saved = 110.0;  // elapsed 90, age+elapsed = 185 >= 100
        in.is_growing_in_compost = 1;
        const TreeGrowResult r = tree_grow_in_time_since_saved(in);
        expect(has(r, TreeGrowCall::IsGrowingInCompost), "old: compost asked");
        expect(float_at(r, 96) == 100.0f, "compost: age = maxAge");
        expect(has(r, TreeGrowCall::UpdateGrowthNo), "old: tail updateGrowth");
    }

    // Case: old path without compost -> sow + die + timeDied + removeAll.
    {
        TreeGrowInputs in = base();
        in.age = 95.0f;
        in.world_time = 200.0;
        in.time_since_saved = 110.0;
        const TreeGrowResult r = tree_grow_in_time_since_saved(in);
        expect(!has(r, TreeGrowCall::IsGrowingInCompost) ||
                   has(r, TreeGrowCall::SowTreeNearParent),
               "death: sowTree happened");
        expect(r.image[104] == 1, "death: dead = 1");
        expect(double_at(r, 112) == 115.0,
               "death: timeDied = t + maxAge - age = 115");
        // adultMaxAge = (float)(elapsed - (double)(maxAge - age))
        //             = (float)(90 - 5) = 85.0f
        bool sow_ok = false;
        for (const auto& c : r.calls) {
            if (c.first == TreeGrowCall::SowTreeNearParent &&
                c.second == bits32(85.0f)) {
                sow_ok = true;
            }
        }
        expect(sow_ok, "death: sowTreeNearParent adultMaxAge = 85.0f bits");
        expect(has(r, TreeGrowCall::RemoveAllOwnedTiles),
               "death: removeAllOwnedTiles");
        expect(!has(r, TreeGrowCall::UpdateGrowthNo),
               "death: tail returns on dead");
    }

    // Case: NaN worldTime -> NaN age+elapsed takes the bpl branch (old
    // path); compost then clamps age.
    {
        TreeGrowInputs in = base();
        in.world_time = std::nan("");
        in.is_growing_in_compost = 1;
        const TreeGrowResult r = tree_grow_in_time_since_saved(in);
        expect(has(r, TreeGrowCall::IsGrowingInCompost),
               "NaN: old path taken (bpl on unordered)");
        expect(float_at(r, 96) == 100.0f, "NaN: compost clamps age");
    }

    // Case: negative elapsed -> grow block skipped (elapsed > 0 false),
    // straight to updateGrowth:0.
    {
        TreeGrowInputs in = base();
        in.world_time = 5.0;
        in.time_since_saved = 10.0;
        const TreeGrowResult r = tree_grow_in_time_since_saved(in);
        expect(r.calls.size() == 3, "negative elapsed: 3 messages");
        expect(r.calls[2].first == TreeGrowCall::UpdateGrowthNo,
               "negative elapsed: tail updateGrowth");
        expect(float_at(r, 68) == 0.2f, "growthCounter untouched");
    }

    // Case: age+elapsed == maxAge exactly -> bpl (>=) takes the OLD path.
    {
        TreeGrowInputs in = base();
        in.age = 50.0f;
        in.world_time = 60.0;
        in.time_since_saved = 10.0;  // 50 + 50 == 100
        in.is_growing_in_compost = 1;
        const TreeGrowResult r = tree_grow_in_time_since_saved(in);
        expect(has(r, TreeGrowCall::IsGrowingInCompost),
               "boundary: >= goes old path");
    }

    // Stage-2 Case: sunlight lighting calculation from tile
    {
        TreeGrowInputs in = base();
        in.has_tile = 1;
        in.tile_sun_light = 204; // 204 * 0.5 / 255 = 0.4 chance
        in.world_time = 100.0;
        in.time_since_saved = 99.0; // elapsed = 1.0
        in.growth_counter = 0.0f;
        in.growth_rate = 1.0f;
        in.height = 2;
        in.max_height = 10;
        // hpct = ((1 - 0.2) + 0.2) * 0.5 = 0.5
        // denom = 0.005 * 0.5 * 1.0 * 0.4 = 0.001
        // timeToGrow = 1.0 -> growthTime = 1000.0
        // eOverG = 1.0 / 1000.0 = 0.001 -> gc = 0.001
        const TreeGrowResult r = tree_grow_in_time_since_saved(in);
        expect(std::abs(float_at(r, 68) - 0.001f) < 1e-6f,
               "stage 2 sunlight: growth_counter == 0.001");
    }

    // Stage-2 Case: artificial lighting calculation from tile
    {
        TreeGrowInputs in = base();
        in.has_tile = 1;
        in.tile_sun_light = 0;
        in.tile_artificial_light_r = 2048;
        in.tile_artificial_light_g = 2048;
        in.tile_artificial_light_b = 1024; // sum = 512+512+512 = 1536 / 1024 = 1 -> chance = 1.0
        in.world_time = 100.0;
        in.time_since_saved = 99.0; // elapsed = 1.0
        in.growth_counter = 0.0f;
        in.growth_rate = 1.0f;
        in.height = 2;
        in.max_height = 10;
        // denom = 0.005 * 0.5 * 1.0 * 1.0 = 0.0025 -> growthTime = 400.0 -> eOverG = 0.0025 -> gc = 0.0025
        const TreeGrowResult r = tree_grow_in_time_since_saved(in);
        expect(std::abs(float_at(r, 68) - 0.0025f) < 1e-6f,
               "stage 2 artificial light: growth_counter == 0.0025");
    }

    if (failures == 0) {
        std::printf("recovered_tree_grow_in_time: PASS\n");
    }
    return failures == 0 ? 0 : 1;
}
