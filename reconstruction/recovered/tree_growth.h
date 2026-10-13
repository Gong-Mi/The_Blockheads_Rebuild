// tree_growth.h — the Tree growth state machine, modelled from the
// ARM-attested listing of `-[Tree growInTimeSinceSaved:]`
// (0x004c2568..0x004c2df0) and pinned by the harness predictions
// (SPECIALS_ARM.md, tools/test_specials_arm.py --class Tree).
//
// Verified behaviour (differential + prediction):
//   - static tree  -> returns kTreeStaticNoGrowth (1), no state change;
//   - dead tree    -> returns kTreeNoGrowth (0/nil), no state change;
//   - age + elapsed >= maxAge -> the death block (dead, timeDied);
//   - height >= maxHeight or elapsed <= 0 -> no growth, no counter change;
//   - otherwise the accumulation loop:
//       P = kGrowthK * ((1 - height/maxHeight + kGrowthHeightFloor) * 0.5)
//             * growthRate * geneIncrement
//       pass while elapsed >= (1 - counter)/P:
//         elapsed -= (1 - counter)/P; age += (1 - counter)/P;
//         counter = 0; incrementHeight(); maxHeightReached = max(...);
//       then counter += elapsed * P and the -1.0 sentinel ends the loop.
//     Prediction-pinned: counter 1.0, maxAge 100, age 50, height 3,
//     maxHeight 10, growthRate 0.5, geneIncrement 5, P = 0.005625:
//     elapsed 25 -> counter 0.140625; elapsed 10 -> counter 0.05625.
#pragma once

namespace blockheads::tree {

struct GeneIncrement {
    // the division chain of the gene block: the values the tile's gene
    // bytes (+7 / +0xe / +0x10 / +0x12) produce; the harness observed the
    // final __aeabi_idiv(5844, 1024) -> 5 for the synthetic tile.
    double increment = 0.0;
};

struct GrowthState {
    float growth_counter = 1.0f;
    float age = 0.0f;
    float max_age = 0.0f;
    float growth_rate = 1.0f;
    int height = 0;
    int max_height = 0;
    int max_height_reached = 0;
    bool dead = false;
    double time_died = 0.0;
};

enum class GrowthOutcome {
    static_tree_no_growth,  // the isStaticTree branch: returns 1
    dead_no_growth,         // the dead check: returns nil
    died,                   // the age check's death block
    no_growth,              // height >= maxHeight or elapsed <= 0
    grew,                   // the accumulation loop ran: returns 1
};

struct GrowthResult {
    GrowthOutcome outcome = GrowthOutcome::no_growth;
    GrowthState state;
    float counter_delta = 0.0f;  // the counter after - before (0 when none)
};

inline constexpr double kGrowthK = 0.005;         // 0x3F747AE147AE147B
inline constexpr float kGrowthHeightFloor = 0.2f; // 0x3E4CCCCD

// world_time - save_time, computed the way the body does (a double).
inline double elapsed_of(double world_time, double save_time) {
    return world_time - save_time;
}

// The growth factor P (SPECIALS_ARM.md "growth arithmetic").
inline double growth_p(const GrowthState& st, const GeneIncrement& genes) {
    const double height_fraction =
        st.max_height > 0 ? static_cast<double>(st.height) / st.max_height
                          : 0.0;
    const double factor =
        (1.0 - height_fraction + kGrowthHeightFloor) * 0.5;
    return kGrowthK * factor * st.growth_rate * genes.increment;
}

// The machine. `elapsed` is the double from the body (mutable copy inside).
GrowthResult grow(const GrowthState& in, double world_time, double save_time,
                  const GeneIncrement& genes, bool is_static);

}  // namespace blockheads::tree
