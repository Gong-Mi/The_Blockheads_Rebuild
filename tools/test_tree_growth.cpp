// test_tree_growth.cpp — pins the tree growth machine against the
// ARM-attested predictions (tools/test_specials_arm.py --class Tree):
//   seeds: counter 1.0, age 50, maxAge 100, height 3, maxHeight 10,
//          growthRate 0.5, gene increment 5.0 (=> P = 0.005625)
//   observed: worldTime 1000, saveTime 975 (elapsed 25) -> counter 0.140625,
//             saveTime 990 (elapsed 10) -> counter 0.05625; both return 1.
#include "tree_growth.h"

#include <cassert>
#include <cmath>
#include <cstdio>

using namespace blockheads::tree;

namespace {
GrowthState base_state() {
    GrowthState s;
    s.growth_counter = 1.0f;
    s.age = 50.0f;
    s.max_age = 100.0f;
    s.growth_rate = 0.5f;
    s.height = 3;
    s.max_height = 10;
    s.max_height_reached = 0;
    return s;
}
GeneIncrement genes() {
    GeneIncrement g;
    g.increment = 5.0;  // __aeabi_idiv(5844,1024) -> 5 on the fake tile
    return g;
}
bool close(float a, float b) { return std::fabs(a - b) < 1e-6f; }
}  // namespace

int main() {
    const auto st = base_state();
    const auto g = genes();
    assert(close(static_cast<float>(growth_p(st, g)), 0.005625f));

    // The two prediction-pinned runs (the differential's numbers).
    {
        const auto r = grow(st, 1000.0, 975.0, g, false);
        assert(r.outcome == GrowthOutcome::grew);
        assert(close(r.state.growth_counter, 0.140625f));
        assert(close(r.state.age, 50.0f));          // the accumulation pass
        assert(r.state.height == 3);                // incrementHeight was
        assert(r.state.max_height_reached == 3);    // a no-op on these runs
        assert(!r.state.dead);
    }
    {
        const auto r = grow(st, 1000.0, 990.0, g, false);
        assert(r.outcome == GrowthOutcome::grew);
        assert(close(r.state.growth_counter, 0.05625f));  // exactly x10/25
    }
    // The no-gene default increment (0.5): the earlier harness run's value.
    {
        GeneIncrement g0;
        g0.increment = 0.5;
        const auto r = grow(st, 1000.0, 975.0, g0, false);
        assert(r.outcome == GrowthOutcome::grew);
        assert(close(r.state.growth_counter, 0.0140625f));
    }

    // Static trees do not grow (return 1, no state change).
    {
        const auto r = grow(st, 1000.0, 975.0, g, true);
        assert(r.outcome == GrowthOutcome::static_tree_no_growth);
        assert(close(r.state.growth_counter, 1.0f));
        assert(r.state.age == 50.0f && r.state.height == 3);
    }
    // Dead trees: the tail, no state change.
    {
        auto d = st;
        d.dead = true;
        const auto r = grow(d, 1000.0, 975.0, g, false);
        assert(r.outcome == GrowthOutcome::dead_no_growth);
    }
    // age + elapsed >= maxAge -> the death block.
    {
        const auto r = grow(st, 1000.0, 940.0, g, false);  // 50 + 60 >= 100
        assert(r.outcome == GrowthOutcome::died);
        assert(r.state.dead && r.state.time_died == 1000.0);
    }
    // height >= maxHeight -> no growth, no counter change.
    {
        auto h = st;
        h.height = 10;
        const auto r = grow(h, 1000.0, 975.0, g, false);
        assert(r.outcome == GrowthOutcome::no_growth);
        assert(close(r.state.growth_counter, 1.0f));
    }
    // elapsed <= 0 -> no growth.
    {
        const auto r = grow(st, 1000.0, 1000.0, g, false);
        assert(r.outcome == GrowthOutcome::no_growth);
    }

    std::printf("tree_growth: PASS (prediction-pinned 0.140625 / 0.05625)\n");
    return 0;
}
