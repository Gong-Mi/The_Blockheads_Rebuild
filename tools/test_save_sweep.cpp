// Contract tests for the recovered five-container save sweep (E22/E40).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_save_sweep.cpp
//       reconstruction/recovered/save_sweep.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "save_sweep.h"

#include <cassert>
#include <utility>
#include <vector>

using blockheads::recovered::FiveContainerSweep;
using blockheads::recovered::SweepContainer;
using blockheads::recovered::SweepPair;

static void test_pinned_sweep_order() {
    FiveContainerSweep sweep;
    sweep.container(SweepContainer::kReliable).push_back({1, 1});
    sweep.container(SweepContainer::kUnreliable).push_back({2, 2});
    sweep.container(SweepContainer::kDynamicChanged).push_back({3, 3});
    sweep.container(SweepContainer::kThirdQueue).push_back({4, 4});
    sweep.container(SweepContainer::kSnow).push_back({5, 5});
    std::vector<SweepContainer> order;
    sweep.sweep([&](SweepContainer which, std::size_t, const SweepPair&) {
        order.push_back(which);
    });
    // The E22 five-container scan order: 570, 574, 578(+0x120), 57c, 580.
    assert(order.size() == 5);
    assert(order[0] == SweepContainer::kReliable);
    assert(order[1] == SweepContainer::kUnreliable);
    assert(order[2] == SweepContainer::kDynamicChanged);
    assert(order[3] == SweepContainer::kThirdQueue);
    assert(order[4] == SweepContainer::kSnow);
}

static void test_elements_walk_in_insertion_order() {
    FiveContainerSweep sweep;
    auto& reliable = sweep.container(SweepContainer::kReliable);
    reliable.push_back({10, 10});
    reliable.push_back({20, 20});
    reliable.push_back({30, 30});
    std::vector<std::pair<std::size_t, SweepPair>> seen;
    sweep.sweep([&](SweepContainer which, std::size_t index, const SweepPair& pair) {
        if (which == SweepContainer::kReliable) {
            seen.emplace_back(index, pair);
        }
    });
    // the (end - start)/8 count walks start..end.
    assert(seen.size() == 3);
    assert(seen[0].first == 0 && seen[0].second.x == 10);
    assert(seen[1].first == 1 && seen[1].second.x == 20);
    assert(seen[2].first == 2 && seen[2].second.x == 30);
}

static void test_empty_containers_skip() {
    FiveContainerSweep sweep;
    sweep.container(SweepContainer::kSnow).push_back({7, 7});
    int calls = 0;
    sweep.sweep([&](SweepContainer which, std::size_t, const SweepPair&) {
        ++calls;
        assert(which == SweepContainer::kSnow);
    });
    assert(calls == 1);
    assert(sweep.totalElements() == 1);
    // fully empty sweep: no calls.
    FiveContainerSweep empty;
    empty.sweep([&](SweepContainer, std::size_t, const SweepPair&) { assert(false); });
    assert(empty.totalElements() == 0);
}

int main() {
    test_pinned_sweep_order();
    test_elements_walk_in_insertion_order();
    test_empty_containers_skip();
    return 0;
}
