// Contract tests for the recovered world-change queue slice (E21/E22/E23).
// Run:
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off \
//     -Ireconstruction/recovered tools/test_world_change_queues.cpp \
//     reconstruction/recovered/world_change_queues.cpp -o "$TMPDIR/t"
//   "$TMPDIR/t"
#include "world_change_queues.h"

#include <cassert>
#include <cstdio>
#include <vector>

using blockheads::recovered::WorldChangePair;
using blockheads::recovered::WorldChangeQueues;
using blockheads::recovered::macroPairForWorldPos;

static void test_macro_conversion_truncates_toward_zero() {
    // E22/E23: __aeabi_idiv semantics.
    WorldChangePair p = macroPairForWorldPos(63, -63);
    assert(p.x == 1);
    assert(p.y == -1);
    p = macroPairForWorldPos(-1, -32);
    assert(p.x == 0);   // -1/32 truncates to 0
    assert(p.y == -1);  // -32/32 == -1
    p = macroPairForWorldPos(-33, 32);
    assert(p.x == -1);
    assert(p.y == 1);
}

static void test_exact_dedup_and_routing() {
    WorldChangeQueues q;
    q.worldChangedAtPos(5, 7, true);
    q.worldChangedAtPos(5, 7, true);   // same exact pair: nothing new
    assert(q.worldChangedPositions().size() == 1);
    assert(q.reliableMacroQueue().size() == 1);
    assert((q.reliableMacroQueue()[0] == WorldChangePair{0, 0}));
    assert(q.unreliableMacroQueue().empty());

    q.worldChangedAtPos(40, 70, false);  // new pair, unreliable route
    assert(q.worldChangedPositions().size() == 2);
    assert(q.unreliableMacroQueue().size() == 1);
    assert((q.unreliableMacroQueue()[0] == WorldChangePair{1, 2}));

    // a second exact pair inside the same macro cell dedups at the macro queue level
    q.worldChangedAtPos(41, 71, false);
    assert(q.unreliableMacroQueue().size() == 1);

    q.worldChangedAtPos(41, 71, true);  // same macro cell on the reliable side
    assert(q.reliableMacroQueue().size() == 2);
}

static void test_water_full_block_gate() {
    WorldChangeQueues q;
    q.waterChangedAtPos(64, 128, false);
    assert(q.waterChangedPositions().empty());
    assert(q.unreliableMacroQueue().size() == 1);  // macro routing still runs
    q.waterChangedAtPos(64, 128, true);
    assert(q.waterChangedPositions().size() == 1);
    q.waterChangedAtPos(64, 128, true);  // dedup
    assert(q.waterChangedPositions().size() == 1);
    assert(q.unreliableMacroQueue().size() == 1);
}

static void test_light_changed_macro_input() {
    WorldChangeQueues q;
    q.lightChangedAtMacroPos(3, 4, true, false);
    assert(q.reliableMacroQueue().size() == 1);
    assert((q.reliableMacroQueue()[0] == WorldChangePair{3, 4}));
    q.lightChangedAtMacroPos(3, 4, true, false);  // dedup
    assert(q.reliableMacroQueue().size() == 1);
    q.lightChangedAtMacroPos(5, 6, false, true);
    assert(q.unreliableMacroQueue().size() == 1);
    assert(q.thirdMacroQueue().size() == 1);
}

static void test_flush_contract() {
    WorldChangeQueues q;
    q.worldChangedAtPos(0, 0, true);    // macro (0,0) reliable
    q.worldChangedAtPos(64, 64, true);  // macro (2,2) reliable
    q.worldChangedAtPos(96, 96, false); // macro (3,3) unreliable

    int calls = 0;
    std::vector<std::pair<WorldChangePair, std::vector<int>>> seen;
    auto save = [&](const WorldChangePair& macro, bool reliable, bool dontSend,
                    bool onlyIfNeeded) -> int {
        ++calls;
        seen.push_back({macro, {reliable ? 1 : 0, dontSend ? 1 : 0, onlyIfNeeded ? 1 : 0}});
        // fail the unreliable entry once to prove the keep-on-zero contract
        if (!reliable && macro == WorldChangePair{3, 3} && calls < 4) {
            return 0;
        }
        return 1;
    };

    q.flush(false, save);  // server gate: non-server flush is a no-op
    assert(calls == 0);
    assert(q.reliableMacroQueue().size() == 2);

    q.flush(true, save);
    // pass 1 visits (0,0) then (2,2) with (1,0,1); pass 2 visits (3,3) with (0,0,1)
    assert(calls == 3);
    assert((seen[0].first == WorldChangePair{0, 0}));
    assert((seen[0].second == std::vector<int>{1, 0, 1}));
    assert((seen[1].first == WorldChangePair{2, 2}));
    assert((seen[1].second == std::vector<int>{1, 0, 1}));
    assert((seen[2].first == WorldChangePair{3, 3}));
    assert((seen[2].second == std::vector<int>{0, 0, 1}));
    // success erased both reliable entries; the failed unreliable entry stays
    assert(q.reliableMacroQueue().empty());
    assert(q.unreliableMacroQueue().size() == 1);

    q.flush(true, save);
    assert(q.unreliableMacroQueue().empty());  // second attempt succeeds
}

int main() {
    test_macro_conversion_truncates_toward_zero();
    test_exact_dedup_and_routing();
    test_water_full_block_gate();
    test_light_changed_macro_input();
    test_flush_contract();
    std::puts("test_world_change_queues: OK");
    return 0;
}
