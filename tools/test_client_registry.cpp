// Contract tests for the recovered client-registry slice (E30/E33/E39).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_client_registry.cpp
//       reconstruction/recovered/client_registry.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "client_registry.h"

#include <cassert>
#include <utility>
#include <vector>

using blockheads::recovered::ClientRegistry;
using blockheads::recovered::kBanPropagationCell;
using blockheads::recovered::kMutePropagationCell;
using blockheads::recovered::kOwnerNameCell;
using blockheads::recovered::kPlayersChangedCell;

static void test_server_gate() {
    ClientRegistry reg;
    // Without the server slot the users/bans operations refuse (E33).
    assert(!reg.serverPresent());
    assert(!reg.addClient(1, "alice"));
    assert(!reg.muteChanged(1, [](std::uint64_t, std::int64_t) {}));
    assert(!reg.banChanged(1, true, [](std::uint64_t, std::int64_t) {}));
    assert(!reg.banQuery(1).has_value());
    assert(!reg.ownerName(1).has_value());
    reg.setServerPresent(true);
    assert(reg.serverPresent());
    assert(reg.addClient(1, "alice"));
}

static void test_mute_and_ban_notifications() {
    ClientRegistry reg;
    reg.setServerPresent(true);
    reg.addClient(7, "bob");
    std::vector<std::pair<std::uint64_t, std::int64_t>> notices;
    assert(reg.muteChanged(7, [&](std::uint64_t id, std::int64_t cell) {
        notices.emplace_back(id, cell);
    }));
    assert(notices.size() == 1);
    assert(notices[0].first == 7);
    assert(notices[0].second == kMutePropagationCell);
    notices.clear();
    assert(reg.banChanged(7, true, [&](std::uint64_t id, std::int64_t cell) {
        notices.emplace_back(id, cell);
    }));
    assert(notices.size() == 1 && notices[0].second == kBanPropagationCell);
    // unknown client: no notification, no flag change.
    assert(!reg.muteChanged(999, [&](std::uint64_t, std::int64_t) { assert(false); }));
    assert(!reg.banChanged(999, true, [&](std::uint64_t, std::int64_t) { assert(false); }));
}

static void test_ban_query_and_owner_name() {
    ClientRegistry reg;
    reg.setServerPresent(true);
    reg.addClient(3, "carol");
    assert(reg.banQuery(3).has_value() && *reg.banQuery(3) == false);
    reg.banChanged(3, true, [](std::uint64_t, std::int64_t) {});
    assert(reg.banQuery(3).has_value() && *reg.banQuery(3) == true);
    assert(reg.banQuery(42) == std::nullopt);
    assert(reg.ownerName(3).has_value() && *reg.ownerName(3) == "carol");
    assert(!reg.ownerName(42).has_value());
}

static void test_players_changed_fanout() {
    ClientRegistry reg;
    reg.setServerPresent(true);
    reg.addClient(1, "a");
    reg.addClient(2, "b");
    int notices = 0;
    reg.playersChanged([&](std::uint64_t, std::int64_t cell) {
        ++notices;
        assert(cell == kPlayersChangedCell);
    });
    assert(notices == 2);
    // without the server slot: no fan-out.
    ClientRegistry off;
    off.playersChanged([&](std::uint64_t, std::int64_t) { assert(false); });
}

static void test_pole_taken_and_workbench_flag() {
    ClientRegistry reg;
    assert(!reg.poleTakenRecorded(5));
    reg.poleTaken(5, 123);
    assert(reg.poleTakenRecorded(5));
    // the workbench flag pair (E39 getter / E30 writer).
    assert(!reg.workbenchHasBeenCrafted());
    reg.setWorkbenchHasBeenCrafted(true);
    assert(reg.workbenchHasBeenCrafted());
}

int main() {
    test_server_gate();
    test_mute_and_ban_notifications();
    test_ban_query_and_owner_name();
    test_players_changed_fanout();
    test_pole_taken_and_workbench_flag();
    return 0;
}
