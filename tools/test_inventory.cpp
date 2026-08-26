#include <cassert>
#include "entity_manager.h"

static void expectStack(const Player& player, int slot, int type, int count) {
    assert(player.slots[slot] == type);
    assert(player.counts[slot] == count);
}

int main() {
    Player player;

    player.addItem(42, 250);
    expectStack(player, 0, 42, 99);
    expectStack(player, 1, 42, 99);
    expectStack(player, 2, 42, 52);

    Player stacking;
    stacking.slots[0] = 42;
    stacking.counts[0] = 90;
    stacking.addItem(42, 20);
    expectStack(stacking, 0, 42, 99);
    expectStack(stacking, 1, 42, 11);

    Player full;
    for (int i = 0; i < Player::INVENTORY_SIZE; ++i) {
        full.slots[i] = 7;
        full.counts[i] = 99;
    }
    full.addItem(42, 1);
    for (int i = 0; i < Player::INVENTORY_SIZE; ++i) {
        assert(full.slots[i] == 7);
        assert(full.counts[i] == 99);
    }

    return 0;
}
