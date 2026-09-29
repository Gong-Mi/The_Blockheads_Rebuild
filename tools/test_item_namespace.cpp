// Real generated ItemManager/Player bridge; not an original InventoryItem codec.
#ifdef NDEBUG
#error assertions must remain enabled
#endif
#include <cassert>
#include <climits>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include "item_manager.h"
#include "entity_manager.h"

int main(int argc, char** argv) {
    assert(argc == 2);
    std::ifstream input(argv[1]);
    assert(input);
    std::string line;
    std::getline(input, line);
    std::map<int, int> forward, reverse;
    auto& manager = ItemManager::getInstance();
    while (std::getline(input, line)) {
        std::istringstream stream(line);
        std::vector<std::string> fields;
        std::string field;
        while (std::getline(stream, field, '\t')) fields.push_back(field);
        assert(fields.size() >= 4);
        const int legacy = std::stoi(fields[0]);
        const int original = fields[3] == "null" ? -1 : std::stoi(fields[3]);
        assert(forward.emplace(legacy, original).second);
        assert(manager.toOriginalType(legacy) == original);
        Player player;
        if (original >= 0) {
            assert(reverse.emplace(original, legacy).second);
            assert(manager.fromOriginalType(original) == legacy);
            if (original == 0) {
                assert(manager.getDefFromOriginalType(original) == nullptr);
                assert(player.addOriginalItem(original, 1) == 0);
                assert(player.originalItemType(0) == 0);
            } else {
                const auto* def = manager.getDefFromOriginalType(original);
                assert(def && def->id == legacy && def->originalType == original);
                assert(player.addOriginalItem(original, 1) == 1);
                assert(player.slots[0] == legacy && player.counts[0] == 1);
                assert(player.originalItemType(0) == original);
            }
        } else {
            assert(player.addItem(legacy, 1) == 1);
            assert(player.originalItemType(0) == -1); // unmapped is never silently coerced to air
        }
    }
    assert(forward.size() == 87 && reverse.size() == 69);
    for (int legacy = 0; legacy < ITEM_COUNT_MAX; ++legacy) {
        const auto it = forward.find(legacy);
        assert(manager.toOriginalType(legacy) == (it == forward.end() ? -1 : it->second));
    }
    // Full uint16 saved-id input domain, including gaps and the server sentinels.
    for (int original = 0; original <= 65535; ++original) {
        const auto it = reverse.find(original);
        assert(manager.fromOriginalType(original) == (it == reverse.end() ? -1 : it->second));
    }
    for (int invalid : {-1, INT_MIN, INT_MAX}) {
        assert(manager.fromOriginalType(invalid) == -1);
        assert(manager.toOriginalType(invalid) == -1);
    }
    // The numeric collision that previously disguised CopperOre as Dodo Meat.
    assert(manager.getDef(31)->id == ITEM_DODO_MEAT);
    assert(manager.getDefFromOriginalType(31)->id == ITEM_COPPER_ORE);
    assert(manager.getDefFromOriginalType(1024)->id == ITEM_STONE);
    assert(manager.getDefFromOriginalType(1048)->id == ITEM_DIRT);
    assert(manager.getDefFromOriginalType(1088)->id == ITEM_ELEVATOR_MOTOR);
    Player p;
    assert(p.addOriginalItem(31, 101) == 101);
    assert(p.slots[0] == ITEM_COPPER_ORE && p.counts[0] == 99);
    assert(p.slots[1] == ITEM_COPPER_ORE && p.counts[1] == 2);
    assert(p.addOriginalItem(344, 1) == 0);
    assert(p.addOriginalItem(1106, 1) == 0);
    assert(p.addOriginalItem(-1, 1) == 0);
    assert(p.addOriginalItem(31, 0) == 0);
    assert(p.addOriginalItem(31, -1) == 0);
    assert(p.originalItemType(-1) == -1 && p.originalItemType(Player::INVENTORY_SIZE) == -1);
    for (int i = 0; i < Player::INVENTORY_SIZE; ++i) {
        p.slots[i] = ITEM_DIRT;
        p.counts[i] = 99;
    }
    assert(p.addOriginalItem(1048, 1) == 0);
    // New-world startup call change must preserve all legacy inventory bytes.
    Player old_start, new_start;
    old_start.addItem(ITEM_STICK, 10);
    old_start.addItem(ITEM_FLINT, 10);
    old_start.addItem(BLOCK_WOOD, 10);
    new_start.addOriginalItem(ORIGINAL_ITEM_STICK, 10);
    new_start.addOriginalItem(ORIGINAL_ITEM_FLINT, 10);
    new_start.addOriginalItem(ORIGINAL_BLOCK_WOOD, 10);
    for (int i = 0; i < Player::INVENTORY_SIZE; ++i) {
        assert(old_start.slots[i] == new_start.slots[i]);
        assert(old_start.counts[i] == new_start.counts[i]);
    }
    std::cout << "item-namespace: PASS (87 decisions; 65536 raw ids; real Player import/export; legacy startup unchanged)\n";
}
