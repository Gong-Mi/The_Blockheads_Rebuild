#include "item_manager.h"

void ItemManager::init() {
    // ID, Name, row, col, isBlock, isFood, hunger, tool
    items[1] = {1, "Dirt", 0, 0, true, false, 0, 52};
    items[2] = {2, "Stone", 0, 1, true, false, 0, 50};
    items[3] = {3, "Wood", 0, 2, true, false, 0, 51};
    items[4] = {4, "Leaves", 0, 3, true, false, 0, 51};
    items[5] = {5, "Grass", 0, 4, true, false, 0, 52};
    items[6] = {6, "Sand", 1, 0, true, false, 0, 52};
    items[7] = {7, "Copper Ore", 1, 1, true, false, 0, 50};
    items[8] = {8, "Tin Ore", 1, 2, true, false, 0, 50};
    items[9] = {9, "Snow", 1, 3, true, false, 0, 52};
    items[12] = {12, "Ice", 1, 4, true, false, 0, 50};
    items[13] = {13, "Cactus", 1, 5, true, false, 0, 51};
    items[14] = {14, "Glass", 1, 6, true, false, 0, 50};
    items[33] = {33, "Fur", 1, 7, false, false, 0, 0};
    
    items[10] = {10, "Workbench", 2, 0, true, false, 0, 0};
    items[11] = {11, "Toolbench", 2, 1, true, false, 0, 0};
    items[15] = {15, "Craftbench", 2, 2, true, false, 0, 0};
    items[60] = {60, "Fur Cap", 2, 3, false, false, 0, 0};
    items[61] = {61, "Fur Pants", 2, 4, false, false, 0, 0};

    items[20] = {20, "Torch", 3, 0, true, false, 0, 0};
    items[21] = {21, "Flint", 3, 1, false, false, 0, 0};
    items[22] = {22, "Stick", 3, 2, false, false, 0, 0};
    items[23] = {23, "Campfire", 3, 3, true, false, 0, 0};

    items[30] = {30, "Chili", 4, 0, false, true, 0.2f, 0};
    items[31] = {31, "Meat", 4, 1, false, true, 0.35f, 0};
    items[32] = {32, "Coconut", 4, 2, false, true, 0.25f, 0};

    items[50] = {50, "Pickaxe", 5, 0, false, false, 0, 0};
    items[51] = {51, "Axe", 5, 1, false, false, 0, 0};
    items[52] = {52, "Spade", 5, 2, false, false, 0, 0};

    items[70] = {70, "Coal", 6, 0, false, false, 0, 0};
    items[71] = {71, "Wire", 6, 1, true, false, 0, 0};
    items[72] = {72, "Generator", 6, 2, true, false, 0, 0};
    items[73] = {73, "Electric Lamp", 6, 3, true, false, 0, 0};
}

const ItemManager::ItemDef* ItemManager::getDef(int id) {
    if (items.count(id)) return &items[id];
    return nullptr;
}

std::string ItemManager::getName(int id) {
    auto def = getDef(id);
    return def ? def->name : "Unknown Item";
}