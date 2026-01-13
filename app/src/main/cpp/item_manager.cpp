#include "item_manager.h"

void ItemManager::init() {
    items[1] = {1, "Dirt", 0};
    items[2] = {2, "Stone", 1};
    items[3] = {3, "Wood", 2};
    items[4] = {4, "Leaves", 3};
    items[5] = {5, "Grass", 4};
    items[7] = {7, "Copper Ore", 10};
    items[8] = {8, "Iron Ore", 11};
    items[10] = {10, "Workbench", 16};
    items[11] = {11, "Toolbench", 17};
    items[20] = {20, "Torch", 20};
    items[21] = {21, "Flint", 21};
    items[22] = {22, "Stick", 22};
    items[50] = {50, "Flint Pickaxe", 50};
    items[51] = {51, "Flint Axe", 51};
    items[52] = {52, "Flint Spade", 52};
    items[100] = {100, "Time Crystal", 32};
}

std::string ItemManager::getName(int id) {
    if (items.count(id)) return items[id].name;
    return "Unknown Item";
}