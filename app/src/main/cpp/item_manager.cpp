#include "item_manager.h"

// g_itemDefs is defined in generated/game_item_data.cpp

const ItemManager::ItemDef* ItemManager::getDef(int id) {
    if (id < 0 || id >= ITEM_COUNT_MAX) return nullptr;
    if (g_itemDefs[id].id == 0) return nullptr; // Empty slot
    return &g_itemDefs[id];
}

std::string ItemManager::getName(int id) {
    const auto* def = getDef(id);
    return def ? def->name : "Unknown Item";
}
