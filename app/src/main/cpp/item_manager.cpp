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

int ItemManager::toOriginalType(int rebuildId) const {
    if (rebuildId < 0 || rebuildId >= ITEM_COUNT_MAX) return -1;
    return g_itemDefs[rebuildId].originalType;
}

int ItemManager::fromOriginalType(int originalType) const {
    if (originalType < 0) return -1;
    for (int id = 0; id < ITEM_COUNT_MAX; ++id) {
        if (g_itemDefs[id].originalType == originalType) return id;
    }
    return -1;
}

const ItemManager::ItemDef* ItemManager::getDefFromOriginalType(int originalType) {
    return getDef(fromOriginalType(originalType));
}
