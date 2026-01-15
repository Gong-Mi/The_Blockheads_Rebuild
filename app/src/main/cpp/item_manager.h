#ifndef ITEM_MANAGER_H
#define ITEM_MANAGER_H

#include <string>
#include "game_item_ids.h" // Generated Enums

class ItemManager {
public:
    struct ItemDef {
        int id;
        std::string name;
        int texRow;
        int texCol;
        bool isBlock;
        bool isFood;
        float hungerRestore;
        int preferredTool;
        int renderType;
    };

    static ItemManager& getInstance() {
        static ItemManager instance;
        return instance;
    }

    // Now pure lookup, no init needed
    const ItemDef* getDef(int id);
    std::string getName(int id);
};

// Extern generated data
extern ItemManager::ItemDef g_itemDefs[ITEM_COUNT_MAX];

#endif