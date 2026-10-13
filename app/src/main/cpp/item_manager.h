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
        // Original inventory ItemType, never TileType or atlas image index.
        // -1 is unmapped; 0 is the empty sentinel. Existing id stays world.bin-compatible.
        int originalType = -1;
    };

    static ItemManager& getInstance() {
        static ItemManager instance;
        return instance;
    }

    // Now pure lookup, no init needed
    const ItemDef* getDef(int id);
    std::string getName(int id);

    // Explicit namespace boundary: unknown/unmapped -> -1, no numeric fallback.
    int toOriginalType(int rebuildId) const;
    int fromOriginalType(int originalType) const;
    const ItemDef* getDefFromOriginalType(int originalType);
};

// Extern generated data
extern ItemManager::ItemDef g_itemDefs[ITEM_COUNT_MAX];

#endif