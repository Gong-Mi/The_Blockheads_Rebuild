#ifndef ITEM_MANAGER_H
#define ITEM_MANAGER_H

#include <string>
#include <map>

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
        int preferredTool; // e.g., ITEM_PICKAXE
    };

    std::map<int, ItemDef> items;
    static ItemManager& getInstance() {
        static ItemManager instance;
        return instance;
    }

    void init();
    const ItemDef* getDef(int id);
    std::string getName(int id);
};

#endif
