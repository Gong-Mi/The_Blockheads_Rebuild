#ifndef ITEM_MANAGER_H
#define ITEM_MANAGER_H

#include <string>
#include <map>

class ItemManager {
public:
    struct ItemDef {
        int id;
        std::string name;
        int textureIndex;
    };

    std::map<int, ItemDef> items;

    void init();
    std::string getName(int id);
};

#endif
