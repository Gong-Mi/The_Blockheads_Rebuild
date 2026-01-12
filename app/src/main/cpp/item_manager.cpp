#include <string>
#include <map>

class ItemManager {
public:
    struct ItemDef {
        int id;
        std::string name;
        int textureIndex; // TileMap.png 中的位置
    };

    std::map<int, ItemDef> items;

    void init() {
        items[1] = {1, "Dirt", 0};
        items[2] = {2, "Stone", 1};
        items[4] = {4, "Flint", 3};
        items[7] = {7, "Copper Ore", 10};
        items[8] = {8, "Iron Ore", 11};
        items[100] = {100, "Time Crystal", 32};
    }

    std::string getName(int id) {
        if (items.count(id)) return items[id].name;
        return "Unknown Item";
    }
};
