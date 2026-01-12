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
        // --- 还原自 ID 挖掘结果 ---
        items[1] = {1, "Dirt", 0};
        items[2] = {2, "Stone", 1};
        items[3] = {3, "Wood", 2};
        items[4] = {4, "Flint", 3};
        items[10] = {10, "Workbench", 16};
        items[100] = {100, "Time Crystal", 32};
        // ... 此处可以继续根据 items_data.json 扩充 500 个物品
    }

    std::string getName(int id) {
        if (items.count(id)) return items[id].name;
        return "Unknown Item";
    }
};
