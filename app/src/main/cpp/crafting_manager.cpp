#include <vector>
#include <map>
#include <string>

struct Ingredient {
    int itemId;
    int count;
};

struct Recipe {
    std::string name;
    int resultItemId;
    int resultCount;
    int workbenchId; // 10:Portal, 11:Tool, 12:Craft, 13:Furnace...
    int workbenchLevel;
    std::vector<Ingredient> ingredients;
    int duration; // 帧数
};

class CraftingManager {
public:
    std::vector<Recipe> recipes;

    void init() {
        // --- 1. 传送门基础合成 (Portal Level 1) ---
        recipes.push_back({"Dirt Workbench", 10, 1, 0, 0, {{1, 1}}, 30});

        // --- 2. 工具台合成 (Tool Bench Level 1) ---
        recipes.push_back({"Flint Pickaxe", 50, 1, 11, 1, {{6, 2}, {4, 1}}, 120});
        recipes.push_back({"Flint Axe", 51, 1, 11, 1, {{6, 2}, {4, 1}}, 100});
        recipes.push_back({"Flint Spade", 52, 1, 11, 1, {{6, 1}, {4, 1}}, 80});

        // --- 3. 基础材料加工 (Craft Bench Level 1) ---
        recipes.push_back({"Wood Planks", 3, 4, 12, 1, {{3, 1}}, 60});
        recipes.push_back({"Torch", 20, 3, 12, 1, {{6, 1}, {5, 1}}, 40});

        // --- 4. 冶炼系统 (Furnace Level 1) ---
        recipes.push_back({"Copper Ingot", 70, 1, 13, 1, {{7, 3}, {5, 1}}, 300});
        recipes.push_back({"Iron Ingot", 71, 1, 13, 1, {{8, 3}, {5, 2}}, 400});

        // --- 5. 纺织与裁剪 (Tailor Bench) ---
        recipes.push_back({"Linen Cloth", 80, 1, 14, 1, {{85, 5}}, 200});
        
        // ... 此处可以根据 items_data.json 继续扩充至数百个 ...
    }

    Recipe* getRecipeForResult(int itemId) {
        for (auto& r : recipes) {
            if (r.resultItemId == itemId) return &r;
        }
        return nullptr;
    }
};