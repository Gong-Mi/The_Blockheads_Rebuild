#include <vector>
#include <map>
#include <string>

struct Ingredient {
    int itemId;
    int count;
};

struct Recipe {
    int resultItemId;
    int resultCount;
    int requiredWorkbench; // 0 为手工，10 为基础工作台...
    std::vector<Ingredient> ingredients;
    int craftTime; // 对应我们之前挖掘出的 time 字段
};

class CraftingManager {
public:
    std::vector<Recipe> recipes;

    void init() {
        // --- 基于原版逻辑的手动还原示例 ---
        
        // 示例：合成火把 (假设 ID 20 是火把)
        // 材料：1个木头 (ID 3) + 1个煤炭 (ID 5)
        Recipe torch;
        torch.resultItemId = 20;
        torch.resultCount = 3;
        torch.requiredWorkbench = 10; // 需要工作台
        torch.ingredients = {{3, 1}, {5, 1}};
        torch.craftTime = 60;
        recipes.push_back(torch);

        // 示例：合成石镐 (假设 ID 50 是石镐)
        // 材料：2个树枝 (ID 6) + 1个石头 (ID 2)
        Recipe stonePickaxe;
        stonePickaxe.resultItemId = 50;
        stonePickaxe.resultCount = 1;
        stonePickaxe.requiredWorkbench = 10;
        stonePickaxe.ingredients = {{6, 2}, {2, 1}};
        stonePickaxe.craftTime = 120;
        recipes.push_back(stonePickaxe);
    }

    // 检查玩家是否拥有足够材料
    bool canCraft(const Recipe& recipe, const std::map<int, int>& playerInventory) {
        for (const auto& ing : recipe.ingredients) {
            if (!playerInventory.count(ing.itemId) || playerInventory.at(ing.itemId) < ing.count) {
                return false;
            }
        }
        return true;
    }
};
