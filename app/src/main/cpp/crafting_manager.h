#ifndef CRAFTING_MANAGER_H
#define CRAFTING_MANAGER_H

#include <vector>
#include <string>
#include <sstream>
#include "entity_manager.h"
#include "game_constants.h"

struct Ingredient {
    int itemId;
    int count;
};

struct Recipe {
    int id;
    std::string name;
    int resultItemId;
    int resultCount;
    int workbenchId; 
    int workbenchLevel;
    std::vector<Ingredient> ingredients;
    int duration;
};

class CraftingManager {
public:
    std::vector<Recipe> recipes;

    CraftingManager() {
        init();
    }

    void init() {
        int idCounter = 1;
        // Hand (0)
        recipes.push_back({idCounter++, "Workbench", ITEM_WORKBENCH, 1, 0, 1, {{ITEM_DIRT, 1}}, 30}); 
        
        // Workbench (10)
        recipes.push_back({idCounter++, "Tool Bench", ITEM_TOOLBENCH, 1, ITEM_WORKBENCH, 1, {{BLOCK_WOOD, 1}, {ITEM_DIRT, 1}}, 60}); 
        recipes.push_back({idCounter++, "Torch", ITEM_TORCH, 4, ITEM_WORKBENCH, 1, {{BLOCK_WOOD, 1}, {ITEM_DIRT, 1}}, 40}); 
        
        // Tool Bench (11)
        recipes.push_back({idCounter++, "Stone Pickaxe", ITEM_PICKAXE, 1, ITEM_TOOLBENCH, 1, {{ITEM_STONE, 3}, {BLOCK_WOOD, 2}}, 120});
    }

    std::string getRecipesJson(int benchId) {
        std::stringstream ss;
        char q = '"';
        ss << "[";
        bool first = true;
        for (const auto& r : recipes) {
            if (r.workbenchId == benchId) {
                if (!first) ss << ",";
                first = false;
                ss << "{" << q << "id" << q << ":" << r.id << "," << q << "name" << q << ":" << q << r.name << q << "," << q << "outId" << q << ":" << r.resultItemId << "," << q << "outCount" << q << ":" << r.resultCount << "," << q << "cost" << q << ":[";
                for (size_t i = 0; i < r.ingredients.size(); ++i) {
                    if (i > 0) ss << ",";
                    ss << "{" << q << "id" << q << ":" << r.ingredients[i].itemId << "," << q << "n" << q << ":" << r.ingredients[i].count << "}";
                }
                ss << "]}";
            }
        }
        ss << "]";
        return ss.str();
    }

    bool canCraft(Player* p, int recipeId) {
        for (const auto& r : recipes) {
            if (r.id == recipeId) {
                for (const auto& ing : r.ingredients) {
                    int has = 0;
                    for (int i = 0; i < 10; i++) if (p->slots[i] == ing.itemId) has += p->counts[i];
                    if (has < ing.count) return false;
                }
                return true;
            }
        }
        return false;
    }

    bool craft(Player* p, int recipeId) {
        for (const auto& r : recipes) {
            if (r.id == recipeId) {
                if (!canCraft(p, recipeId)) return false;
                for (const auto& ing : r.ingredients) {
                    int needed = ing.count;
                    for (int i = 0; i < 10 && needed > 0; i++) {
                        if (p->slots[i] == ing.itemId) {
                            int take = std::min(needed, p->counts[i]);
                            p->counts[i] -= take; needed -= take;
                            if (p->counts[i] <= 0) p->slots[i] = 0;
                        }
                    }
                }
                p->addItem(r.resultItemId, r.resultCount);
                return true;
            }
        }
        return false;
    }
};

#endif