#ifndef CRAFTING_MANAGER_H
#define CRAFTING_MANAGER_H

#include <vector>
#include <string>
#include <algorithm>
#include "entity_manager.h"

struct Recipe {
    int id;
    std::string name;
    int outType;
    int outCount;
    std::vector<std::pair<int, int>> ingredients; 
    int requiredBench; 
    float time; 
};

class CraftingManager {
public:
    std::vector<Recipe> recipes;

    CraftingManager() {
        // Hand Crafting (Bench 0)
        recipes.push_back({100, "Workbench", ITEM_WORKBENCH, 1, {{ITEM_DIRT, 1}}, 0, 1.0f});
        recipes.push_back({101, "Campfire", ITEM_CAMPFIRE, 1, {{ITEM_STICK, 5}}, 0, 5.0f});
        recipes.push_back({1, "Stick", ITEM_STICK, 1, {{BLOCK_WOOD, 1}}, 0, 1.0f});
        recipes.push_back({2, "Torch", ITEM_TORCH, 2, {{ITEM_STICK, 1}, {ITEM_FLINT, 1}}, 0, 2.0f});
        
        // Workbench (Bench 10)
        recipes.push_back({20, "Toolbench", ITEM_TOOLBENCH, 1, {{ITEM_STICK, 1}, {ITEM_FLINT, 1}}, 10, 10.0f});
        
        // Toolbench (Bench 11)
        recipes.push_back({10, "Flint Pickaxe", ITEM_PICKAXE, 1, {{ITEM_STICK, 1}, {ITEM_FLINT, 2}}, 11, 5.0f});
        recipes.push_back({11, "Flint Axe", 51, 1, {{ITEM_STICK, 1}, {ITEM_FLINT, 2}}, 11, 5.0f});
        recipes.push_back({12, "Flint Spade", 52, 1, {{ITEM_STICK, 1}, {ITEM_FLINT, 2}}, 11, 5.0f});

        // Campfire (Bench 23)
        // Note: ID 14 is Glass block (reusing/defining it implicitly if not in constants yet, 
        // assuming standard ID or adding it. Let's assume 14 for Glass).
        // Sand is BLOCK_SAND (6).
        recipes.push_back({30, "Glass", 14, 1, {{BLOCK_SAND, 5}}, 23, 10.0f}); 
    }

    bool canCraft(Player* p, int recipeId) {
        for (const auto& r : recipes) {
            if (r.id == recipeId) {
                for (const auto& ing : r.ingredients) {
                    int found = 0;
                    for (int i = 0; i < 10; i++) {
                        if (p->slots[i] == ing.first) found += p->counts[i];
                    }
                    if (found < ing.second) return false;
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
                    int remaining = ing.second;
                    for (int i = 0; i < 10; i++) {
                        if (p->slots[i] == ing.first) {
                            int take = std::min(remaining, p->counts[i]);
                            p->counts[i] -= take;
                            remaining -= take;
                            if (p->counts[i] == 0) p->slots[i] = 0;
                            if (remaining == 0) break;
                        }
                    }
                }
                p->addItem(r.outType, r.outCount);
                return true;
            }
        }
        return false;
    }

    std::string getRecipesJson(int benchId) {
        std::string json = "[";
        bool firstRecipe = true;
        for (const auto& r : recipes) {
            if (r.requiredBench == benchId) {
                if (!firstRecipe) json += ",";
                json += "{\"id\":" + std::to_string(r.id);
                json += ",\"name\":\"" + r.name + "\"";
                json += ",\"outCount\":" + std::to_string(r.outCount);
                json += ",\"cost\":[";
                for (size_t j=0; j<r.ingredients.size(); j++) {
                    if (j > 0) json += ",";
                    json += "{\"id\":" + std::to_string(r.ingredients[j].first);
                    json += ",\"n\":" + std::to_string(r.ingredients[j].second) + "}";
                }
                json += "]}";
                firstRecipe = false;
            }
        }
        json += "]";
        return json;
    }
};

#endif
