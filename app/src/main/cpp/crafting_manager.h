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
        recipes.push_back({21, "Craftbench", ITEM_CRAFTBENCH, 1, {{BLOCK_WOOD, 1}, {ITEM_DIRT, 1}}, 10, 10.0f});
        recipes.push_back({22, "Wire", ITEM_COPPER_WIRE, 5, {{ITEM_COPPER_ORE, 1}}, 10, 5.0f});
        recipes.push_back({23, "Generator", ITEM_COAL_GENERATOR, 1, {{ITEM_COPPER_WIRE, 10}, {ITEM_STONE, 5}}, 10, 20.0f});
        recipes.push_back({24, "Furnace", ITEM_FURNACE, 1, {{ITEM_STONE, 5}, {ITEM_DIRT, 1}}, 10, 10.0f});
        
        // Toolbench (Bench 11)
        recipes.push_back({10, "Flint Pickaxe", ITEM_PICKAXE, 1, {{ITEM_STICK, 1}, {ITEM_FLINT, 2}}, 11, 5.0f});
        recipes.push_back({11, "Flint Axe", 51, 1, {{ITEM_STICK, 1}, {ITEM_FLINT, 2}}, 11, 5.0f});
        recipes.push_back({12, "Flint Spade", 52, 1, {{ITEM_STICK, 1}, {ITEM_FLINT, 2}}, 11, 5.0f});
        
        recipes.push_back({110, "Iron Pickaxe", ITEM_IRON_PICKAXE, 1, {{ITEM_STICK, 1}, {ITEM_IRON_INGOT, 2}}, 11, 15.0f});
        recipes.push_back({111, "Iron Axe", ITEM_IRON_AXE, 1, {{ITEM_STICK, 1}, {ITEM_IRON_INGOT, 2}}, 11, 15.0f});
        recipes.push_back({112, "Iron Spade", ITEM_IRON_SPADE, 1, {{ITEM_STICK, 1}, {ITEM_IRON_INGOT, 2}}, 11, 15.0f});

        recipes.push_back({120, "Steel Pickaxe", ITEM_STEEL_PICKAXE, 1, {{ITEM_STICK, 1}, {ITEM_STEEL_INGOT, 2}}, 11, 25.0f});
        recipes.push_back({121, "Steel Axe", ITEM_STEEL_AXE, 1, {{ITEM_STICK, 1}, {ITEM_STEEL_INGOT, 2}}, 11, 25.0f});
        recipes.push_back({122, "Steel Spade", ITEM_STEEL_SPADE, 1, {{ITEM_STICK, 1}, {ITEM_STEEL_INGOT, 2}}, 11, 25.0f});

        // Craftbench (Bench 15)
        
        // Furnace (Bench 16)
        recipes.push_back({40, "Copper Ingot", ITEM_COPPER_INGOT, 1, {{ITEM_COPPER_ORE, 1}, {ITEM_COAL, 1}}, 16, 10.0f});
        recipes.push_back({41, "Tin Ingot", ITEM_TIN_INGOT, 1, {{ITEM_TIN_ORE, 1}, {ITEM_COAL, 1}}, 16, 10.0f});
        recipes.push_back({42, "Iron Ingot", ITEM_IRON_INGOT, 1, {{ITEM_IRON_ORE, 1}, {ITEM_COAL, 1}}, 16, 15.0f});

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
