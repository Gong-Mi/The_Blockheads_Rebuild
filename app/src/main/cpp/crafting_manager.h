#ifndef CRAFTING_MANAGER_H
#define CRAFTING_MANAGER_H

#include <vector>
#include <string>
#include <algorithm>
#include <map>
#include <cstdint>
#include <mutex>
#include "entity_manager.h"
#include "game_recipe_data.h"
#include "game_item_ids.h"

struct ActiveCraft {
    int recipeId;
    float progress; // 0.0 to 1.0
    float totalTime;
    bool finished;
};

class CraftingManager {
public:
    // Key is (x << 32 | y)
    std::map<uint64_t, ActiveCraft> activeCrafts;
    std::mutex craftMutex;

    CraftingManager() {}

    bool canCraft(Player* p, int recipeId) {
        for (int i = 0; i < g_recipeCount; ++i) {
            const auto& r = g_recipeData[i];
            if (r.id == recipeId) {
                for (int j = 0; j < r.ingredientCount; ++j) {
                    const auto& ing = r.ingredients[j];
                    int found = 0;
                    for (int slot = 0; slot < 30; slot++) { // Full inventory
                        if (p->slots[slot] == ing.itemId) found += p->counts[slot];
                    }
                    if (found < ing.count) return false;
                }
                return true;
            }
        }
        return false;
    }

    bool startCraft(Player* p, int recipeId, int tx, int ty) {
        std::lock_guard<std::mutex> lock(craftMutex);
        uint64_t key = ((uint64_t)tx << 32) | (uint64_t)ty;
        if (activeCrafts.count(key)) return false; // Already working

        for (int i = 0; i < g_recipeCount; ++i) {
            const auto& r = g_recipeData[i];
            if (r.id == recipeId) {
                if (!canCraft(p, recipeId)) return false;
                
                // Consume ingredients
                for (int j = 0; j < r.ingredientCount; ++j) {
                    const auto& ing = r.ingredients[j];
                    int remaining = ing.count;
                    for (int slot = 0; slot < 30; slot++) {
                        if (p->slots[slot] == ing.itemId) {
                            int take = std::min(remaining, p->counts[slot]);
                            p->counts[slot] -= take;
                            remaining -= take;
                            if (p->counts[slot] == 0) p->slots[slot] = ITEM_EMPTY;
                            if (remaining == 0) break;
                        }
                    }
                }
                
                ActiveCraft ac;
                ac.recipeId = recipeId;
                ac.progress = 0.0f;
                ac.totalTime = r.time;
                ac.finished = false;
                activeCrafts[key] = ac;
                return true;
            }
        }
        return false;
    }

    void update(float dt, Player* p) {
        std::lock_guard<std::mutex> lock(craftMutex);
        auto it = activeCrafts.begin();
        while (it != activeCrafts.end()) {
            ActiveCraft& ac = it->second;
            ac.progress += dt / ac.totalTime;
            
            if (ac.progress >= 1.0f) {
                ac.progress = 1.0f;
                if (!ac.finished) {
                    // Find recipe to get output
                    for (int i = 0; i < g_recipeCount; i++) {
                        if (g_recipeData[i].id == ac.recipeId) {
                            p->addItem(g_recipeData[i].outType, g_recipeData[i].outCount);
                            break;
                        }
                    }
                    ac.finished = true;
                }
                it = activeCrafts.erase(it); // Remove after finishing (one-shot for now)
            } else {
                ++it;
            }
        }
    }

    std::string getRecipesJson(int benchId) {
        std::string json = "[";
        bool firstRecipe = true;
        for (int i = 0; i < g_recipeCount; ++i) {
            const auto& r = g_recipeData[i];
            if (r.requiredBench == benchId) {
                if (!firstRecipe) json += ",";
                json += "{\"id\":" + std::to_string(r.id);
                json += ",\"name\":\"" + std::string(r.name) + "\"";
                json += ",\"outId\":" + std::to_string(r.outType);
                json += ",\"outCount\":" + std::to_string(r.outCount);
                json += ",\"time\":" + std::to_string(r.time);
                json += ",\"cost\":[";
                for (int j = 0; j < r.ingredientCount; ++j) {
                    if (j > 0) json += ",";
                    json += "{\"id\":" + std::to_string(r.ingredients[j].itemId);
                    json += ",\"n\":" + std::to_string(r.ingredients[j].count) + "}";
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
