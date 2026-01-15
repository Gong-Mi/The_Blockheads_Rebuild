#include "blockhead_ai.h"
#include <algorithm>
#include "item_manager.h"

void BlockheadAI::addAction(ActionType type, int tx, int ty) {
    // If we were sleeping and get a new action (that isn't sleep), wake up immediately
    if (isSleeping && type != ACTION_SLEEP) {
        isSleeping = false;
    }
    Action a = {type, tx, ty, 0};
    actionQueue.push(a);
}

bool BlockheadAI::update(float& outX, float& outY, GameWorld* world, EntityManager* entities) {
    if (!entities) return false;
    bool changed = false;
    
    posX = entities->player.x;
    posY = entities->player.y;

    // Interrupt sleep if queue has non-sleep items or empty (should stay sleeping if empty? No, sleep is an action)
    // Actually, let's treat Sleep as a continuous state until morning or interrupted.
    // If actionQueue is empty and we are sleeping, we stay sleeping? 
    // Simplified: Sleep is an Action that lasts until condition met.
    
    if (actionQueue.empty()) {
        currentStatus = ACTION_IDLE;
        entities->player.vx *= 0.8f; 
        if (isSleeping) {
             // If queue empty but isSleeping true, it means we reached the bed. 
             // Logic is handled in GameEngine for time accel. 
             // We just keep player still.
             entities->player.vx = 0;
             entities->player.vy = 0;
        }
        return false;
    }

    Action& current = actionQueue.front();
    
    // Target calculation with wrapping support
    float targetWorldX = (float)current.tx + 0.5f; 
    float dx = targetWorldX - posX;
    
    // Shortest path around circular world
    if (dx > 7500.0f) dx -= 15000.0f;
    if (dx < -7500.0f) dx += 15000.0f;

    float dist = std::abs(dx);
    float verticalDist = std::abs((float)current.ty - posY);

    // Walk logic
    if (dist > 0.5f && current.type != ACTION_SLEEP) { 
        isSleeping = false; // Moving breaks sleep
        currentStatus = ACTION_WALK;
        float speed = 0.02f;
        if (dx > 0) entities->player.vx += speed;
        else entities->player.vx -= speed;
        
        float maxSpeed = 0.3f;
        if (entities->player.vx > maxSpeed) entities->player.vx = maxSpeed;
        if (entities->player.vx < -maxSpeed) entities->player.vx = -maxSpeed;
        
        if (world) {
            int facingDir = (dx > 0) ? 1 : -1;
            int blockX = (int)floor(posX + facingDir * 0.6f);
            int blockY = (int)floor(posY);
            Tile* wall = world->getTile(blockX, blockY);
            if (wall && wall->foreground != 0 && entities->player.grounded) { // 0 is ITEM_EMPTY
                entities->player.vy = 0.6f; 
            }
        }
    } else if (current.type == ACTION_SLEEP && (dist > 0.5f || verticalDist > 1.5f)) {
        // Move towards bed
        currentStatus = ACTION_WALK;
        float speed = 0.02f;
        if (dx > 0.1f) entities->player.vx += speed;
        else if (dx < -0.1f) entities->player.vx -= speed;
        
        // Simple jumping if needed
        if (world && entities->player.grounded) {
             int facingDir = (dx > 0) ? 1 : -1;
             Tile* wall = world->getTile((int)(posX + facingDir*0.6f), (int)posY);
             if (wall && wall->foreground != 0) entities->player.vy = 0.6f;
             
             // Jump up to bed if it's higher
             if (current.ty > posY + 0.5f) entities->player.vy = 0.6f;
        }
        
    } else { 
        // Arrived at target
        entities->player.vx *= 0.5f; 
        
        if (current.type == ACTION_MINE) {
            currentStatus = ACTION_MINE;
            float baseSpeed = 2.0f; 
            if (world) {
                Tile* t = world->getTile(current.tx, current.ty);
                if (t && t->foreground != 0) { // 0 is ITEM_EMPTY
                    int selectedItem = entities->player.slots[entities->player.selectedSlot];
                    auto itemDef = ItemManager::getInstance().getDef(t->foreground);
                    if (itemDef && itemDef->preferredTool != 0) {
                        int p = itemDef->preferredTool;
                        int s = selectedItem;
                        if (s == p) baseSpeed = 25.0f; // Flint
                        // Check Bronze (230-232)
                        else if ((p==50 && s==230) || (p==51 && s==231) || (p==52 && s==232)) baseSpeed = 40.0f;
                        // Check Iron (240-242)
                        else if ((p==50 && s==240) || (p==51 && s==241) || (p==52 && s==242)) baseSpeed = 60.0f;
                        // Check Gold (260-262)
                        else if ((p==50 && s==260) || (p==51 && s==261) || (p==52 && s==262)) baseSpeed = 120.0f;
                    }
                    
                    current.progress += baseSpeed; 
                    if (t->damage < 240) {
                        t->damage = (uint8_t)std::min(255.0f, (float)t->damage + baseSpeed / 2.0f); 
                    } else {
                        // Harvest logic
                        if (t->foreground == 90) { // Flax Plant
                            if (t->growth >= 200) entities->spawnDrop((float)current.tx + 0.5f, (float)current.ty + 0.5f, 91); // Flax
                            entities->spawnDrop((float)current.tx + 0.5f, (float)current.ty + 0.5f, 90); // Seed
                        } else if (t->foreground == 92) { // Sunflower Plant
                            if (t->growth >= 200) entities->spawnDrop((float)current.tx + 0.5f, (float)current.ty + 0.5f, 93); // Sunflower
                            entities->spawnDrop((float)current.tx + 0.5f, (float)current.ty + 0.5f, 92); // Seed
                        } else if (t->foreground == 214) { // Corn
                             if (t->growth >= 200) {
                                 entities->spawnDrop((float)current.tx + 0.5f, (float)current.ty + 0.5f, 214);
                                 if (rand()%10 < 5) entities->spawnDrop((float)current.tx + 0.5f, (float)current.ty + 0.5f, 214);
                             } else {
                                 entities->spawnDrop((float)current.tx + 0.5f, (float)current.ty + 0.5f, 214);
                             }
                        } else if (t->foreground == 215) { // Carrot
                             if (t->growth >= 200) {
                                 entities->spawnDrop((float)current.tx + 0.5f, (float)current.ty + 0.5f, 215);
                                 if (rand()%10 < 5) entities->spawnDrop((float)current.tx + 0.5f, (float)current.ty + 0.5f, 215);
                             } else {
                                 entities->spawnDrop((float)current.tx + 0.5f, (float)current.ty + 0.5f, 215);
                             }
                        } else if (t->foreground == 30) { // Chili
                             if (t->growth >= 200) {
                                 entities->spawnDrop((float)current.tx + 0.5f, (float)current.ty + 0.5f, 30);
                                 if (rand()%10 < 5) entities->spawnDrop((float)current.tx + 0.5f, (float)current.ty + 0.5f, 30);
                             } else {
                                 entities->spawnDrop((float)current.tx + 0.5f, (float)current.ty + 0.5f, 30);
                             }
                        } else if (t->foreground == BLOCK_TC_ORE) {
                            entities->spawnDrop((float)current.tx + 0.5f, (float)current.ty + 0.5f, ITEM_TIME_CRYSTAL);
                            if (rand() % 100 < 30) entities->spawnDrop((float)current.tx + 0.5f, (float)current.ty + 0.5f, ITEM_TIME_CRYSTAL);
                        } else {
                            entities->spawnDrop((float)current.tx + 0.5f, (float)current.ty + 0.5f, t->foreground);
                        }
                        
                        auto def = ItemManager::getInstance().getDef(t->foreground);
                        if (def && (def->preferredTool == ITEM_PICKAXE)) {
                             if (selectedItem == 50 || selectedItem == 110 || selectedItem == 120) entities->queueSound("pickaxe.wav");
                             else entities->queueSound("dig.wav");
                        } else {
                            entities->queueSound("dig.wav");
                        }

                        t->foreground = 0; // ITEM_EMPTY
                        t->damage = 0;
                        changed = true;
                    }
                } else {
                    current.progress = 100.0f;
                }
            }
            if (current.progress >= 100.0f) actionQueue.pop();
            
        } else if (current.type == ACTION_PLACE) {
            currentStatus = ACTION_PLACE;
            if (world) {
                int slot = entities->player.selectedSlot;
                int item = entities->player.slots[slot];
                if (item > 0 && entities->player.counts[slot] > 0) {
                    Tile* t = world->getTile(current.tx, current.ty);
                    if (t && t->foreground == 0) { // ITEM_EMPTY
                        // Planting Check
                        bool canPlace = true;
                        if (item == 90 || item == 92 || item == 214 || item == 215 || item == 30) { // Seeds/Crops
                            Tile* below = world->getTile(current.tx, current.ty - 1);
                            if (!below || (below->foreground != 1 && below->foreground != 5 && below->foreground != 23)) { // Dirt(1), Grass(5), Campfire(23)? No just dirt/grass/compost
                                canPlace = false; 
                            }
                        }

                        if (canPlace) {
                            t->foreground = (uint8_t)item;
                            t->damage = 0;
                            t->growth = 0; // Reset growth
                            entities->player.counts[slot]--;
                            if (entities->player.counts[slot] <= 0) entities->player.slots[slot] = 0;
                            entities->inventoryDirty = true;
                            entities->queueSound("place.wav");
                            changed = true;
                        }
                    }
                }
            }
            actionQueue.pop();

        } else if (current.type == ACTION_INTERACT) {
            if (world) {
                Tile* t = world->getTile(current.tx, current.ty);
                if (t && t->foreground != 0) {
                    if (t->foreground == 72) { // Generator
                        int slot = entities->player.selectedSlot;
                        int item = entities->player.slots[slot];
                        if (item == 70 || item == 3) { // Coal or Wood
                           if (t->growth < 250) {
                               int fuelVal = (item == 70) ? 50 : 10;
                               t->growth = (uint8_t)std::min(255, t->growth + fuelVal);
                               entities->player.counts[slot]--;
                               if (entities->player.counts[slot] <= 0) entities->player.slots[slot] = 0;
                               entities->inventoryDirty = true;
                               entities->queueSound("place.wav");
                           }
                        }
                    } else {
                        pendingInteractionBenchId = t->foreground;
                        pendingInteractionX = current.tx;
                        pendingInteractionY = current.ty;
                        if (t->foreground == 150) { // Portal
                            entities->queueSound("portalInteraction.wav");
                        }
                    }
                }
            }
            actionQueue.pop();

        } else if (current.type == ACTION_SLEEP) {
            currentStatus = ACTION_SLEEP;
            // Align player with bed
            entities->player.x = (float)current.tx + 0.5f;
            entities->player.y = (float)current.ty; 
            entities->player.vx = 0;
            entities->player.vy = 0;
            isSleeping = true;
            
            // Sleep action stays in queue until manually removed or morning comes
            // We pop it only if isSleeping is externally set to false (e.g. by morning logic in engine)
            if (!isSleeping) actionQueue.pop();

        } else if (current.type == ACTION_EAT) {
            currentStatus = ACTION_EAT;
            if (entities) {
                int slot = entities->player.selectedSlot;
                int item = entities->player.slots[slot];
                auto def = ItemManager::getInstance().getDef(item);
                if (def && def->isFood) {
                    entities->player.hunger += def->hungerRestore;
                    if (entities->player.hunger > 1.0f) entities->player.hunger = 1.0f;
                    entities->player.counts[slot]--;
                    if (entities->player.counts[slot] <= 0) entities->player.slots[slot] = 0;
                    entities->inventoryDirty = true;
                    entities->queueSound("crunch.wav");
                    changed = true;
                }
            }
            actionQueue.pop();
        } else if (current.type == ACTION_WEAR) {
            currentStatus = ACTION_WEAR;
            if (entities) {
                int slot = entities->player.selectedSlot;
                int item = entities->player.slots[slot];
                bool wore = false;
                if (item == ITEM_LINEN_CAP) { entities->player.clothingHead = item; wore = true; }
                else if (item == ITEM_LINEN_PANTS) { entities->player.clothingLegs = item; wore = true; }
                
                if (wore) {
                    entities->player.counts[slot]--;
                    if (entities->player.counts[slot] <= 0) entities->player.slots[slot] = 0;
                    entities->inventoryDirty = true;
                    entities->queueSound("place.wav");
                    changed = true;
                }
            }
            actionQueue.pop();
        } else {
            actionQueue.pop();
        }
    }
    
    outX = entities->player.x;
    outY = entities->player.y;
    return changed;
}