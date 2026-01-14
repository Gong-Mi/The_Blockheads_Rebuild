#include "blockhead_ai.h"
#include <algorithm>

void BlockheadAI::addAction(ActionType type, int tx, int ty) {
    Action a = {type, tx, ty, 0};
    actionQueue.push(a);
}

bool BlockheadAI::update(float& outX, float& outY, GameWorld* world, EntityManager* entities) {
    if (!entities) return false;
    bool changed = false;
    
    posX = entities->player.x;
    posY = entities->player.y;

    if (actionQueue.empty()) {
        currentStatus = ACTION_IDLE;
        entities->player.vx *= 0.8f; 
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

    if (dist > 0.5f) { 
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
            if (wall && wall->foreground != ITEM_EMPTY && entities->player.grounded) {
                entities->player.vy = 0.6f; 
            }
        }

    } else { 
        entities->player.vx *= 0.5f; 
        
        if (current.type == ACTION_MINE) {
            currentStatus = ACTION_MINE;
            
            float baseSpeed = 2.0f; // Very slow hand digging
            if (world) {
                Tile* t = world->getTile(current.tx, current.ty);
                if (t && t->foreground != ITEM_EMPTY) {
                    int selectedItem = entities->player.slots[entities->player.selectedSlot];
                    
                    // --- Tool Efficiency Logic ---
                    if (t->foreground == ITEM_STONE || t->foreground == 7 || t->foreground == 8) {
                        if (selectedItem == ITEM_PICKAXE) baseSpeed = 20.0f;
                    } else if (t->foreground == ITEM_DIRT || t->foreground == BLOCK_GRASS) {
                        if (selectedItem == 52) baseSpeed = 25.0f; // Flint Spade
                    } else if (t->foreground == BLOCK_WOOD) {
                        if (selectedItem == 51) baseSpeed = 15.0f; // Flint Axe
                    }
                    
                    // Periodic hit sound (every ~20% progress or so, simplified here to start/end or random?)
                    // For now, let's play sound when block breaks
                    
                    current.progress += baseSpeed; 
                    
                    if (t->damage < 240) {
                        t->damage = (uint8_t)std::min(255.0f, (float)t->damage + baseSpeed / 2.0f); 
                    } else {
                        entities->spawnDrop((float)current.tx + 0.5f, (float)current.ty + 0.5f, t->foreground);
                        
                        // Play break sound
                        if (t->foreground == ITEM_STONE || t->foreground == 7 || t->foreground == 8) 
                            entities->queueSound("pickaxe.wav");
                        else 
                            entities->queueSound("dig.wav");

                        t->foreground = ITEM_EMPTY; 
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
                    if (t && t->foreground == ITEM_EMPTY) {
                        t->foreground = (uint8_t)item;
                        t->damage = 0;
                        entities->player.counts[slot]--;
                        if (entities->player.counts[slot] <= 0) entities->player.slots[slot] = 0;
                        entities->inventoryDirty = true;
                        entities->queueSound("place.wav");
                        changed = true;
                    }
                }
            }
            actionQueue.pop();
        } else if (current.type == ACTION_INTERACT) {
            if (world) {
                Tile* t = world->getTile(current.tx, current.ty);
                if (t && t->foreground != ITEM_EMPTY) {
                    pendingInteractionBenchId = t->foreground;
                }
            }
            actionQueue.pop();
        } else if (current.type == ACTION_EAT) {
            currentStatus = ACTION_EAT;
            if (entities) {
                int slot = entities->player.selectedSlot;
                int item = entities->player.slots[slot];
                
                // Eat logic
                if (item == ITEM_CHILI || item == ITEM_DODO_MEAT || item == ITEM_COCONUT) {
                    float hungerRestore = 0.2f; // Default
                    if (item == ITEM_DODO_MEAT) hungerRestore = 0.35f;
                    if (item == ITEM_COCONUT) hungerRestore = 0.25f;

                    entities->player.hunger += hungerRestore;
                    if (entities->player.hunger > 1.0f) entities->player.hunger = 1.0f;
                    
                    entities->player.counts[slot]--;
                    if (entities->player.counts[slot] <= 0) entities->player.slots[slot] = 0;
                    entities->inventoryDirty = true;
                    
                    entities->queueSound("crunch.wav"); // Reuse existing sound or add eat.wav
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
