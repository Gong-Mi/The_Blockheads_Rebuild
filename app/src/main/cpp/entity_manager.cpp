#include "entity_manager.h"
#include <algorithm>

Player::Player() : x(0), y(0), vx(0), vy(0), grounded(false), selectedSlot(0) {
    for(int i=0; i<INVENTORY_SIZE; i++) { slots[i] = 0; counts[i] = 0; }
}

void Player::addItem(int type, int count) {
    // 1. Try to stack
    for(int i=0; i<INVENTORY_SIZE; i++) {
        if (slots[i] == type && counts[i] < 99) {
            int space = 99 - counts[i];
            int add = std::min(space, count);
            counts[i] += add;
            count -= add;
            if (count == 0) return;
        }
    }
    // 2. Try to fill empty slots
    for(int i=0; i<INVENTORY_SIZE; i++) {
        if (slots[i] == 0) {
            slots[i] = type;
            counts[i] = count;
            return;
        }
    }
}

bool Player::checkCollision(float newX, float newY, GameWorld* world) {
    float w = 0.3f; // Slightly wider for better feel
    int blX = (int)floor((newX - w/2));
    int brX = (int)floor((newX + w/2));
    int feetY = (int)floor(newY); 
    int headY = (int)floor(newY + 1.8f); 
    
    if (feetY < 0) return true;

    auto isSolid = [&](int x, int y) {
        Tile* t = world->getTile(x, y);
        if (!t || t->foreground == ITEM_EMPTY) return false;
        // Architectural items are non-solid for movement
        if (t->foreground == ITEM_WOOD_DOOR || t->foreground == ITEM_WOOD_TRAPDOOR || t->foreground == ITEM_LADDER) return false;
        return true;
    };

    if (isSolid(blX, feetY) || isSolid(brX, feetY)) return true;
    if (isSolid(blX, headY) || isSolid(brX, headY)) return true;

    return false;
}

void Player::update(float gravity, GameWorld* world) {
    // Ladder Logic
    bool onLadder = false;
    if (world) {
        Tile* t = world->getTile((int)floor(x), (int)floor(y + 0.5f));
        if (t && t->foreground == ITEM_LADDER) {
            onLadder = true;
            vx *= 0.5f; // Slow down on ladder
            if (vy < -0.1f) vy = -0.1f; // Slow descent
        }
    }

    x += vx;
    if (onLadder) {
        // Vertical movement on ladder if player is "trying to move"? 
        // For now, ladders just counteract gravity and allow "floating"
        vy *= 0.8f; 
        vy += 0.01f; // Neutral buoyancy on ladder
    } else {
        vy -= gravity; 
    }
    
    float nextY = y + vy;
    
    if (world) {
        if (checkCollision(x, nextY, world)) {
            if (vy < 0) { 
                grounded = true;
                vy = 0;
                y = std::ceil(y); 
            } else {
                vy = 0;
                y = nextY; 
            }
        } else {
            grounded = false;
            y = nextY;
        }
    } else {
        y = nextY;
        if (y < 0) { y = 0; vy = 0; grounded = true; }
    }

    if (grounded) {
        float friction = 0.8f;
        if (world) {
             int bx = (int)floor(x);
             int by = (int)floor(y - 0.5f);
             Tile* t = world->getTile(bx, by);
             if (t) {
                 if (t->foreground == BLOCK_ICE) friction = 0.98f; // Very slippery
                 else if (t->foreground == BLOCK_SNOW) friction = 0.92f; // Somewhat slippery
             }
        }
        vx *= friction;
    }
    else vx *= 0.98f;
    
    // World wrap
    if (x < 0) x += 15000.0f;
    if (x >= 15000.0f) x -= 15000.0f;

    // --- Status Updates ---
    if (world) {
        // Hunger decay
        hunger -= 0.00002f; 
        if (hunger < 0) hunger = 0;
        if (hunger <= 0) health -= 0.0001f; // Starvation damage

        // Drowning logic
        int headX = (int)floor(x);
        int headY = (int)floor(y + 1.5f);
        Tile* headTile = world->getTile(headX, headY);
        if (headTile && headTile->waterLevel > 150) {
            breath -= 0.002f;
            if (breath < 0) breath = 0;
            if (breath <= 0) health -= 0.005f;
        } else {
            breath += 0.01f;
            if (breath > 1.0f) breath = 1.0f;
        }

        // Temperature damage
        Tile* feetTile = world->getTile((int)floor(x), (int)floor(y));
        if (feetTile) {
            uint16_t temp = feetTile->temperature;
            // Clothing insulation
            if (clothingHead == ITEM_LINEN_CAP) {
                if (temp < 15000) temp += 10000;
            }
            if (clothingLegs == ITEM_LINEN_PANTS) {
                if (temp < 15000) temp += 10000;
            }

            if (temp < 15000) health -= 0.0002f; // Too cold
            else if (temp > 55000) health -= 0.0002f; // Too hot
        }

        // Regeneration
        if (hunger > 0.8f && health < 1.0f && health > 0) {
            health += 0.0001f;
        }
        
        if (health < 0) health = 0;
    }
}

void EntityManager::spawnDrop(float x, float y, int itemType) {
    Entity e;
    e.x = x; e.y = y;
    e.vx = ((float)rand() / (float)RAND_MAX - 0.5f) * 0.5f; 
    e.vy = 0.8f; 
    e.type = ENTITY_DROP_ITEM;
    e.itemId = itemType;
    e.rotation = 0;
    e.onGround = false;
    e.markForDelete = false;
    dropItems.push_back(e);
}

void EntityManager::spawnMob(float x, float y, int type) {
    Entity e;
    e.x = x; e.y = y;
    e.vx = 0; e.vy = 0;
    e.type = type;
    e.itemId = 0;
    e.rotation = 0;
    e.onGround = false;
    e.markForDelete = false;
    mobs.push_back(e);
}

void EntityManager::update(float gravity, GameWorld* world) {
    player.update(gravity, world);

    // --- Mob AI ---
    for (auto& m : mobs) {
        if (m.type == ENTITY_DODO || m.type == ENTITY_YAK) {
            // Random walk
            if (rand() % 100 < 2) m.vx = (float)(rand() % 3 - 1) * (m.type == ENTITY_YAK ? 0.03f : 0.05f);
            
            m.vy -= gravity * (m.type == ENTITY_YAK ? 0.8f : 0.5f);
            m.x += m.vx;
            m.y += m.vy;

            if (world) {
                // Check forward collision for jumping
                if (m.vx != 0) {
                    int nextX = (int)floor(m.x + m.vx * 10.0f);
                    int currY = (int)floor(m.y);
                    Tile* wall = world->getTile(nextX, currY);
                    if (wall && wall->foreground != ITEM_EMPTY && m.onGround) {
                        m.vy = (m.type == ENTITY_YAK ? 0.45f : 0.35f); 
                    }
                }

                int bx = (int)floor(m.x);
                int by = (int)floor(m.y);
                Tile* t = world->getTile(bx, by);
                if (t && t->foreground != ITEM_EMPTY) {
                    m.y = (float)(by + 1);
                    m.vy = 0;
                    m.onGround = true;
                } else {
                    m.onGround = false;
                }
            }

            // World wrap
            if (m.x < 0) m.x += 15000.0f;
            if (m.x >= 15000.0f) m.x -= 15000.0f;

            // Player Interaction (Kill)
            float dx = player.x - m.x;
            float dy = player.y - m.y;
            if (dx*dx + dy*dy < 1.5f && rand() % 100 < 5) { 
                 m.markForDelete = true;
                 if (m.type == ENTITY_DODO) {
                     spawnDrop(m.x, m.y, ITEM_DODO_MEAT);
                     if (rand() % 100 < 20) spawnDrop(m.x, m.y, ITEM_FUR);
                     queueSound("dodoDie.wav");
                 } else {
                     spawnDrop(m.x, m.y, ITEM_DODO_MEAT); // Use Meat for both for now
                     spawnDrop(m.x, m.y, ITEM_FUR);
                     spawnDrop(m.x, m.y, ITEM_FUR);
                     queueSound("yakDie.wav"); // Assuming this exists or falls back
                 }
            }
            
            // Random sound
            if (m.type == ENTITY_DODO && rand() % 1000 < 2) queueSound("dodoCluck1.wav");
            if (m.type == ENTITY_YAK && rand() % 1500 < 2) queueSound("yakMoo.wav");
        } else if (m.type == ENTITY_DROPBEAR) {
            // Dropbear AI: Stationary on trees, drops when player is near
            float dx = player.x - m.x;
            float dy = player.y - m.y;
            float distSq = dx*dx + dy*dy;

            if (distSq < 9.0f) { // Aggro range
                m.vy -= gravity * 0.8f; // Falling/Attacking
                m.vx = (dx > 0 ? 1 : -1) * 0.08f;
                if (distSq < 0.5f) {
                    player.health -= 0.01f; // Damage player
                    if (rand() % 5 == 0) queueSound("crunch.wav");
                }
            } else {
                m.vx = 0; m.vy = 0; // Stay on tree
            }

            m.x += m.vx; m.y += m.vy;
            if (world) {
                int bx = (int)floor(m.x); int by = (int)floor(m.y);
                Tile* t = world->getTile(bx, by);
                if (t && t->foreground != ITEM_EMPTY) {
                    m.y = (float)(by + 1); m.vy = 0; m.onGround = true;
                }
            }

            if (distSq < 1.0f && rand() % 100 < 5) { // Can be killed
                m.markForDelete = true;
                spawnDrop(m.x, m.y, ITEM_DODO_MEAT);
                spawnDrop(m.x, m.y, ITEM_FUR);
                queueSound("dropbearDie.wav");
            }
        }
    }
    mobs.erase(std::remove_if(mobs.begin(), mobs.end(), 
        [](const Entity& e){ return e.markForDelete; }), mobs.end());

    // Spawning logic
    if (world && mobs.size() < 20 && rand() % 1000 < 10) {
        int sx = (int)floor(player.x) + (rand() % 60 - 30);
        int sy = (int)floor(player.y) + (rand() % 20 - 10);
        Tile* t = world->getTile(sx, sy);
        Tile* below = world->getTile(sx, sy-1);
        if (t && t->foreground == ITEM_EMPTY && below) {
            if (below->foreground == BLOCK_GRASS) spawnMob((float)sx + 0.5f, (float)sy + 0.5f, ENTITY_DODO);
            else if (below->foreground == BLOCK_SNOW) spawnMob((float)sx + 0.5f, (float)sy + 0.5f, ENTITY_YAK);
            else if (below->foreground == BLOCK_LEAVES) spawnMob((float)sx + 0.5f, (float)sy + 0.5f, ENTITY_DROPBEAR);
        }
    }

    for (auto& e : dropItems) {
        float dx = player.x - e.x;
        float dy = (player.y + 1.5f) - e.y; 
        float distSq = dx*dx + dy*dy;
        
        if (distSq < 5.0f) { 
            e.vx += dx * 0.02f;
            e.vy += dy * 0.02f;
            e.onGround = false; 
        }
        
        if (distSq < 0.2f) { 
            player.addItem(e.itemId, 1);
            inventoryDirty = true;
            queueSound("pop.wav");
            e.markForDelete = true;
            continue;
        }

        if (!e.onGround) {
            e.vy -= gravity * 0.1f; 
            e.x += e.vx;
            e.y += e.vy;
            e.rotation += 0.1f;
            e.vx *= 0.95f;
            e.vy *= 0.95f;

            if (world) {
                int bx = (int)floor(e.x);
                int by = (int)floor(e.y);
                Tile* t = world->getTile(bx, by);
                if (t && t->foreground != ITEM_EMPTY) {
                    e.y = (float)(by + 1); 
                    e.vy = 0;
                    e.onGround = true;
                }
            }
        }
    }
    
    dropItems.erase(std::remove_if(dropItems.begin(), dropItems.end(), 
        [](const Entity& e){ return e.markForDelete; }), dropItems.end());
}
