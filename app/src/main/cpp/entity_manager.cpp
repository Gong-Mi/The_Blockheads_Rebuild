#include "entity_manager.h"
#include <algorithm>

Player::Player() : x(0), y(0), vx(0), vy(0), grounded(false), selectedSlot(0) {
    for(int i=0; i<10; i++) { slots[i] = 0; counts[i] = 0; }
}

void Player::addItem(int type, int count) {
    for(int i=0; i<10; i++) {
        if (slots[i] == type && counts[i] < 99) {
            counts[i] += count;
            return;
        }
    }
    for(int i=0; i<10; i++) {
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
    int headY = (int)floor(newY + 1.8f); // ~2 blocks high
    
    if (feetY < 0) return true;

    // Check feet level
    Tile* t1 = world->getTile(blX, feetY);
    Tile* t2 = world->getTile(brX, feetY);
    if ((t1 && t1->foreground != ITEM_EMPTY) || (t2 && t2->foreground != ITEM_EMPTY)) return true;

    // Check head level
    Tile* t3 = world->getTile(blX, headY);
    Tile* t4 = world->getTile(brX, headY);
    if ((t3 && t3->foreground != ITEM_EMPTY) || (t4 && t4->foreground != ITEM_EMPTY)) return true;

    return false;
}

void Player::update(float gravity, GameWorld* world) {
    x += vx;
    vy -= gravity; 
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
            if (feetTile->temperature < 15000) health -= 0.0002f; // Too cold
            else if (feetTile->temperature > 55000) health -= 0.0002f; // Too hot
        }

        // Regeneration
        if (hunger > 0.8f && health < 1.0f && health > 0) {
            health += 0.0001f;
        }
        
        if (health < 0) health = 0;
    }
}

void EntityManager::spawnDrop(float x, float y, int type) {
    Entity e;
    e.x = x; e.y = y;
    e.vx = ((float)rand() / (float)RAND_MAX - 0.5f) * 0.5f; 
    e.vy = 0.8f; 
    e.type = type;
    e.rotation = 0;
    e.onGround = false;
    e.markForDelete = false;
    dropItems.push_back(e);
}

void EntityManager::update(float gravity, GameWorld* world) {
    player.update(gravity, world);

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
            player.addItem(e.type, 1);
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
