#ifndef ENTITY_MANAGER_H
#define ENTITY_MANAGER_H

#include <vector>
#include <cmath>
#include "game_world.h"

struct Entity {
    float x, y;
    float vx, vy;
    int type; // Entity Type (e.g., ENTITY_DODO, ENTITY_DROP_ITEM)
    int itemId; // For drops: Item ID
    float rotation;
    bool onGround;
    bool markForDelete; 
};

class Player {
public:
    float x, y;
    float vx, vy;
    bool grounded;
    
    float health = 1.0f; // 0.0 to 1.0
    float hunger = 1.0f; // 0.0 to 1.0
    float breath = 1.0f; // 0.0 to 1.0

    int clothingHead = 0;
    int clothingLegs = 0;

    int slots[10];
    int counts[10];
    int selectedSlot;

    Player();
    void addItem(int type, int count);
    bool checkCollision(float newX, float newY, GameWorld* world);
    void update(float gravity, GameWorld* world);
};

class EntityManager {
public:
    Player player;
    std::vector<Entity> dropItems;
    std::vector<Entity> mobs;
    bool inventoryDirty = false;
    std::vector<std::string> soundEvents;

    void queueSound(const std::string& name) {
        soundEvents.push_back(name);
    }

    void spawnDrop(float x, float y, int type);
    void spawnMob(float x, float y, int type);
    void update(float gravity, GameWorld* world);
};

#endif