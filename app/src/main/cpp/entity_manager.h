#ifndef ENTITY_MANAGER_H
#define ENTITY_MANAGER_H

#include <vector>
#include <cmath>
#include "game_world.h"

struct Entity {
    float x, y;
    float vx, vy;
    int type;
    float rotation;
    bool onGround;
    bool markForDelete; 
};

class Player {
public:
    float x, y;
    float vx, vy;
    bool grounded;
    
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
    bool inventoryDirty = false;

    void spawnDrop(float x, float y, int type);
    void update(float gravity, GameWorld* world);
};

#endif