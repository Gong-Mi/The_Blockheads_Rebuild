#ifndef BLOCKHEAD_AI_H
#define BLOCKHEAD_AI_H

#include <queue>
#include "game_constants.h"
#include "game_world.h"
#include "entity_manager.h"

enum ActionType { ACTION_WALK, ACTION_MINE, ACTION_PLACE, ACTION_IDLE, ACTION_INTERACT, ACTION_EAT, ACTION_WEAR };

struct Action {
    ActionType type;
    int tx, ty; 
    float progress;
};

class BlockheadAI {
public:
    std::queue<Action> actionQueue;
    ActionType currentStatus = ACTION_IDLE;
    float posX = 0, posY = 0;
    int pendingInteractionBenchId = -1; 
    int pendingInteractionX = 0;
    int pendingInteractionY = 0;
    
    void addAction(ActionType type, int tx, int ty);
    bool update(float& outX, float& outY, GameWorld* world, EntityManager* entities);
};

#endif
