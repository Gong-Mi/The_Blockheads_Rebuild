#include <string>
#include <vector>
#include <queue>
#include <cmath>
#include "game_constants.h"

enum ActionType { ACTION_WALK, ACTION_MINE, ACTION_PLACE, ACTION_IDLE };

struct Action {
    ActionType type;
    int tx, ty; // 目标坐标
    float progress;
};

class BlockheadAI {
public:
    std::queue<Action> actionQueue;
    ActionType currentStatus = ACTION_IDLE;
    float posX = 0, posY = 0;
    float targetX = 0;

    void addAction(ActionType type, int tx, int ty) {
        Action a = {type, tx, ty, 0};
        actionQueue.push(a);
    }

    void update(float& outX, float& outY, GameWorld* world, EntityManager* entities) {
        if (actionQueue.empty()) {
            currentStatus = ACTION_IDLE;
            return;
        }

        Action& current = actionQueue.front();
        float dx = (current.tx * 0.1f) - posX;

        // --- 还原自原版的寻路/行走逻辑 ---
        if (std::abs(dx) > 0.01f) {
            currentStatus = ACTION_WALK;
            posX += (dx > 0 ? 1 : -1) * 0.005f; // 步进
        } else {
            // 到达位置，开始工作
            if (current.type == ACTION_MINE) {
                currentStatus = ACTION_MINE;
                current.progress += 5.0f; // Speed up mining for testing (was 2.0f)
                
                // --- Mining Logic ---
                if (world) {
                    Tile* t = world->getTile(current.tx, current.ty);
                    if (t && t->foreground != 0) {
                        if (t->damage < 240) {
                            t->damage += 10; // Faster damage (was 5)
                        } else {
                            // Drop item before destroying
                            if (entities) {
                                // Convert tile coordinates to world float coordinates
                                // +0.05f to center in the block (block is 0.1f wide)
                                float dropX = current.tx * 0.1f + 0.05f;
                                float dropY = current.ty * 0.1f + 0.05f;
                                // Drop the item type matching the foreground block (simplified)
                                entities->spawnDrop(dropX, dropY, t->foreground);
                            }

                            t->foreground = 0; // Destroy block
                            t->damage = 0;
                        }
                    } else {
                        // Empty or invalid, job done
                        current.progress = 100.0f;
                    }
                }

                if (current.progress >= 100.0f) actionQueue.pop();
            } else {
                actionQueue.pop();
            }
        }
        outX = posX; outY = posY;
    }
};