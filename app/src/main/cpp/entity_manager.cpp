#include <vector>
#include <cmath>

struct Entity {
    float x, y;
    float vx, vy;
    int type;
    float rotation;
    bool onGround;
};

class Player {
public:
    float x, y;
    float vx, vy;
    bool grounded;

    Player() : x(0), y(0), vx(0), vy(0), grounded(false) {}

    void update(float gravity) {
        vy += gravity;
        y += vy;
        
        // 简单模拟落地：地表在 Y=0
        if (y > 0) {
            y = 0;
            vy = 0;
            grounded = true;
        }
    }
};

class EntityManager {
public:
    Player player;
    std::vector<Entity> dropItems;
    // ...

    void spawnDrop(float x, float y, int type) {
        Entity e;
        e.x = x; e.y = y;
        e.vx = ((float)rand() / RAND_MAX - 0.5f) * 0.05f; // 随机初速度
        e.vy = -0.08f; // 向上弹出
        e.type = type;
        e.rotation = 0;
        e.onGround = false;
        dropItems.push_back(e);
    }

    void update(float gravity) {
        for (auto& e : dropItems) {
            if (!e.onGround) {
                e.vy += gravity * 0.1f; // 应用重力
                e.x += e.vx;
                e.y += e.vy;
                e.rotation += 0.1f;

                // 简单的地面检测 (示例：停在 Y=0)
                if (e.y > 0) {
                    e.y = 0;
                    e.vy = -e.vy * 0.5f; // 弹跳
                    if (std::abs(e.vy) < 0.01f) {
                        e.vy = 0;
                        e.onGround = true;
                    }
                }
            }
        }
    }
};
