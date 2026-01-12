#include <vector>
#include <cmath>
#include <algorithm>

// Forward declaration if needed, but GameWorld should be defined by the inclusion order in game_engine.cpp
class GameWorld; 

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

    Player() : x(0), y(0), vx(0), vy(0), grounded(false), selectedSlot(0) {
        for(int i=0; i<10; i++) { slots[i] = 0; counts[i] = 0; }
    }

    void addItem(int type, int count) {
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

    // Helper to check collision with world
    bool checkCollision(float newX, float newY, GameWorld* world);

    void update(float gravity, GameWorld* world) {
        // Horizontal Movement (friction)
        // Note: AI currently modifies x directly, we should change that later.
        // For now, let's just handle Gravity (Y axis).
        
        vy += gravity; // Gravity is usually negative in physics, but here y=0 is bottom?
        // Wait, renderer uses ortho(-2, 2, ...). 
        // In renderer: Matrix::translate(..., -camY). 
        // In chunks: y=0 is chunk 0.
        // So +Y is UP. Gravity should be NEGATIVE.
        // But previously I had: vy += gravity; y += vy; if(y>0) y=0;
        // This implies gravity pulls DOWN (negative), and ground is at 0.
        // But my gravity param passed is 0.005f (positive). 
        // So I should subtract gravity.
        
        vy -= gravity; 
        
        // Predict next Y position
        float nextY = y + vy;
        
        if (world) {
            if (checkCollision(x, nextY, world)) {
                // Collision detected below
                if (vy < 0) { // Falling
                    grounded = true;
                    vy = 0;
                    // Snap to block grid?
                    // 1 block = 0.1f. 
                    // If feet (y) hit block top (blockY + 0.1), snap y to blockY + 0.1
                    // Simple snap: round to nearest 0.1
                    y = std::ceil(y * 10.0f) / 10.0f; 
                } else {
                    // Hitting head
                    vy = 0;
                    y = nextY; // Or push back
                }
            } else {
                grounded = false;
                y = nextY;
            }
        } else {
            // Fallback if no world
            y = nextY;
            if (y < 0) { y = 0; vy = 0; grounded = true; }
        }
    }
};

class EntityManager {
public:
    Player player;
    std::vector<Entity> dropItems;
    bool inventoryDirty = false;

    void spawnDrop(float x, float y, int type) {
        Entity e;
        e.x = x; e.y = y;
        e.vx = ((float)rand() / RAND_MAX - 0.5f) * 0.05f; 
        e.vy = 0.08f; // Pop UP (positive Y)
        e.type = type;
        e.rotation = 0;
        e.onGround = false;
        e.markForDelete = false;
        dropItems.push_back(e);
    }

    void update(float gravity, GameWorld* world) {
        // Player update
        player.update(gravity, world);

        // Drops update
        for (auto& e : dropItems) {
            float dx = player.x - e.x;
            float dy = (player.y + 0.15f) - e.y; // Center of player (h=0.3)
            float distSq = dx*dx + dy*dy;
            
            if (distSq < 0.5f) { // Magnet
                e.vx += dx * 0.02f;
                e.vy += dy * 0.02f;
                e.onGround = false; 
            }
            
            if (distSq < 0.02f) { // Collect
                player.addItem(e.type, 1);
                inventoryDirty = true;
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

                // Simple collision for items (check block below)
                if (world) {
                    // Check point collision
                    int bx = (int)(e.x * 10.0f);
                    int by = (int)(e.y * 10.0f);
                    // Check block *below* item center? No, item center is e.y
                    // Items are small (0.1).
                    // If e.y is inside a solid block
                    // Wait, getTile takes integer coords.
                    // If e.y < block_top, collision.
                    // Let's assume item radius is 0.05. Bottom is e.y
                    Tile* t = world->getTile(bx, by);
                    if (t && t->foreground != 0) {
                        e.y = (by + 1) * 0.1f; // On top of block
                        e.vy = 0;
                        e.onGround = true;
                    }
                }
            }
        }
        
        dropItems.erase(std::remove_if(dropItems.begin(), dropItems.end(), 
            [](const Entity& e){ return e.markForDelete; }), dropItems.end());
    }
};

// Implement collision helper
// We need GameWorld definition here. Since this is included in game_engine.cpp, 
// GameWorld class is defined BEFORE this file inclusion.
// But we need to access its members.
bool Player::checkCollision(float newX, float newY, GameWorld* world) {
    // Player box: width 0.15 (1.5 blocks), height 0.3 (3 blocks)
    // Coords are bottom-center.
    float w = 0.15f; 
    // Check feet (bottom-left, bottom-right)
    int blX = (int)((newX - w/2) * 10.0f);
    int brX = (int)((newX + w/2) * 10.0f);
    int feetY = (int)(newY * 10.0f); // Block containing feet
    
    // Safety check: don't fall through bedrock
    if (feetY < 0) return true;

    // We mostly care about falling ONTO things.
    // If block AT feet is solid, we are colliding.
    Tile* t1 = world->getTile(blX, feetY);
    Tile* t2 = world->getTile(brX, feetY);
    
    if ((t1 && t1->foreground != 0) || (t2 && t2->foreground != 0)) {
        return true;
    }
    return false;
}
