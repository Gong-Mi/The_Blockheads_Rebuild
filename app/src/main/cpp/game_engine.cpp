#include <jni.h>
#include <string>
#include <vector>
#include <android/log.h>
#include "game_constants.h"

#define LOG_TAG "BlockheadsNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// --- 深度还原自 Block.fsh 的 Tile 结构 ---
struct Tile {
    uint8_t foreground;    // 前景
    uint8_t background;    // 背景墙
    uint8_t sunlight;      // 阳光强度 (0-255)
    uint8_t artLight;      // 人造光强度
    uint8_t damage;        // 破损度 (0-255，关联 destruct_texture)
    int8_t normalX;        // 法线偏移 X (还原 2.5D 质感)
    int8_t normalY;        // 法线偏移 Y
    uint8_t paintColor[4]; // RGBA 染色数据
    
    // 扩展属性
    uint16_t temperature;  // 基于纬度和深度的实时温度
};

struct PhysicalBlock {
    int x, y;
    Tile tiles[CHUNK_SIZE * CHUNK_SIZE];
};

class GameWorld {
public:
    std::vector<PhysicalBlock*> chunks;

    // --- 核心：环形世界坐标转换 (还原自 15000 块周长设定) ---
    int wrapX(int x) {
        if (x < 0) return (x % WORLD_WIDTH) + WORLD_WIDTH;
        return x % WORLD_WIDTH;
    }

    void generateChunk(int cx, int cy) {
        int wrappedX = wrapX(cx);
        PhysicalBlock* block = new PhysicalBlock();
        block->x = wrappedX;
        block->y = cy;
        
        for (int x = 0; x < CHUNK_SIZE; x++) {
            for (int y = 0; y < CHUNK_SIZE; y++) {
                int worldY = cy * CHUNK_SIZE + y;
                Tile& t = block->tiles[y * CHUNK_SIZE + x];
                
                // 1. 基础地形 (还原自深度分布)
                if (worldY > 100) {
                    t.foreground = 2; // 石头层
                    // --- 矿物随机分布 ---
                    float oreRand = (float)rand() / RAND_MAX;
                    if (oreRand > 0.98f) t.foreground = 100; // 极低概率时间水晶
                    else if (oreRand > 0.95f) t.foreground = 8; // 铁矿
                    else if (oreRand > 0.90f) t.foreground = 7; // 铜矿
                } else if (worldY > 80) {
                    t.foreground = 1; // 泥土层
                    if ((float)rand() / RAND_MAX > 0.95f) t.foreground = 4; // 燧石
                } else if (worldY == 80) {
                    t.foreground = 5; // 草地
                } else {
                    t.foreground = 0; // 天空
                }

                // 2. 溶洞生成 (还原自原版地下空洞逻辑)
                // 使用简单的概率函数模拟空洞
                if (worldY > 110 && (rand() % 100) > 92) {
                    t.foreground = 0; 
                }

                t.sunlight = (worldY <= 80) ? 255 : 0;
                t.damage = 0;
            }
        }
        chunks.push_back(block);
    }
};

static GameWorld* g_world = nullptr;

#include "entity_manager.cpp"

#include "blockhead_ai.cpp"

BlockheadAI* g_ai = nullptr;

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_initNative(JNIEnv* env, jobject obj) {
    CompressionManager::init();
    g_world = new GameWorld();
    g_entities = new EntityManager();
    g_ai = new BlockheadAI();
    g_world->generateChunk(0, 0);
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleTouchNative(JNIEnv* env, jobject obj, jfloat x, jfloat y) {
    int tx = (int)(x / 100.0f);
    int ty = (int)(y / 100.0f);
    
    // 发送挖掘指令给 AI
    if (g_ai) g_ai->addAction(ACTION_MINE, tx, ty);
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_onDrawFrameNative(JNIEnv* env, jobject obj) {
    if (g_renderer && g_world && g_entities && g_ai) {
        // 更新 AI 逻辑
        g_ai->update(g_entities->player.x, g_entities->player.y);
        g_entities->update(0.005f);
        
        // ... 后续渲染逻辑保持不变 ...
    }
}


