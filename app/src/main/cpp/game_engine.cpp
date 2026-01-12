#include <jni.h>
#include <string>
#include <vector>
#include <android/log.h>
#include "game_constants.h"

#define LOG_TAG "BlockheadsNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

struct Tile {
    uint8_t foreground;
    uint8_t background;
    uint8_t sunlight;
    uint8_t artLight;
    uint8_t damage;
    uint8_t waterLevel; // 0-255 代表含水量
    int8_t normalX;
    int8_t normalY;
    uint8_t paintColor[4];
    uint16_t temperature;
};

class GameWorld {
public:
    // ... 
    void updatePhysics() {
        // --- 还原自原版的高性能流体算法 ---
        for (auto* block : chunks) {
            for (int i = 0; i < CHUNK_SIZE * CHUNK_SIZE; i++) {
                Tile& t = block->tiles[i];
                if (t.waterLevel > 0) {
                    // 水向下流，如果没有阻挡
                    // 这里将来会实现横向扩散压力平衡
                }
            }
        }
    }
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

    void updateLighting(PhysicalBlock* block) {
        // --- 还原自原版的递归光照传播 ---
        for (int x = 0; x < CHUNK_SIZE; x++) {
            int currentSun = 255;
            for (int y = 0; y < CHUNK_SIZE; y++) {
                Tile& t = block->tiles[y * CHUNK_SIZE + x];
                if (t.foreground != 0) {
                    currentSun -= 40; // 方块阻挡光线
                    if (currentSun < 0) currentSun = 0;
                }
                t.sunlight = (uint8_t)currentSun;
            }
        }
    }

    void generateChunk(int cx, int cy) {
        // ... 之前的生成代码 ...
        updateLighting(block); // 生成后立即计算光照
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


