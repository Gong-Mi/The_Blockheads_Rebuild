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
                
                // --- 还原自原版生成逻辑 ---
                if (worldY > 100) {
                    t.foreground = 2; // 石头
                } else if (worldY > 80) {
                    t.foreground = 1; // 泥土
                } else if (worldY == 80) {
                    t.foreground = 5; // 草
                } else {
                    t.foreground = 0; // 天空
                }
                
                t.sunlight = (worldY <= 80) ? 255 : 0;
                t.damage = 0;
            }
        }
        
        chunks.push_back(block);
        LOGI("World Generated at Chunk X:%d, Y:%d", wrappedX, cy);
    }
};

static GameWorld* g_world = nullptr;

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_initNative(JNIEnv* env, jobject obj) {
    CompressionManager::init(); // 检测 CPU 架构
    g_world = new GameWorld();
    g_world->generateChunk(0, 0);
    LOGI("Native Engine Initialized with adaptive compression");
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleActionNative(JNIEnv* env, jobject obj, jint actionType) {
    LOGI("Action Received: %d", actionType);
    // 这里将来会调用 command_processor.cpp 里的逻辑
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleCraftNative(JNIEnv* env, jobject obj, jint targetItemId) {
    LOGI("Crafting Request for Item ID: %d", targetItemId);
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleTouchNative(JNIEnv* env, jobject obj, jfloat x, jfloat y) {
    LOGI("Touch at: %f, %f", x, y);
}
