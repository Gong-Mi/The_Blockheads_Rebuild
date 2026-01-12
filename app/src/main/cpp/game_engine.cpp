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
        
        // 计算当前块的纬度温度 (还原自 POLE/EQUATOR 设定)
        float distToEquator = std::min(std::abs(wrappedX - EQUATOR_1), std::abs(wrappedX - EQUATOR_2));
        // 简单模拟：越靠近极点越冷
        chunks.push_back(block);
        LOGI("Chunk generated at wrapped X: %d, Y: %d", wrappedX, cy);
    }
};

static GameWorld* g_world = nullptr;

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_initNative(JNIEnv* env, jobject obj) {
    g_world = new GameWorld();
    g_world->generateChunk(0, 0);
}
