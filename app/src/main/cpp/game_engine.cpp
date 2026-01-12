#include <jni.h>
#include <string>
#include <vector>
#include <android/log.h>
#include "game_constants.h"

// 引入子模块源码 (这些文件必须存在)
#include "compression_manager.cpp"
#include "entity_manager.cpp"
#include "blockhead_ai.cpp"

// 声明渲染器全局指针 (由 world_renderer.cpp 提供)
#include <android/asset_manager.h>
class WorldRenderer {
public:
    void init(AAssetManager* mgr);
    void renderFrame();
    void updateMesh(const std::vector<PhysicalBlock*>& chunks);
    // Expose camera control for input
    float camX, camY;
    float targetX, targetY;
};
extern WorldRenderer* g_renderer;

#define LOG_TAG "BlockheadsNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

class GameWorld {
public:
    std::vector<PhysicalBlock*> chunks;

    int wrapX(int x) {
        if (x < 0) return (x % WORLD_WIDTH) + WORLD_WIDTH;
        return x % WORLD_WIDTH;
    }

    void updateLighting(PhysicalBlock* block) {
        for (int x = 0; x < CHUNK_SIZE; x++) {
            int currentSun = 255;
            for (int y = 0; y < CHUNK_SIZE; y++) {
                Tile& t = block->tiles[y * CHUNK_SIZE + x];
                if (t.foreground != 0) {
                    currentSun -= 40;
                    if (currentSun < 0) currentSun = 0;
                }
                t.sunlight = (uint8_t)currentSun;
            }
        }
    }

    void generateChunk(int cx, int cy) {
        int wrappedX = wrapX(cx);
        PhysicalBlock* block = new PhysicalBlock();
        block->x = wrappedX;
        block->y = cy;
        
        for (int i = 0; i < CHUNK_SIZE * CHUNK_SIZE; i++) {
            int worldY = cy * CHUNK_SIZE + (i / CHUNK_SIZE);
            Tile& t = block->tiles[i];
            if (worldY > 100) t.foreground = 2;
            else if (worldY > 80) t.foreground = 1;
            else if (worldY == 80) t.foreground = 5;
            else t.foreground = 0;
            t.damage = 0;
        }
        updateLighting(block);
        chunks.push_back(block);
    }
};

// 全局实例
static GameWorld* g_world = nullptr;
EntityManager* g_entities = nullptr;
BlockheadAI* g_ai = nullptr;

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_initNative(JNIEnv* env, jobject obj) {
    CompressionManager::init();
    g_world = new GameWorld();
    g_entities = new EntityManager();
    g_ai = new BlockheadAI();
    g_world->generateChunk(0, 0); // Generates block at 0,0
    // Manually force mesh update after world gen
    if (g_renderer) {
        g_renderer->updateMesh(g_world->chunks);
    }
    LOGI("Native Engine Ready");
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleActionNative(JNIEnv* env, jobject obj, jint actionType) {
    LOGI("Action: %d", actionType);
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleCraftNative(JNIEnv* env, jobject obj, jint targetItemId) {
    LOGI("Craft: %d", targetItemId);
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleTouchNative(JNIEnv* env, jobject obj, jfloat x, jfloat y) {
    if (g_ai) g_ai->addAction(ACTION_MINE, (int)(x/100.0f), (int)(y/100.0f));
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handlePanNative(JNIEnv* env, jobject obj, jfloat dx, jfloat dy) {
    if (g_renderer) {
        // Pixel to world unit conversion (approximate)
        // Dragging right (positive dx) should move camera left (decrease camX)
        g_renderer->targetX -= dx * 0.005f;
        g_renderer->targetY += dy * 0.005f; // Screen Y is down, world Y is up? Need to check.
        // If Y is inverted in renderer, dy needs sign flip. 
        // Renderer uses Matrix::translate(-camX, -camY, 0).
        // If I drag up (dy < 0), I want to see lower (camY decreases).
        // So targetY += dy is correct if screen Y is down.
    }
}

// 包含绘制逻辑
extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_onDrawFrameNative(JNIEnv* env, jobject obj) {
    if (g_world && g_entities && g_ai) {
        g_ai->update(g_entities->player.x, g_entities->player.y);
        g_entities->update(0.005f);
        if (g_renderer) {
            // Sync player position to renderer
            g_renderer->playerX = g_entities->player.x;
            g_renderer->playerY = g_entities->player.y;
            g_renderer->renderFrame();
        }
    }
}