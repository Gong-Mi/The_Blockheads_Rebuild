#include <jni.h>
#include <string>
#include <vector>
#include <android/log.h>
#include "game_constants.h"
#include "game_world.h"

// 引入子模块源码 (这些文件必须存在)
#include "compression_manager.cpp"
#include "entity_manager.cpp"
#include "blockhead_ai.cpp"

// 声明渲染器全局指针 (由 world_renderer.cpp 提供)
#include "world_renderer.h"

#undef LOG_TAG
#define LOG_TAG "BlockheadsNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

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
    
    // Generate surface chunks (y=80 is ground, so we need chunks at cy=2, cx=0...3)
    g_world->generateChunk(0, 2); // y: 64-95
    g_world->generateChunk(0, 3); // y: 96-127
    
    // Position player and camera at the ground level
    g_entities->player.x = 1.0f;
    g_entities->player.y = 8.1f; // Just above ground (8.0)
    
    if (g_renderer) {
        g_renderer->updateMesh(g_world->chunks);
        g_renderer->targetX = 1.0f;
        g_renderer->targetY = 8.0f;
        g_renderer->camX = 1.0f;
        g_renderer->camY = 8.0f;
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
        g_ai->update(g_entities->player.x, g_entities->player.y, g_world, g_entities);
        g_entities->update(0.005f);
        if (g_renderer) {
            // Sync player position to renderer
            g_renderer->playerX = g_entities->player.x;
            g_renderer->playerY = g_entities->player.y;
            
            // Sync drop items
            g_renderer->dropItems.clear();
            for (const auto& e : g_entities->dropItems) {
                g_renderer->dropItems.push_back({e.x, e.y, e.type});
            }
            
            // For prototype: brute-force update mesh every frame to show mining damage
            // In production: only update when dirty
            g_renderer->updateMesh(g_world->chunks);
            
            g_renderer->renderFrame();
        }
    }
}