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
    // actionType is slot index (0-9) from Java loop
    if (g_entities && actionType >= 0 && actionType < 10) {
        g_entities->player.selectedSlot = actionType;
        LOGI("Selected Slot: %d (Item: %d)", actionType, g_entities->player.slots[actionType]);
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleCraftNative(JNIEnv* env, jobject obj, jint targetItemId) {
    LOGI("Craft: %d", targetItemId);
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_onSurfaceChangedNative(JNIEnv* env, jobject obj, jint width, jint height) {
    if (g_renderer) {
        g_renderer->resize(width, height);
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleTouchNative(JNIEnv* env, jobject obj, jfloat x, jfloat y) {
    if (!g_renderer || !g_ai || !g_world || !g_entities) return;

    // Convert Screen (x,y) -> NDC (-1..1) -> World
    // Screen X: 0..W -> NDC: -1..1
    float ndcX = (x / (float)g_renderer->screenW) * 2.0f - 1.0f;
    // Screen Y: 0..H -> NDC: 1..-1 (flipped because screen Y is down)
    float ndcY = 1.0f - (y / (float)g_renderer->screenH) * 2.0f;

    // Unproject using Ortho params (-2, 2) width and (-2*aspect, 2*aspect) height
    float aspect = (float)g_renderer->screenH / (float)g_renderer->screenW;
    float worldX_rel = ndcX * 2.0f; // Width is 4 units (-2 to 2)
    float worldY_rel = ndcY * (2.0f * aspect); 

    // Apply Camera position
    float worldX = g_renderer->camX + worldX_rel;
    float worldY = g_renderer->camY + worldY_rel;

    // Convert world float coords to block integer coords
    // 1 block = 0.1f world units
    int blockX = (int)(worldX * 10.0f);
    int blockY = (int)(worldY * 10.0f);

    // Decision: Mine or Place?
    Tile* t = g_world->getTile(blockX, blockY);
    bool targetHasBlock = (t && t->foreground != 0);
    
    // Check if we have an item selected to place
    int slot = g_entities->player.selectedSlot;
    int item = g_entities->player.slots[slot];
    
    if (targetHasBlock) {
        g_ai->addAction(ACTION_MINE, blockX, blockY);
    } else if (item > 0 && g_entities->player.counts[slot] > 0) {
        // Place block
        g_ai->addAction(ACTION_PLACE, blockX, blockY);
    } else {
        // Just walk
        g_ai->addAction(ACTION_WALK, blockX, blockY);
    }
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
    static int frameCount = 0;
    frameCount++;

    if (g_world && g_entities && g_ai) {
        g_ai->update(g_entities->player.x, g_entities->player.y, g_world, g_entities);
        g_entities->update(0.005f);
        
        // Sync Inventory to Java UI
        if (g_entities->inventoryDirty) {
            jclass cls = env->GetObjectClass(obj);
            jmethodID mid = env->GetMethodID(cls, "updateHotbarSlot", "(III)V");
            if (mid) {
                for (int i = 0; i < 10; i++) {
                    env->CallVoidMethod(obj, mid, i, g_entities->player.slots[i], g_entities->player.counts[i]);
                }
            }
            g_entities->inventoryDirty = false;
        }

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

            // Debug Info Overlay (every 30 frames)
            if (frameCount % 30 == 0) {
                jclass cls = env->GetObjectClass(obj);
                jmethodID mid = env->GetMethodID(cls, "updateDebugInfo", "(Ljava/lang/String;)V");
                if (mid) {
                    char buf[256];
                    sprintf(buf, "Cam: %.2f, %.2f\nPlayer: %.2f, %.2f\nVerts: %d\nSlot: %d", 
                        g_renderer->camX, g_renderer->camY,
                        g_entities->player.x, g_entities->player.y,
                        g_renderer->vertexCount,
                        g_entities->player.selectedSlot);
                    jstring str = env->NewStringUTF(buf);
                    env->CallVoidMethod(obj, mid, str);
                    env->DeleteLocalRef(str);
                }
            }
        }
    }
}