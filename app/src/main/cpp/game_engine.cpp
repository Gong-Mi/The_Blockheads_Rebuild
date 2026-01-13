#include <jni.h>
#include <string>
#include <vector>
#include <android/log.h>
#include <android/asset_manager_jni.h>
#include "game_constants.h"
#include "game_world.h"

// 子模块头文件
#include "compression_manager.h"
#include "entity_manager.h"
#include "blockhead_ai.h"
#include "persistence_manager.h"
#include "crafting_manager.h"
#include "world_renderer.h"
#include "settings_manager.h"

#undef LOG_TAG
#define LOG_TAG "BlockheadsNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// 全局实例
static GameWorld* g_world = nullptr;
EntityManager* g_entities = nullptr;
BlockheadAI* g_ai = nullptr;
CraftingManager* g_crafting = nullptr;
std::string g_storagePath;

// --- Shared Helper for Surface Created ---
void onSurfaceCreatedInternal(JNIEnv* env, jobject assetMgr) {
    if (!g_renderer) {
        g_renderer = new WorldRenderer();
    }
    g_renderer->init(AAssetManager_fromJava(env, assetMgr));
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_MainMenuActivity_onSurfaceCreatedNative(JNIEnv* env, jobject obj, jobject assetMgr) {
    onSurfaceCreatedInternal(env, assetMgr);
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_MainMenuActivity_onSurfaceChangedNative(JNIEnv* env, jobject obj, jint width, jint height) {
    if (g_renderer) g_renderer->resize(width, height);
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_MainMenuActivity_onDrawFrameNative(JNIEnv* env, jobject obj) {
    if (g_renderer) g_renderer->renderFrame();
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_MainMenuActivity_setMenuModeNative(JNIEnv* env, jobject obj, jboolean mode) {
    if (g_renderer) g_renderer->menuMode = mode;
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_onSurfaceCreatedNative(JNIEnv* env, jobject obj, jobject assetMgr) {
    onSurfaceCreatedInternal(env, assetMgr);
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_initNative(JNIEnv* env, jobject obj, jstring storageDir) {
    CompressionManager::init();
    const char *path = env->GetStringUTFChars(storageDir, 0);
    g_storagePath = std::string(path);
    env->ReleaseStringUTFChars(storageDir, path);
    
    if (!g_world) g_world = new GameWorld();
    if (!g_entities) g_entities = new EntityManager();
    if (!g_ai) g_ai = new BlockheadAI();
    if (!g_crafting) g_crafting = new CraftingManager();
    
    if (!PersistenceManager::loadWorld(g_storagePath.c_str(), g_world, g_entities)) {
        for (int cx = -2; cx <= 2; cx++) {
            for (int cy = 0; cy <= 4; cy++) {
                g_world->generateChunkSync(cx, cy);
            }
        }
        g_entities->player.x = 0.0f;
        g_entities->player.y = 100.0f;
    }
    LOGI("Native Engine Ready");
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_saveGameNative(JNIEnv* env, jobject obj) {
    if (g_world && g_entities && !g_storagePath.empty()) {
        PersistenceManager::saveWorld(g_storagePath.c_str(), g_world, g_entities);
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_getRecipesNative(JNIEnv* env, jobject obj, jint benchId) {
    if (g_crafting) return env->NewStringUTF(g_crafting->getRecipesJson(benchId).c_str());
    return env->NewStringUTF("[]");
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleActionNative(JNIEnv* env, jobject obj, jint actionType) {
    if (g_entities && actionType >= 0 && actionType < 10) g_entities->player.selectedSlot = actionType;
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleCraftNative(JNIEnv* env, jobject obj, jint recipeId) {
    if (g_crafting && g_entities) {
        if (g_crafting->craft(&g_entities->player, recipeId)) g_entities->inventoryDirty = true;
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_onSurfaceChangedNative(JNIEnv* env, jobject obj, jint width, jint height) {
    if (g_renderer) g_renderer->resize(width, height);
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleTouchNative(JNIEnv* env, jobject obj, jfloat x, jfloat y) {
    if (!g_renderer || !g_ai || !g_world || !g_entities) return;
    float aspect = (float)g_renderer->screenW / (float)g_renderer->screenH;
    float h_cam = 10.0f * g_renderer->camZoom;
    float w_cam = h_cam * aspect;
    float worldX = g_renderer->camX + ((x / (float)g_renderer->screenW) * 2.0f - 1.0f) * w_cam;
    float worldY = g_renderer->camY + (1.0f - (y / (float)g_renderer->screenH) * 2.0f) * h_cam;
    int blockX = (int)floor(worldX); int blockY = (int)floor(worldY);
    g_renderer->targetBlockX = blockX; g_renderer->targetBlockY = blockY;
    g_renderer->showActionSquare = true; g_renderer->followingPlayer = true; 
    Tile* t = g_world->getTile(blockX, blockY);
    if (t && (t->foreground == 10 || t->foreground == 11)) g_ai->addAction(ACTION_INTERACT, blockX, blockY);
    else if (t && t->foreground != ITEM_EMPTY) g_ai->addAction(ACTION_MINE, blockX, blockY);
    else g_ai->addAction(ACTION_PLACE, blockX, blockY);
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handlePanNative(JNIEnv* env, jobject obj, jfloat dx, jfloat dy) {
    if (g_renderer) {
        g_renderer->followingPlayer = false; 
        g_renderer->targetX -= dx * 0.02f * g_renderer->camZoom;
        g_renderer->targetY -= dy * 0.02f * g_renderer->camZoom; 
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_setSettingNative(JNIEnv* env, jobject obj, jstring key, jboolean value) {
    const char *k = env->GetStringUTFChars(key, 0);
    SettingsManager::getInstance().setBool(k, value);
    env->ReleaseStringUTFChars(key, k);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_getSettingNative(JNIEnv* env, jobject obj, jstring key, jboolean defaultValue) {
    const char *k = env->GetStringUTFChars(key, 0);
    bool val = SettingsManager::getInstance().getBool(k, defaultValue);
    env->ReleaseStringUTFChars(key, k);
    return val;
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleZoomNative(JNIEnv* env, jobject obj, jfloat scaleFactor) {
    if (g_renderer) {
        g_renderer->camZoom /= scaleFactor; 
        if (g_renderer->camZoom < 0.1f) g_renderer->camZoom = 0.1f; 
        if (g_renderer->camZoom > 15.0f) g_renderer->camZoom = 15.0f; 
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_onDrawFrameNative(JNIEnv* env, jobject obj) {
    if (g_world && g_entities && g_ai) {
        if (g_ai->update(g_entities->player.x, g_entities->player.y, g_world, g_entities)) g_world->updateLighting();
        g_entities->update(0.05f, g_world); 
        if (g_renderer) {
            if (g_renderer->followingPlayer) { g_renderer->targetX = g_entities->player.x; g_renderer->targetY = g_entities->player.y; }
            g_world->updateChunks(g_renderer->camX, g_renderer->camY);
            g_renderer->playerX = g_entities->player.x; g_renderer->playerY = g_entities->player.y;
            { std::lock_guard<std::mutex> lock(g_world->chunksMutex); g_renderer->updateMesh(g_world->chunks); }
            g_renderer->renderFrame();
        }
    }
}
