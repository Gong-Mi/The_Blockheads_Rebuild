#include <jni.h>
#include <string>
#include <vector>
#include <mutex>
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
std::recursive_mutex g_engineMutex;
FILE* g_logFile = nullptr;

void logToFile(const char* fmt, ...) {
    if(!g_logFile) return;
    va_list args;
    va_start(args, fmt);
    vfprintf(g_logFile, fmt, args);
    va_end(args);
    fprintf(g_logFile, "\n");
    fflush(g_logFile);
}

// --- Shared Helper for Surface Created ---
void onSurfaceCreatedInternal(JNIEnv* env, jobject assetMgr) {
    logToFile("onSurfaceCreatedInternal called");

    // MainMenuActivity and GameActivity each create their own GLSurfaceView and
    // EGL context.  Program, texture and VBO names from the previous context are
    // invalid here even though the C++ pointer survives the Activity transition.
    // Rebuild the renderer and all context-owned resources for this surface.
    delete g_renderer;
    g_renderer = new WorldRenderer();
    g_renderer->init(AAssetManager_fromJava(env, assetMgr));
    logToFile("Renderer replaced and initialized for current EGL context");
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_MainMenuActivity_onSurfaceCreatedNativeInternal(JNIEnv* env, jobject obj, jobject assetMgr) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    onSurfaceCreatedInternal(env, assetMgr);
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_MainMenuActivity_onSurfaceChangedNative(JNIEnv* env, jobject obj, jint width, jint height) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (g_renderer) g_renderer->resize(width, height);
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_MainMenuActivity_onDrawFrameNative(JNIEnv* env, jobject obj) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (g_renderer) g_renderer->renderFrame();
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_MainMenuActivity_setMenuModeNative(JNIEnv* env, jobject obj, jboolean mode) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (g_renderer) g_renderer->menuMode = mode;
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_MainMenuActivity_handleMenuTouchNative(JNIEnv* env, jobject obj, jfloat x, jfloat y) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (g_renderer) {
        g_renderer->menuTouchX = x;
        g_renderer->menuTouchY = y;
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_onSurfaceCreatedNative(JNIEnv* env, jobject obj, jobject assetMgr) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    onSurfaceCreatedInternal(env, assetMgr);
    if (g_renderer) g_renderer->menuMode = false;
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_initNative(JNIEnv* env, jobject obj, jstring storageDir) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    CompressionManager::init();
    const char *path = env->GetStringUTFChars(storageDir, 0);
    g_storagePath = std::string(path);
    env->ReleaseStringUTFChars(storageDir, path);
    
    // Init Logging
    std::string logPath = g_storagePath + "/game_log.txt";
    g_logFile = fopen(logPath.c_str(), "w");
    logToFile("Native Init Start. Storage: %s", g_storagePath.c_str());

    SettingsManager::getInstance().load(g_storagePath + "/settings.ini");

    CompressionManager::init();
    
    if (!g_world) g_world = new GameWorld();
    if (!g_entities) g_entities = new EntityManager();
    if (!g_ai) g_ai = new BlockheadAI();
    if (!g_crafting) g_crafting = new CraftingManager();
    
    logToFile("Managers allocated");

    if (!PersistenceManager::loadWorld(g_storagePath.c_str(), g_world, g_entities)) {
        logToFile("No save found or load failed, generating new world...");
        for (int cx = -2; cx <= 2; cx++) {
            for (int cy = 0; cy <= 4; cy++) {
                g_world->generateChunkSync(cx, cy);
            }
        }
        g_entities->player.x = 0.0f;
        g_entities->player.y = 100.0f;
        
        // Initial supplies for logic verification
        g_entities->player.addItem(ITEM_STICK, 10);
        g_entities->player.addItem(ITEM_FLINT, 10);
        g_entities->player.addItem(BLOCK_WOOD, 10);
        g_entities->inventoryDirty = true;
    } else {
        logToFile("World loaded successfully");
    }
    LOGI("Native Engine Ready");
    logToFile("Native Init Complete");
    jclass clazz = env->GetObjectClass(obj);
    jmethodID debugMethod = env->GetMethodID(clazz, "updateDebugInfo", "(Ljava/lang/String;)V");
    if (debugMethod) {
        jstring ready = env->NewStringUTF("Ready");
        env->CallVoidMethod(obj, debugMethod, ready);
        env->DeleteLocalRef(ready);
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_saveGameNative(JNIEnv* env, jobject obj) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (g_world && g_entities && !g_storagePath.empty()) {
        PersistenceManager::saveWorld(g_storagePath.c_str(), g_world, g_entities);
    }
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_getRecipesNative(JNIEnv* env, jobject obj, jint benchId) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (g_crafting) return env->NewStringUTF(g_crafting->getRecipesJson(benchId).c_str());
    return env->NewStringUTF("[]");
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleActionNative(JNIEnv* env, jobject obj, jint actionType) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (g_entities && actionType >= 0 && actionType < 10) g_entities->player.selectedSlot = actionType;
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleCraftNative(JNIEnv* env, jobject obj, jint recipeId, jint tx, jint ty) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (g_crafting && g_entities) {
        if (g_crafting->startCraft(&g_entities->player, recipeId, tx, ty)) {
            g_entities->inventoryDirty = true;
            g_entities->queueSound("craftCreate.wav");
        }
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleSwapInventoryItemNative(JNIEnv* env, jobject obj, jint fromSlot, jint toSlot) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (g_entities) {
        if (fromSlot >= 0 && fromSlot < 30 && toSlot >= 0 && toSlot < 30) {
            std::swap(g_entities->player.slots[fromSlot], g_entities->player.slots[toSlot]);
            std::swap(g_entities->player.counts[fromSlot], g_entities->player.counts[toSlot]);
            g_entities->inventoryDirty = true;
        }
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_onSurfaceChangedNative(JNIEnv* env, jobject obj, jint width, jint height) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (g_renderer) g_renderer->resize(width, height);
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleTouchNative(JNIEnv* env, jobject obj, jfloat x, jfloat y) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
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
    if (t && (t->foreground == 11 || t->foreground == 12 || t->foreground == 16 || t->foreground == 17 || t->foreground == 19 || t->foreground == 23 || t->foreground == 110 || t->foreground == 72 || t->foreground == 150 || t->foreground == 270 || t->foreground == 272)) g_ai->addAction(ACTION_INTERACT, blockX, blockY);
    else if (t && t->foreground != ITEM_EMPTY) g_ai->addAction(ACTION_MINE, blockX, blockY);
    else {
        int slot = g_entities->player.selectedSlot;
        int item = g_entities->player.slots[slot];
        if (item == ITEM_CHILI || item == ITEM_DODO_MEAT || item == ITEM_COCONUT) {
            g_ai->addAction(ACTION_EAT, blockX, blockY);
        } else if (item == ITEM_LINEN_CAP || item == ITEM_LINEN_PANTS) {
            g_ai->addAction(ACTION_WEAR, blockX, blockY);
        } else {
            g_ai->addAction(ACTION_PLACE, blockX, blockY);
        }
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handlePanNative(JNIEnv* env, jobject obj, jfloat dx, jfloat dy) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (g_renderer) {
        g_renderer->followingPlayer = false; 
        g_renderer->targetX -= dx * 0.02f * g_renderer->camZoom;
        g_renderer->targetY -= dy * 0.02f * g_renderer->camZoom; 
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_setSettingNative(JNIEnv* env, jobject obj, jstring key, jboolean value) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    const char *k = env->GetStringUTFChars(key, 0);
    SettingsManager::getInstance().setBool(k, value);
    env->ReleaseStringUTFChars(key, k);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_getSettingNative(JNIEnv* env, jobject obj, jstring key, jboolean defaultValue) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    const char *k = env->GetStringUTFChars(key, 0);
    bool val = SettingsManager::getInstance().getBool(k, defaultValue);
    env->ReleaseStringUTFChars(key, k);
    return val;
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleZoomNative(JNIEnv* env, jobject obj, jfloat scaleFactor) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (g_renderer) {
        g_renderer->camZoom /= scaleFactor; 
        if (g_renderer->camZoom < 0.1f) g_renderer->camZoom = 0.1f; 
        if (g_renderer->camZoom > 15.0f) g_renderer->camZoom = 15.0f; 
    }
}

extern "C" JNIEXPORT jint JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_getContainerItemTypeNative(JNIEnv* env, jobject obj, jint x, jint y, jint slot) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (!g_world) return 0;
    uint64_t key = g_world->getContainerKey(x, y);
    if (g_world->containers.count(key)) {
        return g_world->containers[key].slots[slot];
    }
    return 0;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_getContainerItemCountNative(JNIEnv* env, jobject obj, jint x, jint y, jint slot) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (!g_world) return 0;
    uint64_t key = g_world->getContainerKey(x, y);
    if (g_world->containers.count(key)) {
        return g_world->containers[key].counts[slot];
    }
    return 0;
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_setContainerItemNative(JNIEnv* env, jobject obj, jint x, jint y, jint slot, jint type, jint count) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (!g_world) return;
    uint64_t key = g_world->getContainerKey(x, y);
    g_world->containers[key].slots[slot] = type;
    g_world->containers[key].counts[slot] = count;
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleSleepNative(JNIEnv* env, jobject obj) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (g_ai) {
        // Clear previous actions to focus on sleeping
        std::queue<Action> empty;
        std::swap(g_ai->actionQueue, empty);
        
        g_ai->addAction(ACTION_SLEEP, g_ai->pendingInteractionX, g_ai->pendingInteractionY);
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_onDrawFrameNative(JNIEnv* env, jobject obj) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    static int frameLog = 0;
    if (frameLog++ % 600 == 0) logToFile("Frame %d", frameLog);

    if (g_world && g_entities && g_ai) {
        // Time Acceleration Logic
        float timeSpeed = 1.0f;
        if (g_ai->isSleeping) {
            timeSpeed = 100.0f; // 100x speed
            // Wake up if it's morning (0.25 is usually dawn)
            if (g_renderer && g_renderer->worldTime > 0.25f && g_renderer->worldTime < 0.3f) {
                g_ai->isSleeping = false;
            }
        }
        if (g_renderer) g_renderer->timeScale = timeSpeed;

        if (g_ai->update(g_entities->player.x, g_entities->player.y, g_world, g_entities)) g_world->updateLighting();
        
        if (g_crafting) g_crafting->update(0.05f * timeSpeed, &g_entities->player);

        if (g_ai->pendingInteractionBenchId != -1) {
            jclass clazz = env->GetObjectClass(obj);
            if (g_ai->pendingInteractionBenchId == 19) { // Chest
                 jmethodID mid = env->GetMethodID(clazz, "openContainer", "(II)V"); 
                 if (mid) env->CallVoidMethod(obj, mid, g_ai->pendingInteractionX, g_ai->pendingInteractionY);
            } else {
                 jmethodID mid = env->GetMethodID(clazz, "openCraftingMenu", "(III)V");
                 if (mid) env->CallVoidMethod(obj, mid, g_ai->pendingInteractionBenchId, g_ai->pendingInteractionX, g_ai->pendingInteractionY);
            }
            g_ai->pendingInteractionBenchId = -1;
        }

        g_entities->update(0.05f * timeSpeed, g_world);

        // Sync Inventory to Java
        if (g_entities->inventoryDirty) {
            jclass clazz = env->GetObjectClass(obj);
            jmethodID mid = env->GetMethodID(clazz, "updateHotbarSlot", "(III)V");
            for (int i = 0; i < 30; i++) {
                env->CallVoidMethod(obj, mid, i, g_entities->player.slots[i], g_entities->player.counts[i]);
            }
            g_entities->inventoryDirty = false;
        }

        // Sync Status UI
        static int statusTick = 0;
        if (statusTick++ % 10 == 0) {
            jclass clazz = env->GetObjectClass(obj);
            jmethodID mid = env->GetMethodID(clazz, "updateStatusUI", "(FF)V");
            if (mid) env->CallVoidMethod(obj, mid, g_entities->player.health, g_entities->player.hunger);
        }

        // Sync Name Tag Position
        static int nameTagTick = 0;
        if (g_renderer && nameTagTick++ % 2 == 0) {
            float screenX, screenY;
            g_renderer->projectWorldToScreen(g_entities->player.x, g_entities->player.y + 1.8f, screenX, screenY);
            jclass clazz = env->GetObjectClass(obj);
            jmethodID mid = env->GetMethodID(clazz, "updateNameTagPosition", "(FF)V");
            if (mid) env->CallVoidMethod(obj, mid, screenX, screenY);
        }

        // Process Sound Events
        if (!g_entities->soundEvents.empty()) {
            jclass clazz = env->GetObjectClass(obj);
            jmethodID mid = env->GetMethodID(clazz, "playSound", "(Ljava/lang/String;)V");
            for (const auto& sound : g_entities->soundEvents) {
                jstring jStr = env->NewStringUTF(sound.c_str());
                env->CallVoidMethod(obj, mid, jStr);
                env->DeleteLocalRef(jStr);
            }
            g_entities->soundEvents.clear();
        }

        // Process Floating Text
        if (!g_entities->textEvents.empty()) {
            jclass clazz = env->GetObjectClass(obj);
            jmethodID mid = env->GetMethodID(clazz, "showFloatingText", "(FFLjava/lang/String;I)V");
            for (const auto& evt : g_entities->textEvents) {
                float sx, sy;
                g_renderer->projectWorldToScreen(evt.x, evt.y, sx, sy);
                jstring jStr = env->NewStringUTF(evt.text.c_str());
                env->CallVoidMethod(obj, mid, sx, sy, jStr, (jint)evt.color);
                env->DeleteLocalRef(jStr);
            }
            g_entities->textEvents.clear();
        }

        if (g_renderer) {
            if (g_renderer->followingPlayer) { g_renderer->targetX = g_entities->player.x; g_renderer->targetY = g_entities->player.y; }
            g_world->updateChunks(g_renderer->camX, g_renderer->camY);
            
            // Sync Time to World for Simulation (Temperature, etc)
            g_world->worldTime = g_renderer->worldTime;
            
            // Sync Clothing for Rendering
            g_renderer->clothingHead = g_entities->player.clothingHead;
            g_renderer->clothingLegs = g_entities->player.clothingLegs;
            
            // Ambient Sounds
            static int ambientTick = 0;
            if (ambientTick++ % 300 == 0) {
                float t = g_renderer->worldTime;
                bool isDay = (t > 0.25f && t < 0.75f);
                if (rand() % 100 < 30) {
                    if (isDay) {
                        int birdIdx = 1 + (rand() % 14);
                        g_entities->queueSound("bird" + std::to_string(birdIdx) + ".wav");
                    } else {
                        g_entities->queueSound(rand() % 2 == 0 ? "crickets1.wav" : "crickets2.wav");
                    }
                }
            }
            
            // BGM
            float t = g_renderer->worldTime;
            const char* desiredMusic = (t > 0.25f && t < 0.75f) ? "morning.mp4" : "nightFall.mp4";
            static std::string lastMusic = "";
            if (lastMusic != desiredMusic) {
                 jclass clazz = env->GetObjectClass(obj);
                 jmethodID mid = env->GetMethodID(clazz, "playMusic", "(Ljava/lang/String;)V");
                 jstring jStr = env->NewStringUTF(desiredMusic);
                 env->CallVoidMethod(obj, mid, jStr);
                 env->DeleteLocalRef(jStr);
                 lastMusic = desiredMusic;
            }
            g_renderer->playerX = g_entities->player.x; g_renderer->playerY = g_entities->player.y;
            
            g_renderer->dropItems.clear();
            for (const auto& e : g_entities->dropItems) {
                g_renderer->dropItems.push_back({e.x, e.y, e.itemId});
            }
            
            g_renderer->mobs.clear();
            for (const auto& m : g_entities->mobs) {
                g_renderer->mobs.push_back({m.x, m.y, m.type});
            }

            { std::lock_guard<std::mutex> lock(g_world->chunksMutex); g_renderer->updateMesh(g_world->chunks); }
            g_renderer->renderFrame();
            if (frameLog % 60 == 0) {
                char status[128];
                snprintf(status, sizeof(status), "Ready chunks=%zu vertices=%d",
                         g_renderer->chunkMeshes.size(), g_renderer->totalVertexCount);
                jclass statusClazz = env->GetObjectClass(obj);
                jmethodID statusMethod = env->GetMethodID(statusClazz, "updateDebugInfo", "(Ljava/lang/String;)V");
                if (statusMethod) {
                    jstring statusString = env->NewStringUTF(status);
                    env->CallVoidMethod(obj, statusMethod, statusString);
                    env->DeleteLocalRef(statusString);
                }
            }
        }
    }
}