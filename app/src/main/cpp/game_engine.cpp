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

// Original client assembly (batch b5a/b5b): the recovered original-save path.
#include "original_client_app.h"
#include "original_dynamic_import.h"
#include "original_world_import.h"

#undef LOG_TAG
#define LOG_TAG "BlockheadsNative"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// 全局实例
#include "sound_preload_registry.h"
static blockheads::replacement::SoundPreloadRegistry g_soundPreload;

static GameWorld* g_world = nullptr;
EntityManager* g_entities = nullptr;
BlockheadAI* g_ai = nullptr;
CraftingManager* g_crafting = nullptr;
std::string g_storagePath;
std::recursive_mutex g_engineMutex;
FILE* g_logFile = nullptr;

// The original-client assembly handle (kept alive for later slices; see the
// OriginalClientApp wiring inside initNative).
static bh176::OriginalClientApp g_originalClientApp;

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

    // updateMesh() clears meshReady after uploading a chunk to a VBO.  Those
    // VBOs belonged to the discarded context, while vertexCache remains valid
    // CPU data.  Queue every cached chunk for upload into the new context.
    if (g_world) {
        std::lock_guard<std::mutex> chunksLock(g_world->chunksMutex);
        for (PhysicalBlock* chunk : g_world->chunks) {
            if (chunk) chunk->meshReady = true;
        }
    }
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

    // ---- Original client assembly path (b5b device wiring) ----------------
    // If an assembled original save snapshot is present on the device, open it
    // through the recovered client path and write the load report. This wires
    // OriginalClientApp into the production APK's startup; it does not replace
    // the replacement-world path below, and a missing snapshot is an explicit
    // log line, never invented data.
    {
        const std::string snapshotDir = g_storagePath + "/original-snapshot";
        std::string originalError;
        if (g_originalClientApp.open(snapshotDir, &originalError)) {
            if (g_originalClientApp.loadDynamicObjects(&originalError)) {
                const bh176::ClientAppReport& r = g_originalClientApp.report();
                logToFile("Original snapshot loaded: blocks=%zu records=%zu objects=%zu stub=%zu unidentified=%zu out_of_range=%zu opaque=%zu malformed=%zu",
                          r.blocks, r.dynamic_records, r.dynamic_objects,
                          r.stub_objects, r.unidentified_objects,
                          r.out_of_range_objects, r.opaque_records,
                          r.malformed_records);
                for (const auto& entry : r.per_type) {
                    logToFile("  original type %d: %zu object(s)", entry.first,
                              entry.second);
                }
                // Layer 3: the dynamic domain materialized into markers. This
                // line reports data availability, not gameplay consumption.
                const bh176::DynamicImportReport& mat =
                    g_originalClientApp.materializationReport();
                logToFile("Original dynamic markers: materialized=%zu (floatPos=%zu integer=%zu recovered=%zu stub=%zu) without_position=%zu out_of_world=%zu",
                          mat.materialized, mat.from_float_pos,
                          mat.from_integer_pos, mat.recovered_objects,
                          mat.stub_objects, mat.without_position,
                          mat.out_of_world);
                const bh176::OriginalWorldState& ws =
                    g_originalClientApp.worldState();
                logToFile("Original world state: worldv2=%d randomSeed=%lld portal=%lld expert=%d maxPlayers=%s player_records=%zu opaque_blobs=%zu",
                          ws.worldv2_present ? 1 : 0, ws.random_seed,
                          ws.portal_level, ws.expert_mode ? 1 : 0,
                          ws.max_players.c_str(), ws.player_records,
                          ws.opaque_data_blobs);
                const std::string reportPath =
                    g_storagePath + "/original_snapshot_report.json";
                FILE* reportFile = fopen(reportPath.c_str(), "w");
                if (reportFile) {
                    const std::string json = g_originalClientApp.toJson();
                    fwrite(json.data(), 1, json.size(), reportFile);
                    fclose(reportFile);
                    logToFile("Original snapshot report written: %s",
                              reportPath.c_str());
                } else {
                    logToFile("Original snapshot report NOT writable: %s",
                              reportPath.c_str());
                }
            } else {
                logToFile("Original snapshot open OK but dynamic load failed: %s",
                          originalError.c_str());
            }
        } else {
            logToFile("Original snapshot not present at %s (%s)",
                      snapshotDir.c_str(), originalError.c_str());
        }
    }

    // World data source, layer 2: when an assembled original snapshot is
    // present AND no replacement world.bin exists yet, its decoded block
    // domain becomes the seed terrain (one-time import). After the first
    // save the world.bin becomes authoritative — later launches load it and
    // the player's edits survive; the snapshot stays as the evidence copy.
    // Import is all-or-nothing; on any failure the log names the error and
    // the old generation path runs. Dynamic objects / player state are NOT
    // imported yet (their consumers are separate gaps).
    bool originalTerrainActive = false;
    const bool hasWorldBin =
        std::filesystem::exists(std::filesystem::path(g_storagePath) /
                                "world.bin");
    if (g_originalClientApp.report().blocks > 0 && !hasWorldBin) {
        bh176::WorldImportReport importReport;
        // Layer 4 consumer: the original save's randomSeed becomes the
        // replacement generation seed. It only affects chunks the snapshot
        // does NOT cover; with no seed the generator is unchanged.
        {
            const bh176::OriginalWorldState& ws =
                g_originalClientApp.worldState();
            if (ws.worldv2_present && g_world) {
                g_world->setGenerationSeed(ws.random_seed);
                // Layer 4 clock: the save's own worldTime (seconds) seeds the
                // world clock so season gates and day/night continue where the
                // original left off (this save: 900.0 = exactly one day).
                g_world->worldSeconds = g_originalClientApp.worldTime();

            // Audio: register the original's load-time sound names (World -[incrementalLoad], 32 of
            // them, generated with a --check gate into sound_preload_list.h). This only records what
            // the original names - it plays nothing and claims no playback order. 26 of the 32 are
            // still unreferenced by this replacement, which is the wiring backlog the artifact lists.
            g_soundPreload.registerLoadTimeSounds();
                g_world->hasWorldSeconds = true;
                logToFile("Original world seed applied: randomSeed=%lld "
                          "(offset %.1f,%.1f)",
                          ws.random_seed, g_world->generationSeedOffsetX(),
                          g_world->generationSeedOffsetY());
            }
        }
        if (bh176::importOriginalWorld(g_originalClientApp.world(), *g_world,
                                       importReport)) {
            originalTerrainActive = true;
            logToFile("Original terrain imported: blocks=%zu tiles=%zu mapped=%zu unmapped=%zu item0/air=%zu",
                      importReport.blocks_imported, importReport.tiles_total,
                      importReport.tiles_mapped, importReport.tiles_unmapped,
                      importReport.tiles_empty);
            for (const auto& [tileType, count] : importReport.unmapped_by_tile_type) {
                logToFile("  original TileType %d: %zu tile(s) without a direct item mapping",
                          tileType, count);
            }
            // Seed save: the imported terrain becomes the authoritative
            // world.bin so a later launch (with or without the snapshot)
            // loads the same world instead of re-importing over edits.
            PersistenceManager::saveWorld(g_storagePath.c_str(), g_world, g_entities);
            logToFile("Imported terrain saved as world.bin (seed)");
        } else {
            logToFile("Original terrain import FAILED: %s",
                      importReport.error.c_str());
        }
    }

    if (originalTerrainActive) {
        logToFile("Original terrain active; skipping world generation");
        g_entities->player.x = 16.0f;
        g_entities->player.y = 90.0f;
        g_entities->inventoryDirty = true;
    } else if (!PersistenceManager::loadWorld(g_storagePath.c_str(), g_world, g_entities)) {
        logToFile("No save found or load failed, generating new world...");
        for (int cx = -2; cx <= 2; cx++) {
            for (int cy = 0; cy <= 4; cy++) {
                g_world->generateChunkSync(cx, cy);
            }
        }
        g_entities->player.x = 0.0f;
        g_entities->player.y = 100.0f;
        
        // Explicit original ItemType -> compatibility id boundary. These produce
        // the identical legacy slots/counts; world.bin ids are not renumbered.
        g_entities->player.addOriginalItem(ORIGINAL_ITEM_STICK, 10);
        g_entities->player.addOriginalItem(ORIGINAL_ITEM_FLINT, 10);
        g_entities->player.addOriginalItem(ORIGINAL_BLOCK_WOOD, 10);
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

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_handleMoveNative(JNIEnv*, jobject, jfloat axis, jboolean jump) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (!g_entities) return;
    g_entities->player.inputAxis = axis;   // sustained; Player::update clamps
    if (jump) g_entities->player.jumpRequested = true;
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_clearMoveNative(JNIEnv*, jobject) {
    std::lock_guard<std::recursive_mutex> lock(g_engineMutex);
    if (!g_entities) return;
    g_entities->player.inputAxis = 0.0f;
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
        // Time acceleration. The only multiplier measured in the original is the
        // fastForward state's 20.0 (LIVE_WORLD_CLOCK.md); the previous 100.0 here
        // had no evidence behind it. Which condition sets fastForward in the
        // original is still unknown, so mapping our sleep state onto it is an
        // inference - the STATE and the 20.0 are measured, the trigger is not. See
        // reconstruction/reverse-v3/native/WORLD_CLOCK_WRITER_BOUNDARY.md: eight
        // mechanisms that could have set it statically were each excluded, so the trigger is
        // outside static reach and this mapping stays a labelled guess.
        const bool sleeping = g_ai->isSleeping;
        g_world->setFastForward(sleeping);
        const float timeSpeed = g_world->clockTimeScale;
        if (sleeping && g_renderer && g_renderer->worldTime > 0.25f && g_renderer->worldTime < 0.3f) {
            g_ai->isSleeping = false;   // wake up if it's morning (0.25 is usually dawn)
        }
        if (g_renderer) g_renderer->timeScale = timeSpeed;
        // World clock (WORLD_TIME_DOMAIN.md): the engine's own seconds clock
        // is advanced by the worker's 50ms cadence times the acceleration;
        // the renderer's fraction is derived from it, not the other way round.
        g_world->clockTimeScale = timeSpeed;

        if (g_ai->update(g_entities->player.x, g_entities->player.y, g_world, g_entities)) g_world->updateLighting();
        
        if (g_crafting) {
            const int done = g_crafting->craftsCompleted;
            const bool inventoryChanged = g_crafting->update(0.05f * timeSpeed, &g_entities->player);
            // A craft completing is where the original plays fanfare.wav: it is the sound of
            // Blockhead -[craftProgressUICompleteButtonTapped], and the same asset plays again when the
            // crafted blockhead is delivered. Both are recovered pairs in audio_wiring_model.h, and
            // tools/test_craft_completion_sound.py keeps this call site and that table from disagreeing.
            for (int i = done; i < g_crafting->craftsCompleted; ++i) g_entities->queueSound("fanfare.wav");
            // unchanged from before this edit: the dirty flag follows update()'s return value, which means
            // "the inventory changed", NOT "a craft completed" - those differ whenever a finished craft has
            // output still being delivered.
            if (inventoryChanged) {
                g_entities->inventoryDirty = true;
            }
        }

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
            
            // Time flows world -> renderer (WORLD_TIME_DOMAIN.md): the world
            // clock is authoritative and the renderer mirrors the derived
            // day fraction; copying the renderer fraction into the world made
            // the seconds-domain gates unfireable.
            g_renderer->worldTime = g_world->worldTime;
            
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