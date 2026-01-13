#ifndef PERSISTENCE_MANAGER_H
#define PERSISTENCE_MANAGER_H

#include <string>
#include <cstdio>
#include <sys/stat.h>
#include <android/log.h>
#include "game_world.h"
#include "entity_manager.h"

#define SAVE_TAG "Persistence"
#define LOGS(...) __android_log_print(ANDROID_LOG_INFO, SAVE_TAG, __VA_ARGS__)

class PersistenceManager {
public:
    static std::string getSavePath(const char* rootDir) {
        std::string path = std::string(rootDir) + "/world.bin";
        return path;
    }

    static void saveWorld(const char* rootDir, GameWorld* world, EntityManager* entities) {
        if (!world || !entities) return;
        std::string path = getSavePath(rootDir);
        FILE* f = fopen(path.c_str(), "wb");
        if (!f) {
            LOGS("Failed to open file for saving: %s", path.c_str());
            return;
        }

        // 1. Header
        uint32_t version = 1;
        fwrite(&version, sizeof(uint32_t), 1, f);

        // 2. Player Data
        fwrite(&entities->player.x, sizeof(float), 1, f);
        fwrite(&entities->player.y, sizeof(float), 1, f);
        fwrite(entities->player.slots, sizeof(int), 10, f);
        fwrite(entities->player.counts, sizeof(int), 10, f);

        // 3. Chunks
        uint32_t chunkCount = world->chunks.size();
        fwrite(&chunkCount, sizeof(uint32_t), 1, f);

        for (PhysicalBlock* chunk : world->chunks) {
            fwrite(&chunk->x, sizeof(int), 1, f);
            fwrite(&chunk->y, sizeof(int), 1, f);
            // Save tiles (Currently simple struct dump, compression later)
            fwrite(chunk->tiles, sizeof(Tile), CHUNK_SIZE * CHUNK_SIZE, f);
        }

        fclose(f);
        LOGS("World saved to %s", path.c_str());
    }

    static bool loadWorld(const char* rootDir, GameWorld* world, EntityManager* entities) {
        std::string path = getSavePath(rootDir);
        FILE* f = fopen(path.c_str(), "rb");
        if (!f) {
            LOGS("No save file found at %s", path.c_str());
            return false;
        }

        uint32_t version;
        fread(&version, sizeof(uint32_t), 1, f);
        if (version != 1) {
            LOGS("Save version mismatch! Expected 1, got %d", version);
            fclose(f);
            return false;
        }

        // Load Player
        fread(&entities->player.x, sizeof(float), 1, f);
        fread(&entities->player.y, sizeof(float), 1, f);
        fread(entities->player.slots, sizeof(int), 10, f);
        fread(entities->player.counts, sizeof(int), 10, f);
        
        // Notify UI update needed
        entities->inventoryDirty = true;

        // Load Chunks
        uint32_t chunkCount;
        fread(&chunkCount, sizeof(uint32_t), 1, f);
        
        world->chunks.clear(); // Clear existing (if any)
        
        for (uint32_t i = 0; i < chunkCount; i++) {
            PhysicalBlock* chunk = new PhysicalBlock();
            fread(&chunk->x, sizeof(int), 1, f);
            fread(&chunk->y, sizeof(int), 1, f);
            fread(chunk->tiles, sizeof(Tile), CHUNK_SIZE * CHUNK_SIZE, f);
            world->chunks.push_back(chunk);
        }

        fclose(f);
        LOGS("World loaded successfully!");
        return true;
    }
};

#endif
