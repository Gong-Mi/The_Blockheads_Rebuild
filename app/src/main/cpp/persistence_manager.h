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
        uint32_t version = 3; // Upgraded version (Tile size changed)
        fwrite(&version, sizeof(uint32_t), 1, f);

        // 2. Player
        fwrite(&entities->player.x, sizeof(float), 1, f);
        fwrite(&entities->player.y, sizeof(float), 1, f);
        
        int invSize = 30;
        fwrite(entities->player.slots, sizeof(int), invSize, f);
        fwrite(entities->player.counts, sizeof(int), invSize, f);
        
        // 2.5 Status
        fwrite(&entities->player.health, sizeof(float), 1, f);
        fwrite(&entities->player.hunger, sizeof(float), 1, f);
        fwrite(&entities->player.breath, sizeof(float), 1, f);
        fwrite(&entities->player.clothingHead, sizeof(int), 1, f);
        fwrite(&entities->player.clothingLegs, sizeof(int), 1, f);

        // 2.6 Mobs
        uint32_t mobCount = entities->mobs.size();
        fwrite(&mobCount, sizeof(uint32_t), 1, f);
        if (mobCount > 0) {
            fwrite(entities->mobs.data(), sizeof(Entity), mobCount, f);
        }

        // 2.8 Containers
        uint32_t containerCount = world->containers.size();
        fwrite(&containerCount, sizeof(uint32_t), 1, f);
        for (std::map<uint64_t, ContainerData>::iterator it = world->containers.begin(); it != world->containers.end(); ++it) {
            uint64_t key = it->first;
            ContainerData& data = it->second;
            fwrite(&key, sizeof(uint64_t), 1, f);
            fwrite(data.slots, sizeof(int), 16, f);
            fwrite(data.counts, sizeof(int), 16, f);
        }

        // 3. Chunks
        uint32_t chunkCount = world->chunks.size();
        fwrite(&chunkCount, sizeof(uint32_t), 1, f);
        for (PhysicalBlock* chunk : world->chunks) {
            fwrite(&chunk->x, sizeof(int), 1, f);
            fwrite(&chunk->y, sizeof(int), 1, f);
            fwrite(chunk->tiles, sizeof(Tile), CHUNK_SIZE * CHUNK_SIZE, f);
        }

        fclose(f);
        LOGS("World saved successfully!");
    }
    static bool loadWorld(const char* rootDir, GameWorld* world, EntityManager* entities) {
        std::string path = getSavePath(rootDir);
        FILE* f = fopen(path.c_str(), "rb");
        if (!f) {
            LOGS("No save file found at %s", path.c_str());
            return false;
        }

        uint32_t version = 0;
        if (fread(&version, sizeof(uint32_t), 1, f) != 1) { fclose(f); return false; }
        
        if (version < 1 || version > 3) {
            LOGS("Unsupported save version: %u", version);
            fclose(f);
            return false;
        }
        
        if (version < 3) {
            LOGS("Legacy save version %u detected. Forcing new world due to Tile format change.", version);
            fclose(f);
            return false;
        }

        // Load Player
        if (fread(&entities->player.x, sizeof(float), 1, f) != 1) { fclose(f); return false; }
        if (fread(&entities->player.y, sizeof(float), 1, f) != 1) { fclose(f); return false; }
        
        int invSize = (version >= 2) ? 30 : 10;
        if (fread(entities->player.slots, sizeof(int), invSize, f) != (size_t)invSize) { fclose(f); return false; }
        if (fread(entities->player.counts, sizeof(int), invSize, f) != (size_t)invSize) { fclose(f); return false; }
        
        // Load status
        if (fread(&entities->player.health, sizeof(float), 1, f) != 1) { fclose(f); return false; }
        if (fread(&entities->player.hunger, sizeof(float), 1, f) != 1) { fclose(f); return false; }
        if (fread(&entities->player.breath, sizeof(float), 1, f) != 1) { fclose(f); return false; }
        if (fread(&entities->player.clothingHead, sizeof(int), 1, f) != 1) { fclose(f); return false; }
        if (fread(&entities->player.clothingLegs, sizeof(int), 1, f) != 1) { fclose(f); return false; }
        
        entities->inventoryDirty = true;

        // Load Mobs
        uint32_t mobCount = 0;
        if (fread(&mobCount, sizeof(uint32_t), 1, f) == 1 && mobCount < 1000) {
            entities->mobs.resize(mobCount);
            if (mobCount > 0) {
                if (fread(entities->mobs.data(), sizeof(Entity), mobCount, f) != mobCount) {
                    entities->mobs.clear();
                }
            }
        }

        // Load Containers (Version 2+)
        if (version >= 2) {
            uint32_t containerCount = 0;
            if (fread(&containerCount, sizeof(uint32_t), 1, f) == 1 && containerCount < 5000) {
                world->containers.clear();
                for (uint32_t i = 0; i < containerCount; i++) {
                    uint64_t key;
                    ContainerData data;
                    if (fread(&key, sizeof(uint64_t), 1, f) != 1) break;
                    if (fread(data.slots, sizeof(int), 16, f) != 16) break;
                    if (fread(data.counts, sizeof(int), 16, f) != 16) break;
                    world->containers[key] = data;
                }
            }
        }

        // Load Chunks
        uint32_t chunkCount = 0;
        if (fread(&chunkCount, sizeof(uint32_t), 1, f) != 1 || chunkCount > 10000) {
            LOGS("Invalid chunk count: %u", chunkCount);
            fclose(f);
            return false;
        }
        
        world->chunks.clear(); 
        for (uint32_t i = 0; i < chunkCount; i++) {
            PhysicalBlock* chunk = new PhysicalBlock();
            if (fread(&chunk->x, sizeof(int), 1, f) != 1 || 
                fread(&chunk->y, sizeof(int), 1, f) != 1 ||
                fread(chunk->tiles, sizeof(Tile), CHUNK_SIZE * CHUNK_SIZE, f) != (CHUNK_SIZE * CHUNK_SIZE)) {
                delete chunk;
                break;
            }
            world->chunks.push_back(chunk);
            int wrappedX = world->wrapChunkX(chunk->x);
            if (chunk->y >= 0 && chunk->y < GameWorld::MAX_CHUNKS_Y) {
                world->chunkGrid[wrappedX][chunk->y] = chunk;
            }
            // Loaded chunks have tiles but no runtime mesh cache. Rebuild it
            // before the renderer consumes the saved world.
            chunk->dirty = true;
            world->processChunkAsync(chunk);
        }

        fclose(f);
        LOGS("World loaded successfully!");
        return true;
    }
};

#endif
