#ifndef GAME_WORLD_H
#define GAME_WORLD_H

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <map>
#include <cstdint>
#include "game_constants.h"
#include "noise_utils.h"

struct LightNode {
    int x, y;
};

struct ContainerData {
    int slots[16]; // 4x4 Chest
    int counts[16];
    ContainerData() {
        for(int i=0; i<16; i++) { slots[i]=0; counts[i]=0; }
    }
};

// Global helper for world wrapping
inline int wrapX(int x) {
    if (x < 0) return (x % 15000) + 15000;
    return x % 15000;
}

class GameWorld {
public:
    static const int MAX_CHUNKS_X = 15000 / CHUNK_SIZE + 1;
    static const int MAX_CHUNKS_Y = WORLD_DEPTH / CHUNK_SIZE + 1;
    
    std::map<uint64_t, ContainerData> containers;
    uint64_t getContainerKey(int x, int y) { return ((uint64_t)wrapX(x) << 32) | (uint64_t)y; }

    PhysicalBlock* chunkGrid[MAX_CHUNKS_X][MAX_CHUNKS_Y];
    std::vector<PhysicalBlock*> chunks; 
    std::mutex chunksMutex;

    std::queue<std::pair<int, int>> taskQueue;
    std::mutex queueMutex;
    std::condition_variable queueCV;
    std::atomic<bool> stopThread{false};
    std::thread workerThread;

    GameWorld();
    ~GameWorld();

    int wrapChunkX(int cx);
    void updateLighting();
    Tile* getTileInternal(int x, int y);
    Tile* getTile(int x, int y) { return getTileInternal(x, y); }
    void workerLoop();
    void processChunkAsync(PhysicalBlock* block);
    // Publish CPU mesh changes after a foreground gameplay edit.
    void refreshTileMesh(int x, int y);
    void buildMeshCache(PhysicalBlock* block);
    void generateChunkSync(int cx, int cy);

public:
    // Original-save world seed (worldv2 randomSeed). The replacement noise
    // functions take no seed of their own, so an imported seed shifts the
    // sample coordinates by a deterministic offset. With no seed imported the
    // offsets stay 0 and generation is unchanged.
    static std::pair<float, float> generationSeedOffset(long long seed);
    void setGenerationSeed(long long seed);
    bool hasGenerationSeed() const { return has_generation_seed_; }
    float generationSeedOffsetX() const { return seed_offset_x_; }
    float generationSeedOffsetY() const { return seed_offset_y_; }

private:
    bool has_generation_seed_ = false;
    float seed_offset_x_ = 0.0f;
    float seed_offset_y_ = 0.0f;
    void updateChunks(float camX, float camY);
    void updateFluids();
    void updateElectricity();
    void updateVegetation();
    void updateTemperature();
    
    float worldTime = 0.0f;
};

#endif