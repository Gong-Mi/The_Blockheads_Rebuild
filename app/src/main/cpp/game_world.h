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
    void buildMeshCache(PhysicalBlock* block);
    void generateChunkSync(int cx, int cy);
    void updateChunks(float camX, float camY);
    void updateFluids();
    void updateElectricity();
    void updateVegetation();
};

#endif