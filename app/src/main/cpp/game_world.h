#ifndef GAME_WORLD_H
#define GAME_WORLD_H

#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include "game_constants.h"
#include "noise_utils.h"

struct LightNode {
    int x, y;
};

class GameWorld {
public:
    static const int MAX_CHUNKS_X = 15000 / CHUNK_SIZE + 1;
    static const int MAX_CHUNKS_Y = WORLD_DEPTH / CHUNK_SIZE + 1;
    
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
};

// Global helper for world wrapping
inline int wrapX(int x) {
    if (x < 0) return (x % 15000) + 15000;
    return x % 15000;
}

#endif