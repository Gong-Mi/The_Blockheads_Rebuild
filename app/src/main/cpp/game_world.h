#ifndef GAME_WORLD_H
#define GAME_WORLD_H

#include <vector>
#include "game_constants.h"

class GameWorld {
public:
    std::vector<PhysicalBlock*> chunks;

    int wrapX(int x) {
        if (x < 0) return (x % WORLD_WIDTH) + WORLD_WIDTH;
        return x % WORLD_WIDTH;
    }

    void updateLighting(PhysicalBlock* block) {
        for (int x = 0; x < CHUNK_SIZE; x++) {
            int currentSun = 255;
            for (int y = 0; y < CHUNK_SIZE; y++) {
                Tile& t = block->tiles[y * CHUNK_SIZE + x];
                if (t.foreground != 0) {
                    currentSun -= 40;
                    if (currentSun < 0) currentSun = 0;
                }
                t.sunlight = (uint8_t)currentSun;
            }
        }
    }

    Tile* getTile(int x, int y) {
        int wrappedX = wrapX(x);
        int cx = wrappedX / CHUNK_SIZE;
        int cy = y / CHUNK_SIZE;
        
        for (PhysicalBlock* chunk : chunks) {
            if (chunk->x == cx && chunk->y == cy) {
                int lx = wrappedX % CHUNK_SIZE;
                int ly = y % CHUNK_SIZE;
                return &chunk->tiles[ly * CHUNK_SIZE + lx];
            }
        }
        return nullptr;
    }

    void generateChunk(int cx, int cy) {
        int wrappedX = wrapX(cx);
        PhysicalBlock* block = new PhysicalBlock();
        block->x = wrappedX; // Chunk Index
        block->y = cy;
        
        for (int i = 0; i < CHUNK_SIZE * CHUNK_SIZE; i++) {
            int worldY = cy * CHUNK_SIZE + (i / CHUNK_SIZE);
            Tile& t = block->tiles[i];
            if (worldY > 100) t.foreground = 2; // Stone
            else if (worldY > 80) t.foreground = 1; // Dirt
            else if (worldY == 80) t.foreground = 5; // Grass
            else t.foreground = 0; // Air
            t.damage = 0;
        }
        updateLighting(block);
        chunks.push_back(block);
    }
};

#endif
