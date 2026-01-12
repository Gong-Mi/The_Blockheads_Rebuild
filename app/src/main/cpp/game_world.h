#ifndef GAME_WORLD_H
#define GAME_WORLD_H

#include <vector>
#include "game_constants.h"
#include "noise_utils.h"

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
            int lx = i % CHUNK_SIZE;
            int ly = i / CHUNK_SIZE;
            
            // Absolute World Coordinates
            int worldX = wrappedX * CHUNK_SIZE + lx;
            int worldY = cy * CHUNK_SIZE + ly;
            
            Tile& t = block->tiles[i];
            t.damage = 0;
            
            // 1. Terrain Height (1D Noise)
            // Scale: 0.01 implies terrain features over 100 blocks
            // Amplitude: 20 blocks variation
            // Base height: 80
            float heightNoise = Noise::fbm(worldX * 0.02f, 3); 
            int surfaceHeight = 80 + (int)(heightNoise * 20.0f);
            
            // 2. Cave Generation (2D Noise)
            float caveNoise = Noise::noise2d(worldX * 0.05f, worldY * 0.05f);
            bool isCave = (caveNoise > 0.6f); // Threshold for caves

            if (worldY > surfaceHeight) {
                t.foreground = 0; // Air above ground
            } else if (worldY == surfaceHeight) {
                t.foreground = 5; // Grass on top
            } else if (worldY > surfaceHeight - 5) {
                t.foreground = 1; // Dirt layer
            } else {
                t.foreground = 2; // Stone below
            }
            
            // Carve caves (only underground)
            if (worldY < surfaceHeight && isCave) {
                t.foreground = 0; 
            }
            
            // Bedrock at bottom
            if (worldY == 0) t.foreground = 2; 
        }
        updateLighting(block);
        chunks.push_back(block);
    }
};

#endif
