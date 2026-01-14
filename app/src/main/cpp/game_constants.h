#ifndef GAME_CONSTANTS_H
#define GAME_CONSTANTS_H

#include <stdint.h>
#include <vector>
#include <mutex>


// --- 世界规模 ---
const int WORLD_WIDTH = 15000;    
const int WORLD_DEPTH = 500;      
const int CHUNK_SIZE = 32;        

struct Tile {
    uint8_t foreground;
    uint8_t background;
    uint8_t sunlight;    // 0-255
    uint8_t artLight;    // 0-255 (Torches, etc.)
    uint8_t damage;
    uint8_t waterLevel;
    int8_t normalX;
    int8_t normalY;
    uint8_t paintColor[4];
    uint16_t temperature;
    uint8_t powerLevel; // 0-255
    uint8_t growth;     // 0-255 (Plant growth)
};

#include <vector>
#include "game_item_ids.h"

struct Vertex; // Forward declaration

struct PhysicalBlock {
    int x, y;
    Tile tiles[CHUNK_SIZE * CHUNK_SIZE];
    bool dirty = true;
    bool lightingDirty = true;
    bool meshReady = false;
    std::vector<float> vertexCache; // Staging buffer for async building
    std::mutex dataMutex;
};

// Removed ItemID enum - now generated in game_item_ids.h

#endif
