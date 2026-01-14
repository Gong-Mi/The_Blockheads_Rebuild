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
};

#include <vector>

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

enum ItemID {
    ITEM_EMPTY = 0,
    ITEM_DIRT = 1,
    ITEM_STONE = 2,
    BLOCK_WOOD = 3,
    BLOCK_LEAVES = 4,
    BLOCK_GRASS = 5,
    BLOCK_SAND = 6,
    ITEM_COPPER_ORE = 7,
    ITEM_TIN_ORE = 8,
    BLOCK_SNOW = 9,
    ITEM_WORKBENCH = 10,
    ITEM_TOOLBENCH = 11,
    ITEM_FURNACE = 16,
    BLOCK_ICE = 12,
    BLOCK_CACTUS = 13,
    BLOCK_GLASS = 14,
    ITEM_CRAFTBENCH = 15,
    ITEM_TORCH = 20,
    ITEM_FLINT = 21,
    ITEM_STICK = 22,
    ITEM_CAMPFIRE = 23,
    ITEM_CHILI = 30,
    ITEM_DODO_MEAT = 31,
    ITEM_COCONUT = 32,
    ITEM_FUR = 33,
    ITEM_COPPER_INGOT = 40,
    ITEM_TIN_INGOT = 41,
    ITEM_IRON_INGOT = 42,
    ITEM_STEEL_INGOT = 43,
    ITEM_BRONZE_INGOT = 44,
    ITEM_PICKAXE = 50,
    ITEM_IRON_PICKAXE = 110,
    ITEM_IRON_AXE = 111,
    ITEM_IRON_SPADE = 112,
    ITEM_STEEL_PICKAXE = 120,
    ITEM_STEEL_AXE = 121,
    ITEM_STEEL_SPADE = 122,
    ENTITY_DODO = 100,
    ENTITY_DROP_ITEM = 101,
    ENTITY_YAK = 102
};

#endif
