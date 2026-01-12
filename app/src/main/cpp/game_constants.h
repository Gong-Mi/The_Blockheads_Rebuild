#ifndef GAME_CONSTANTS_H
#define GAME_CONSTANTS_H

#include <stdint.h>

// --- 世界规模 (还原自指令集) ---
const int WORLD_WIDTH = 15000;    // 环球一周 15000 块
const int WORLD_DEPTH = 500;      // 地下深度 500 块
const int CHUNK_SIZE = 32;        // 每个物理块 32x32

struct Tile {
    uint8_t foreground;
    uint8_t background;
    uint8_t sunlight;
    uint8_t artLight;
    uint8_t damage;
    uint8_t waterLevel;
    int8_t normalX;
    int8_t normalY;
    uint8_t paintColor[4];
    uint16_t temperature;
};

struct PhysicalBlock {
    int x, y;
    Tile tiles[CHUNK_SIZE * CHUNK_SIZE];
};

// --- 地理坐标 (基于纬度模拟) ---
const int EQUATOR_1 = 0;          // 第一个赤道
const int POLE_NORTH = 3750;      // 北极
const int EQUATOR_2 = 7500;       // 第二个赤道
const int POLE_SOUTH = 11250;     // 南极

// --- 物理参数 ---
const int MAX_WATER_LEVEL = 255;
const int FREEZING_POINT = 32;    // 华氏度模拟
const int BOILING_POINT = 212;
const float TEMP_CONVECTION = 0.05f; // 温度对流系数
const float WATER_FLOW_SPEED = 0.2f;

// --- 物品 ID 定义 (部分还原) ---
enum ItemID {
    ITEM_EMPTY = 0,
    ITEM_DIRT = 1,
    ITEM_STONE = 2,
    ITEM_FLINT = 4,   // 挖掘泥土掉落
    ITEM_STICK = 6,   // 砍树掉落
    ITEM_WORKBENCH = 10,
    ITEM_TIME_CRYSTAL = 100
};

#endif
