#ifndef GAME_CONSTANTS_H
#define GAME_CONSTANTS_H

// --- 世界规模 (还原自指令集) ---
const int WORLD_WIDTH = 15000;    // 环球一周 15000 块
const int WORLD_DEPTH = 500;      // 地下深度 500 块
const int CHUNK_SIZE = 32;        // 每个物理块 32x32

// --- 地理坐标 (基于纬度模拟) ---
const int EQUATOR_1 = 0;          // 第一个赤道
const int POLE_NORTH = 3750;      // 北极
const int EQUATOR_2 = 7500;       // 第二个赤道
const int POLE_SOUTH = 11250;     // 南极

// --- 物理参数 ---
const float PLAYER_WIDTH = 0.06f;
const float PLAYER_HEIGHT = 0.12f;
const float HUNGER_DECAY = 0.001f;
const float ENERGY_DECAY = 0.0005f;

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
