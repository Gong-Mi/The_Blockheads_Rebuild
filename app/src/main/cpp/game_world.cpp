#include "game_world.h"
#include <cmath>
#include <algorithm>

GameWorld::GameWorld() {
    for(int x=0; x<MAX_CHUNKS_X; x++) 
        for(int y=0; y<MAX_CHUNKS_Y; y++) 
            chunkGrid[x][y] = nullptr;
    
    workerThread = std::thread(&GameWorld::workerLoop, this);
}

GameWorld::~GameWorld() {
    stopThread = true;
    queueCV.notify_all();
    if(workerThread.joinable()) workerThread.join();
}

int GameWorld::wrapChunkX(int cx) {
    int chunksW = 15000 / CHUNK_SIZE; 
    if (cx < 0) return (cx % chunksW) + chunksW;
    return cx % chunksW;
}

void GameWorld::updateLighting() {
    std::lock_guard<std::mutex> lock(chunksMutex);
    
    std::queue<LightNode> sunQueue;
    std::queue<LightNode> artQueue;

    for (auto chunk : chunks) {
        for (int i = 0; i < CHUNK_SIZE * CHUNK_SIZE; i++) {
            Tile& t = chunk->tiles[i];
            t.sunlight = 0; t.artLight = 0;
            int wx = chunk->x * CHUNK_SIZE + (i % CHUNK_SIZE);
            int wy = chunk->y * CHUNK_SIZE + (i / CHUNK_SIZE);
            
            if (wy >= WORLD_DEPTH - 1 || (wy > 120 && t.foreground == ITEM_EMPTY)) { 
                t.sunlight = 255; 
                sunQueue.push({wx, wy}); 
            }
            if (t.foreground == ITEM_TORCH) { 
                t.artLight = 255; 
                artQueue.push({wx, wy}); 
            }
            if (t.foreground == ITEM_ELECTRIC_LAMP && t.powerLevel > 0) {
                t.artLight = 255;
                artQueue.push({wx, wy});
            }
        }
    }

    auto propagate = [&](std::queue<LightNode>& q, bool isSun) {
        int dx[] = {1, -1, 0, 0}; int dy[] = {0, 0, 1, -1};
        while(!q.empty()) {
            LightNode n = q.front(); q.pop();
            Tile* curr = getTileInternal(n.x, n.y);
            if(!curr) continue;
            int val = isSun ? curr->sunlight : curr->artLight;
            if (val <= 0) continue;

            for(int i=0; i<4; i++) {
                int nx = n.x + dx[i]; int ny = n.y + dy[i];
                Tile* next = getTileInternal(nx, ny);
                if(!next) continue;
                
                int loss = (next->foreground != ITEM_EMPTY) ? 60 : 15;
                if (next->waterLevel > 0) loss += (next->waterLevel / 10); // Water blocks light
                int nextVal = val - loss;
                if(nextVal < 0) nextVal = 0;
                
                uint8_t& target = isSun ? next->sunlight : next->artLight;
                if(nextVal > target) { 
                    target = (uint8_t)nextVal; 
                    q.push({nx, ny}); 
                }
            }
        }
    };
    propagate(sunQueue, true);
    propagate(artQueue, false);
}

Tile* GameWorld::getTileInternal(int x, int y) {
    int cx = (int)floor((float)x / CHUNK_SIZE);
    int cy = y / CHUNK_SIZE;
    if (cy < 0 || cy >= MAX_CHUNKS_Y) return nullptr;
    int wrappedCx = wrapChunkX(cx);
    
    PhysicalBlock* chunk = chunkGrid[wrappedCx][cy];
    if (!chunk) return nullptr;
    
    int lx = x % CHUNK_SIZE; if (lx < 0) lx += CHUNK_SIZE;
    int ly = y % CHUNK_SIZE; 
    return &chunk->tiles[ly * CHUNK_SIZE + lx];
}

void GameWorld::updateFluids() {
    std::lock_guard<std::mutex> lock(chunksMutex);
    // Use a temp buffer or careful ordering to avoid "infinite speed" flow in one tick
    // For a prototype, simple sweep is okay
    for (auto chunk : chunks) {
        bool changed = false;
        for (int i = 0; i < CHUNK_SIZE * CHUNK_SIZE; i++) {
            Tile& t = chunk->tiles[i];
            if (t.waterLevel > 0) {
                int wx = chunk->x * CHUNK_SIZE + (i % CHUNK_SIZE);
                int wy = chunk->y * CHUNK_SIZE + (i / CHUNK_SIZE);
                
                // 1. Evaporation (Only at surface if sunlight is high)
                if (t.sunlight > 200 && rand() % 500 < 1) {
                    t.waterLevel--;
                    changed = true;
                    continue;
                }

                // 2. Flow down
                Tile* below = getTileInternal(wx, wy - 1);
                if (below && below->foreground == ITEM_EMPTY && below->waterLevel < 255) {
                    int canTake = 255 - below->waterLevel;
                    int flow = std::min((int)t.waterLevel, canTake);
                    below->waterLevel += flow;
                    t.waterLevel -= flow;
                    changed = true;
                } else if (t.waterLevel > 1) {
                    // 3. Flow sideways
                    int dir = (rand() % 2 == 0) ? 1 : -1;
                    Tile* side = getTileInternal(wx + dir, wy);
                    if (side && side->foreground == ITEM_EMPTY && side->waterLevel < t.waterLevel) {
                        int diff = t.waterLevel - side->waterLevel;
                        if (diff > 1) {
                            int flow = diff / 2;
                            side->waterLevel += flow;
                            t.waterLevel -= flow;
                            changed = true;
                        }
                    }
                }
            }
        }
        if (changed) chunk->dirty = true;
    }
}

void GameWorld::updateElectricity() {
    std::lock_guard<std::mutex> lock(chunksMutex);
    
    // Pass 1: Reset and find sources
    std::queue<LightNode> powerQueue;
    for (auto chunk : chunks) {
        for (int i = 0; i < CHUNK_SIZE * CHUNK_SIZE; i++) {
            Tile& t = chunk->tiles[i];
            t.powerLevel = 0;
            if (t.foreground == ITEM_COAL_GENERATOR) {
                t.powerLevel = 255;
                int wx = chunk->x * CHUNK_SIZE + (i % CHUNK_SIZE);
                int wy = chunk->y * CHUNK_SIZE + (i / CHUNK_SIZE);
                powerQueue.push({wx, wy});
            }
        }
    }

    // Pass 2: Propagate through wires
    int dx[] = {1, -1, 0, 0}; int dy[] = {0, 0, 1, -1};
    while(!powerQueue.empty()) {
        LightNode n = powerQueue.front(); powerQueue.pop();
        Tile* curr = getTileInternal(n.x, n.y);
        if(!curr || curr->powerLevel <= 10) continue;

        for(int i=0; i<4; i++) {
            int nx = n.x + dx[i]; int ny = n.y + dy[i];
            Tile* next = getTileInternal(nx, ny);
            if(next && (next->foreground == ITEM_COPPER_WIRE || next->foreground == ITEM_ELECTRIC_LAMP)) {
                int nextPower = curr->powerLevel - 5; // Power loss over distance
                if(nextPower > next->powerLevel) {
                    next->powerLevel = (uint8_t)nextPower;
                    powerQueue.push({nx, ny});
                }
            }
        }
    }
}

void GameWorld::workerLoop() {
    int tick = 0;
    while (!stopThread) {
        tick++;
        if (tick % 10 == 0) updateFluids(); 
        if (tick % 30 == 0) updateElectricity(); 
        
        std::pair<int, int> task;
        {
            std::unique_lock<std::mutex> lock(queueMutex);
            queueCV.wait(lock, [this]{ return !taskQueue.empty() || stopThread; });
            if (stopThread) return;
            task = taskQueue.front();
            taskQueue.pop();
        }
        
        int cx = task.first;
        int cy = task.second;
        int wCx = wrapChunkX(cx);
        
        if (!chunkGrid[wCx][cy]) {
            generateChunkSync(cx, cy);
        } else if (chunkGrid[wCx][cy]->dirty) {
            processChunkAsync(chunkGrid[wCx][cy]);
        }
    }
}

void GameWorld::processChunkAsync(PhysicalBlock* block) {
    if (!block) return;
    updateLighting(); 
    buildMeshCache(block);
    block->dirty = false;
    block->meshReady = true;
}

void GameWorld::buildMeshCache(PhysicalBlock* block) {
    std::lock_guard<std::mutex> lock(block->dataMutex);
    block->vertexCache.clear();
    
    for (int i = 0; i < CHUNK_SIZE * CHUNK_SIZE; i++) {
        Tile& t = block->tiles[i];
        int lx = i % CHUNK_SIZE;
        int ly = i / CHUNK_SIZE;
        float wx = (float)(block->x * CHUNK_SIZE + lx);
        float wy = (float)(block->y * CHUNK_SIZE + ly);
        
        auto pushPart = [&](int type, float x, float y, float size, uint8_t sun, uint8_t art) {
            if (type == 0) return;
            
            int texRow = 0, texCol = 0;
            auto def = ItemManager::getInstance().getDef(type);
            if (def) {
                texRow = def->texRow;
                texCol = def->texCol;
            } else {
                texCol = (type - 1) % 32;
                texRow = (type - 1) / 32;
            }

            float tx = (float)texCol;
            float ty = (float)texRow;
            float thick = 0.3f; // Original-like thickness

            auto pushV = [&](float vx, float vy, float vz, float vw, float vu, float vv, float oz, float brightnessMult) {
                block->vertexCache.push_back(vx);
                block->vertexCache.push_back(vy);
                block->vertexCache.push_back(vz);
                block->vertexCache.push_back(vw);
                block->vertexCache.push_back(vu);
                block->vertexCache.push_back(vv);
                block->vertexCache.push_back((float)sun * brightnessMult); 
                block->vertexCache.push_back(0.0f);
                block->vertexCache.push_back((float)art * brightnessMult);
                block->vertexCache.push_back(0.0f);
                block->vertexCache.push_back(oz);
                block->vertexCache.push_back(0.0f);
                block->vertexCache.push_back(1.0f);
                block->vertexCache.push_back(1.0f);
                block->vertexCache.push_back(1.0f);
                block->vertexCache.push_back(1.0f);
            };

            // 1. FRONT FACE (Z = 0.0)
            pushV(x,      y,      0.0f, tx, 0.0f,   255.0f, ty, 1.0f);
            pushV(x+size, y,      0.0f, tx, 255.0f, 255.0f, ty, 1.0f);
            pushV(x,      y+size, 0.0f, tx, 0.0f,   0.0f,   ty, 1.0f);
            pushV(x+size, y,      0.0f, tx, 255.0f, 255.0f, ty, 1.0f);
            pushV(x+size, y+size, 0.0f, tx, 255.0f, 0.0f,   ty, 1.0f);
            pushV(x,      y+size, 0.0f, tx, 0.0f,   0.0f,   ty, 1.0f);

            // 2. RIGHT SIDE (Shaded, slanted)
            float rs = 0.7f; // Right side brightness
            pushV(x+size,       y,       0.0f,  tx, 255.0f, 255.0f, ty, rs);
            pushV(x+size+thick, y-thick, -thick,tx, 255.0f, 255.0f, ty, rs);
            pushV(x+size,       y+size,  0.0f,  tx, 255.0f, 0.0f,   ty, rs);
            pushV(x+size+thick, y-thick, -thick,tx, 255.0f, 255.0f, ty, rs);
            pushV(x+size+thick, y+size-thick, -thick, tx, 255.0f, 0.0f, ty, rs);
            pushV(x+size,       y+size,  0.0f,  tx, 255.0f, 0.0f,   ty, rs);

            // 3. BOTTOM SIDE (Darker, slanted)
            float bs = 0.5f; // Bottom side brightness
            pushV(x,            y,       0.0f,  tx, 0.0f,   255.0f, ty, bs);
            pushV(x+size,       y,       0.0f,  tx, 255.0f, 255.0f, ty, bs);
            pushV(x+thick,      y-thick, -thick,tx, 0.0f,   255.0f, ty, bs);
            pushV(x+size,       y,       0.0f,  tx, 255.0f, 255.0f, ty, bs);
            pushV(x+size+thick, y-thick, -thick,tx, 255.0f, 255.0f, ty, bs);
            pushV(x+thick,      y-thick, -thick,tx, 0.0f,   255.0f, ty, bs);
        };

        if (t.background != 0 && t.foreground == 0) {
            pushPart(t.background, wx, wy, 1.0f, t.sunlight, t.artLight);
        }
        if (t.foreground != 0) {
            pushPart(t.foreground, wx, wy, 1.0f, t.sunlight, t.artLight);
        }
    }
}

void GameWorld::generateChunkSync(int cx, int cy) {
    int wrappedX = wrapChunkX(cx);
    if (cy < 0 || cy >= MAX_CHUNKS_Y) return;
    
    PhysicalBlock* block = new PhysicalBlock();
    block->x = wrappedX; block->y = cy;
    
    for (int i = 0; i < CHUNK_SIZE * CHUNK_SIZE; i++) {
        int lx = i % CHUNK_SIZE; int ly = i / CHUNK_SIZE;
        int worldX = wrappedX * CHUNK_SIZE + lx;
        int worldY = cy * CHUNK_SIZE + ly;
        Tile& t = block->tiles[i];
        t.damage = 0; t.sunlight = 0; t.artLight = 0;
        
        float h = Noise::fbm(worldX * 0.02f, 3); 
        
        // --- Biome Logic ---
        float temperature = Noise::fbm(worldX * 0.0005f + 1000.0f, 2); // Large scale temperature
        t.temperature = (uint16_t)((temperature + 1.0f) * 0.5f * 65535.0f); // Store for later
        
        int surfaceHeight = 80 + (int)(h * 20.0f);
        
        if (worldY > surfaceHeight) {
            t.foreground = ITEM_EMPTY;
            t.background = ITEM_EMPTY;
        } else {
            int type = ITEM_STONE;
            if (worldY > surfaceHeight - 5) {
                if (temperature < -0.2f) type = BLOCK_SNOW;      // Cold -> Snow
                else if (temperature > 0.4f) type = BLOCK_SAND;  // Hot -> Sand
                else type = ITEM_DIRT;                           // Normal -> Dirt
            }
            if (worldY == surfaceHeight) {
                if (temperature < -0.2f) type = BLOCK_SNOW;
                else if (temperature > 0.4f) type = BLOCK_SAND;
                else type = BLOCK_GRASS;
            }
            
            float caveNoise = Noise::noise2d(worldX * 0.08f, worldY * 0.08f);
            float caveDensity = 0.55f; 
            if (worldY < 50) caveDensity = 0.45f;

            if (caveNoise > caveDensity) {
                t.foreground = ITEM_EMPTY;
            } else {
                t.foreground = type;
                float oreNoise = Noise::noise2d(worldX * 0.2f, worldY * 0.2f);
                if (oreNoise > 0.75f) {
                    if (worldY < 60 && worldY > 30) t.foreground = ITEM_COPPER_ORE;
                    if (worldY < 40) t.foreground = ITEM_TIN_ORE;
                }
            }
            t.background = (worldY > surfaceHeight - 10) ? ITEM_DIRT : ITEM_STONE;
            if (temperature > 0.4f && worldY <= surfaceHeight) t.background = BLOCK_SAND; 

            if (worldY < 85 && t.foreground == ITEM_EMPTY) {
                if (temperature < -0.4f) t.foreground = BLOCK_ICE; // Freeze water if very cold
                else t.waterLevel = 255;
            } else {
                t.waterLevel = 0;
            }
        }
        if (worldY == 0) t.foreground = ITEM_STONE; 
    }
    
    for (int i = 0; i < CHUNK_SIZE; i++) {
        int worldX = wrappedX * CHUNK_SIZE + i;
        float h = Noise::fbm(worldX * 0.02f, 3);
        int surfaceHeight = 80 + (int)(h * 20.0f);
        
        if (cy * CHUNK_SIZE <= surfaceHeight && (cy + 1) * CHUNK_SIZE > surfaceHeight) {
            int localY = surfaceHeight % CHUNK_SIZE;
            Tile& surfaceTile = block->tiles[localY * CHUNK_SIZE + i];
            
            if (surfaceTile.foreground == BLOCK_SAND) {
                 // Cactus Generation
                 if ((worldX * 731) % 100 < 5) { 
                    int cactusH = 3 + (worldX % 3);
                    for (int ty = 1; ty <= cactusH; ty++) {
                        int targetY = surfaceHeight + ty;
                        if (targetY / CHUNK_SIZE == cy) {
                            int ly = targetY % CHUNK_SIZE;
                            block->tiles[ly * CHUNK_SIZE + i].foreground = BLOCK_CACTUS;
                        }
                    }
                 }
            } else if (surfaceTile.foreground == BLOCK_GRASS || surfaceTile.foreground == BLOCK_SNOW) {
                // Tree Generation
                if ((worldX * 731) % 100 < 15) { 
                    int treeH = 4 + (worldX % 4);
                    for (int ty = 1; ty <= treeH; ty++) {
                        int targetY = surfaceHeight + ty;
                        if (targetY / CHUNK_SIZE == cy) {
                            int ly = targetY % CHUNK_SIZE;
                            Tile& t = block->tiles[ly * CHUNK_SIZE + i];
                            t.foreground = BLOCK_WOOD;
                            if (ty > treeH - 2) {
                                if (i > 0) block->tiles[ly * CHUNK_SIZE + i - 1].foreground = BLOCK_LEAVES;
                                if (i < CHUNK_SIZE - 1) block->tiles[ly * CHUNK_SIZE + i + 1].foreground = BLOCK_LEAVES;
                            }
                        }
                    }
                }
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(chunksMutex);
        chunkGrid[wrappedX][cy] = block;
        chunks.push_back(block);
    }
    processChunkAsync(block);
}

void GameWorld::updateChunks(float camX, float camY) {
    float chunkSize = (float)CHUNK_SIZE;
    int centerCx = (int)floor(camX / chunkSize);
    int centerCy = (int)floor(camY / chunkSize);
    
    for (int dy = -2; dy <= 2; dy++) {
        for (int dx = -2; dx <= 2; dx++) {
            int tCx = centerCx + dx;
            int tCy = centerCy + dy;
            int wCx = wrapChunkX(tCx);
            if (tCy >= 0 && tCy < MAX_CHUNKS_Y && !chunkGrid[wCx][tCy]) {
                std::lock_guard<std::mutex> lock(queueMutex);
                taskQueue.push({tCx, tCy});
                queueCV.notify_one();
            }
        }
    }
}