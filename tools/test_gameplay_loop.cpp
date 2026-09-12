// Production replacement-gameplay regression, NOT an original-runtime oracle.
#ifdef NDEBUG
#error gameplay assertions must remain enabled
#endif
#include <cassert>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <filesystem>
#include "blockhead_ai.h"
#include "persistence_manager.h"

struct Scene {
    std::unique_ptr<GameWorld> world = std::make_unique<GameWorld>();
    std::unique_ptr<PhysicalBlock> chunk = std::make_unique<PhysicalBlock>();
    EntityManager entities;
    BlockheadAI ai;
    Scene() {
        // Deterministic fixture: no worker simulation, real world/tile/mesh code.
        world->stopThread = true;
        world->queueCV.notify_all();
        world->workerThread.join();
        chunk->x = 0; chunk->y = 0;
        std::memset(chunk->tiles, 0, sizeof(chunk->tiles));
        world->chunks.push_back(chunk.get());
        world->chunkGrid[0][0] = chunk.get();
        entities.player.x = 4.5f; entities.player.y = 4.0f;
    }
    ~Scene() { world->chunks.clear(); world->chunkGrid[0][0] = nullptr; }
    Tile& tile(int x=4, int y=4) { return *world->getTile(x,y); }
    bool step() { return ai.update(entities.player.x, entities.player.y, world.get(), &entities); }
};

static void mining() {
    Scene s;
    s.tile().foreground = ITEM_DIRT;
    s.world->processChunkAsync(s.chunk.get());
    const auto before = s.chunk->vertexCache;
    assert(!before.empty());
    s.chunk->meshReady = false;
    s.ai.addAction(ACTION_MINE,4,4);
    for(int i=0;i<512 && !s.ai.actionQueue.empty();++i) s.step();
    assert(s.tile().foreground == ITEM_EMPTY && "mine must not finish before removing target");
    assert(s.ai.actionQueue.empty());
    assert(s.entities.dropItems.size()==1 && s.entities.dropItems[0].itemId==ITEM_DIRT);
    assert(s.chunk->meshReady && "changed terrain must reach mesh upload queue");
    assert(s.chunk->vertexCache != before);
    s.step();
    assert(s.entities.dropItems.size()==1);
}

static void fullPickup() {
    EntityManager e;
    for(int i=0;i<Player::INVENTORY_SIZE;++i) { e.player.slots[i]=ITEM_DIRT; e.player.counts[i]=99; }
    e.spawnDrop(0,1.5f,ITEM_DIRT);
    e.update(0,nullptr);
    assert(e.dropItems.size()==1 && "full inventory must retain unaccepted drop");
    assert(!e.inventoryDirty && e.soundEvents.empty());
    e.player.counts[0]=98;
    e.dropItems[0].x=e.player.x; e.dropItems[0].y=e.player.y+1.5f;
    e.update(0,nullptr);
    assert(e.dropItems.empty() && e.player.counts[0]==99);
    assert(e.inventoryDirty && e.soundEvents.size()==1);
    e.update(0,nullptr);
    assert(e.soundEvents.size()==1);
}

static void placement() {
    Scene s;
    s.entities.player.addItem(ITEM_ELEVATOR_MOTOR,1);
    s.ai.addAction(ACTION_PLACE,4,4);
    assert(s.step());
    assert(s.tile().foreground==ITEM_ELEVATOR_MOTOR && "16-bit runtime item must not truncate to 8 bits");
    assert(s.entities.player.counts[0]==0 && s.entities.player.slots[0]==ITEM_EMPTY);
    assert(s.entities.inventoryDirty);
    assert(s.chunk->meshReady && !s.chunk->vertexCache.empty());
    s.entities.player.addItem(ITEM_DIRT,1);
    s.ai.addAction(ACTION_PLACE,4,4);
    assert(!s.step());
    assert(s.entities.player.counts[0]==1 && s.tile().foreground==ITEM_ELEVATOR_MOTOR);
}

static void neighborLighting() {
    Scene s;
    auto neighbor=std::make_unique<PhysicalBlock>();
    neighbor->x=1; neighbor->y=0;
    std::memset(neighbor->tiles,0,sizeof(neighbor->tiles));
    neighbor->tiles[4*CHUNK_SIZE].foreground=ITEM_DIRT;
    s.world->chunks.push_back(neighbor.get());
    s.world->chunkGrid[1][0]=neighbor.get();
    s.world->processChunkAsync(neighbor.get());
    const auto before=neighbor->vertexCache;
    neighbor->meshReady=false;
    s.entities.player.x=31.5f;
    s.entities.player.addItem(ITEM_TORCH,1);
    s.ai.addAction(ACTION_PLACE,31,4);
    assert(s.step());
    assert(neighbor->tiles[4*CHUNK_SIZE].artLight>0);
    assert(neighbor->meshReady && neighbor->vertexCache!=before);
    // Removing that torch must republish the neighboring darkened mesh too.
    const auto lit=neighbor->vertexCache;
    neighbor->meshReady=false;
    s.world->getTile(31,4)->damage=240;
    s.ai.addAction(ACTION_MINE,31,4);
    assert(s.step());
    assert(neighbor->tiles[4*CHUNK_SIZE].artLight==0);
    assert(neighbor->meshReady && neighbor->vertexCache!=lit);
    s.world->chunks.pop_back(); s.world->chunkGrid[1][0]=nullptr;
}

static void closedLoop() {
    Scene s;
    s.tile().foreground=ITEM_DIRT;
    s.ai.addAction(ACTION_MINE,4,4);
    for(int i=0;i<512 && !s.ai.actionQueue.empty();++i) s.step();
    assert(s.entities.dropItems.size()==1);
    // Bring the actual produced drop to the pickup boundary, not a new item.
    s.entities.dropItems[0].x=s.entities.player.x;
    s.entities.dropItems[0].y=s.entities.player.y+1.5f;
    s.entities.update(0,nullptr);
    assert(s.entities.dropItems.empty());
    assert(s.entities.player.slots[0]==ITEM_DIRT && s.entities.player.counts[0]==1);
    s.entities.player.x=5.5f;
    s.ai.addAction(ACTION_PLACE,5,4);
    assert(s.step());
    assert(s.tile().foreground==ITEM_EMPTY && s.tile(5,4).foreground==ITEM_DIRT);
    assert(s.entities.player.counts[0]==0);

    // Exercise the existing development save format with the actual edited
    // world and inventory. This is explicitly NOT an original LMDB import.
    std::string pattern=(std::filesystem::temp_directory_path()/"bh-gameplay-XXXXXX").string();
    assert(mkdtemp(pattern.data()));
    PersistenceManager::saveWorld(pattern.c_str(),s.world.get(),&s.entities);
    auto loaded=std::make_unique<GameWorld>();
    loaded->stopThread=true; loaded->queueCV.notify_all(); loaded->workerThread.join();
    EntityManager restored;
    assert(PersistenceManager::loadWorld(pattern.c_str(),loaded.get(),&restored));
    assert(loaded->chunks.size()==1);
    assert(std::memcmp(s.chunk->tiles,loaded->chunks[0]->tiles,sizeof(s.chunk->tiles))==0);
    assert(std::memcmp(s.entities.player.slots,restored.player.slots,sizeof(restored.player.slots))==0);
    assert(std::memcmp(s.entities.player.counts,restored.player.counts,sizeof(restored.player.counts))==0);
    assert(loaded->getTile(4,4)->foreground==ITEM_EMPTY && loaded->getTile(5,4)->foreground==ITEM_DIRT);
    assert(loaded->chunks[0]->meshReady && !loaded->chunks[0]->vertexCache.empty());
    for(auto* chunk:loaded->chunks) delete chunk;
    loaded->chunks.clear();
    std::filesystem::remove_all(pattern);
}

static void rejectedTargets() {
    Scene s;
    for (int y=-CHUNK_SIZE; y<0; ++y) assert(s.world->getTile(4,y)==nullptr);
    s.ai.addAction(ACTION_MINE,4,4);
    s.step();
    assert(s.ai.actionQueue.empty() && s.entities.dropItems.empty());
    s.ai.addAction(ACTION_PLACE,4,4);
    assert(!s.step());
    assert(s.tile().foreground==ITEM_EMPTY && !s.entities.inventoryDirty);
}

int main(int argc,char** argv) {
    assert(argc==2);
    const std::string name=argv[1];
    if(name=="mining") mining();
    else if(name=="pickup") fullPickup();
    else if(name=="placement") { placement(); neighborLighting(); }
    else if(name=="loop") closedLoop();
    else if(name=="reject") rejectedTargets();
    else return 2;
    std::cout << "PASS gameplay " << name << '\n';
}
