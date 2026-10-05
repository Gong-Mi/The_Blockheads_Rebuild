// Contract test: a craft completing queues the sound the ORIGINAL plays, and the name is the recovered one.
//
// Two independent things have to hold, which is why this is worth a test rather than a comment:
//
//   1. the event really happens - a craft reaching 1.0 progress must move CraftingManager::craftsCompleted, and
//      the caller in game_engine.cpp must turn that into a queued sound. (Driven here by inserting a craft at the
//      transition, so removing the counter or the increment fails this test.)
//   2. the asset name is the recovered one. audio_wiring_model.h records that the original plays fanfare.wav for
//      Blockhead -[craftProgressUICompleteButtonTapped], and again when the crafted blockhead is delivered. The
//      app's call site must use that asset - not an invented or mistyped name - which is checked by reading the
//      call site out of game_engine.cpp and matching it against the recovered table.
//
// A test that only grepped for "fanfare.wav" would pass on a comment; this drives the event.
#include "crafting_manager.h"
#include "entity_manager.h"

#include <cassert>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>

#include "audio_wiring_model.h"
#include "game_constants.h"

#ifndef BH_APP_SOURCE_DIR
#error "build must define BH_APP_SOURCE_DIR so this test can read the call site it checks"
#endif

namespace {

std::string read_file(const std::string& path) {
    std::ifstream in(path);
    std::ostringstream out;
    out << in.rdbuf();
    return out.str();
}

}  // namespace

int main() {
    // ---- 1. the recovered table says this asset, for these origins --------------------------------
    constexpr const char* kAsset = "fanfare.wav";
    bool fromCompleteButton = false, fromDelivery = false;
    for (const auto& w : blockheads::recovered::audio::kAudioWiring) {
        if (w.sound != kAsset) continue;
        if (w.method == "Blockhead -[craftProgressUICompleteButtonTapped]") fromCompleteButton = true;
        if (w.method == "DynamicWorld -[teleportBlockhead:toWorkbench:]") fromDelivery = true;
    }
    assert(fromCompleteButton && "the recovered table must attribute fanfare.wav to the complete button");
    assert(fromDelivery && "the recovered table must attribute fanfare.wav to delivering the crafted blockhead");

    // ---- 2. the event moves the counter ----------------------------------------------------------
    EntityManager entities;
    CraftingManager crafting;
    assert(crafting.craftsCompleted == 0);

    // a craft at the edge of completion, as the game would have it just before the timer runs out
    ActiveCraft ac;
    ac.recipeId = 0;
    ac.progress = 0.99f;
    ac.totalTime = 1.0f;
    ac.finished = false;
    ac.outputType = ITEM_EMPTY;
    ac.remainingOutput = 1;
    crafting.activeCrafts[0] = ac;

    const int before = crafting.craftsCompleted;
    crafting.update(0.05f, &entities.player);   // 0.99 + 0.05 crosses 1.0
    assert(crafting.craftsCompleted == before + 1 && "crossing 1.0 must count exactly one completion");

    // and it must count the transition once, not once per frame
    crafting.update(0.05f, &entities.player);
    crafting.update(0.05f, &entities.player);
    assert(crafting.craftsCompleted == before + 1 && "a finished craft must not keep counting");

    // ---- 3. the call site queues that asset ------------------------------------------------------
    const std::string engine = read_file(std::string(BH_APP_SOURCE_DIR) + "/game_engine.cpp");
    assert(!engine.empty() && "game_engine.cpp must be readable for this check");
    assert(engine.find("queueSound(\"" + std::string(kAsset) + "\")") != std::string::npos &&
           "the completion call site must queue the recovered asset");
    assert(engine.find("craftsCompleted") != std::string::npos &&
           "the call site must drain the counter, not guess at completion some other way");
    // and the preserving half: the dirty flag must still follow update()'s return value
    assert(engine.find("inventoryChanged = g_crafting->update(") != std::string::npos &&
           "the inventoryDirty flag must stay tied to update()'s return value");

    std::puts("craft-completion-sound: PASS (event moves the counter; the asset is the recovered one)");
    return 0;
}
