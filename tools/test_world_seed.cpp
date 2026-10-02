// Seed-consumer contract: the original save's randomSeed becomes the
// replacement generation offset (world data source, layer 4 consumer).
//
// Pure and deterministic on purpose: this pins the seed -> offset mapping, the
// "no seed imported" state and the determinism of the mix. It does NOT generate
// chunks, so it makes no claim about the terrain those offsets produce.
#ifdef NDEBUG
#error assertions must remain enabled
#endif
#include <cassert>
#include <iostream>

#include "game_world.h"

int main() {
    GameWorld world;
    // no seed imported: offsets stay 0, generation is unchanged
    assert(!world.hasGenerationSeed());
    assert(world.generationSeedOffsetX() == 0.0f);
    assert(world.generationSeedOffsetY() == 0.0f);

    const auto seeded = GameWorld::generationSeedOffset(1788626619);
    assert(seeded == GameWorld::generationSeedOffset(1788626619));  // deterministic
    assert(GameWorld::generationSeedOffset(1788626620) != seeded);  // mixed, not shifted by 1
    assert(GameWorld::generationSeedOffset(0) != seeded);           // 0 is a real seed
    assert(GameWorld::generationSeedOffset(-1) != seeded);

    world.setGenerationSeed(1788626619);
    assert(world.hasGenerationSeed());
    assert(world.generationSeedOffsetX() == seeded.first);
    assert(world.generationSeedOffsetY() == seeded.second);

    // Access-level guard: game_engine's frame loop drives GameWorld through
    // these members. Taking their address proves access at compile time
    // without running the frame loop, and the host build compiles this test
    // on every push - which is what the APK-only failure taught us to pin.
    auto update_chunks = &GameWorld::updateChunks;
    assert(update_chunks != nullptr);
    (void)world.worldTime;

    // the world owns a worker thread; stop it like the other host tests do
    world.stopThread = true;
    world.queueCV.notify_all();
    world.workerThread.join();

    std::cout << "world-seed: PASS (no seed -> 0 offset; imported seed -> "
                 "deterministic mixed offset)\n";
    return 0;
}
