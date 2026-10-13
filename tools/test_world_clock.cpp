// The original-domain world clock (WORLD_TIME_DOMAIN.md, A-grade: a seconds clock, 900s per in-game day,
// the day fraction DERIVED - and DERIVED FROM A MEASUREMENT: the fraction is a sinusoid, see day_phase.h).
//
// Pinned here: fraction derivation, the v4 persistence round-trip of the
// clock, and that the worker advances the clock by real elapsed time with the
// sleep acceleration scaling it.
#ifdef NDEBUG
#error assertions must remain enabled
#endif
#include <cassert>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <string>
#include <thread>

#include "entity_manager.h"
#include "game_world.h"
#include "persistence_manager.h"

int main() {
    namespace fs = std::filesystem;

    // ---- derivation: dayFraction = fmod(worldSeconds / 900) ----------------
    {
        GameWorld world;
        world.stopThread = true;
        world.queueCV.notify_all();
        world.workerThread.join();

        // The day fraction is a MEASURED sinusoid, not a sawtooth. This block used to assert
        // fmod(worldSeconds, 900) / 900 - the naive reading - and the live measurement on the running original
        // disproved the WAVEFORM (the period is indeed ~900, but the phase is a sinusoid of amplitude ~0.22
        // around ~0.25, so it swings within roughly 0.03..0.47 and never reaches 0 or 1). See day_phase.h for
        // the derivation and tools/test_day_phase.py, which replays the committed 100-sample fixture.
        world.worldSeconds = 0.0;
        const double at_zero = world.dayFraction();
        world.worldSeconds = 895.0;  // the fitted period
        assert(std::abs(world.dayFraction() - at_zero) < 1e-9);
        world.worldSeconds = 1790.0;  // and again, exactly two periods on
        assert(std::abs(world.dayFraction() - at_zero) < 1e-9);
        world.worldSeconds = -895.0;
        assert(std::abs(world.dayFraction() - at_zero) < 1e-9);

        // NON-TAUTOLOGICAL CONTROL. A sawtooth is monotone inside a cycle and jumps at the wrap; a sinusoid
        // rises AND falls. Requiring both directions means any reintroduced monotone day fraction fails here,
        // whichever way it is written - this is the assertion that would have caught the change silently
        // reverting the other way.
        bool rose = false, fell = false;
        world.worldSeconds = 0.0;
        double prev = world.dayFraction();
        for (double w = 3.0; w < 900.0; w += 3.0) {
            world.worldSeconds = w;
            const double cur = world.dayFraction();
            if (cur > prev + 1e-9) rose = true;
            if (cur < prev - 1e-9) fell = true;
            prev = cur;
        }
        assert(rose && fell);

        // the range the measurement established: this is what "the phase never reaches its extremes" means
        for (double w = -1800.0; w < 3600.0; w += 7.0) {
            world.worldSeconds = w;
            const double f = world.dayFraction();
            assert(f > 0.02 && f < 0.48);
        }
        // the direction flag the original exposes is the derivative's sign, not a stored value
        world.worldSeconds = 0.0;
        const bool at_zero_rising = world.headingTowardsMidday();
        world.worldSeconds = 895.0 / 2.0;  // half a period later the slope has the opposite sign
        assert(world.headingTowardsMidday() != at_zero_rising);
        assert(GameWorld::kOriginalSecondsPerDay == 900.0);

        // fastForward: the measured factor and the state that carries it
        // (LIVE_WORLD_CLOCK.md - 20.0 units per real second while the flag is set)
        assert(GameWorld::kOriginalFastForwardScale == 20.0);
        assert(!world.fastForward && world.clockTimeScale == 1.0f);
        world.setFastForward(true);
        assert(world.fastForward && world.clockTimeScale == 20.0f);
        world.setFastForward(false);
        assert(!world.fastForward && world.clockTimeScale == 1.0f);
        // in the measured state one 900-unit day is 45 real seconds
        assert(std::abs(GameWorld::kOriginalSecondsPerDay /
                        GameWorld::kOriginalFastForwardScale - 45.0) < 1e-9);
    }

    // ---- v4 persistence round-trips the clock ------------------------------
    {
        fs::path root = fs::temp_directory_path() / "bh-clock-save";
        fs::remove_all(root);
        fs::create_directories(root);

        {
            GameWorld world;
            world.stopThread = true;
            world.queueCV.notify_all();
            world.workerThread.join();
            EntityManager entities;
            world.worldSeconds = 1234.5;
            world.hasWorldSeconds = true;
            world.setFastForward(true);   // must NOT survive a save
            PersistenceManager::saveWorld(root.c_str(), &world, &entities);
        }
        {
            GameWorld world;
            world.stopThread = true;
            world.queueCV.notify_all();
            world.workerThread.join();
            EntityManager entities;
            assert(PersistenceManager::loadWorld(root.c_str(), &world, &entities));
            assert(world.hasWorldSeconds);
            assert(std::abs(world.worldSeconds - 1234.5) < 1e-6);
            // runtime-only, by evidence: the original's World.fastForward is not a
            // savedict key, so v4 must not resurrect it
            assert(!world.fastForward && world.clockTimeScale == 1.0f);
        }
        fs::remove_all(root);
    }

    // ---- the worker advances the clock with real elapsed time --------------
    {
        GameWorld world;  // worker runs at its 50ms cadence
        world.clockTimeScale = 1.0f;
        const double before = world.worldSeconds;
        std::this_thread::sleep_for(std::chrono::milliseconds(350));
        assert(world.hasWorldSeconds);
        const double advanced = world.worldSeconds - before;
        assert(advanced > 0.15 && advanced < 1.2);  // ~0.35s, tolerant to CI jitter

        // fastForward scales the world clock, not the frame count - and it is the
        // measured 20.0, so a regression to the old invented 100.0 must fail here
        world.setFastForward(true);
        const double before_fast = world.worldSeconds;
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        const double fast = world.worldSeconds - before_fast;
        assert(fast > 3.0);    // ~6.0 at 20x over 300ms
        assert(fast < 15.0);   // a 100x regression would give ~30
        world.setFastForward(false);
        assert(world.clockTimeScale == 1.0f);
        world.stopThread = true;
        world.queueCV.notify_all();
        world.workerThread.join();
    }

    std::cout << "world-clock: PASS (derivation, v4 round-trip, real-time "
                 "advance, acceleration scaling)\n";
    return 0;
}
