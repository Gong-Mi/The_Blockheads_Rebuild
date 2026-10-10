// Contract test for the recovered World clock/weather domain model.
//
// The Python side re-derives every offset from the pinned binary and compares it with the header; this
// test keeps the layout reasoning (adjacency, widths) executable on the C++ side.
#include "world_clock_domain.h"

#include <cassert>
#include <cstdio>

using namespace blockheads::recovered::world_clock;

int main() {
    assert(kOffsetWorldTime == 648);
    assert(kOffsetSunDirection == 660);
    assert(kOffsetTimeOfDayFraction == 880);
    assert(kOffsetWeatherFraction == 916);
    assert(kOffsetRainFraction == 920);
    assert(kOffsetRainFractionNotIncludingSnow == 924);
    assert(kOffsetFastForward == 934);
    assert(kOffsetDoubleTimeUnlocked == 3072);
    assert(kOffsetSimulationProgress == 3136);
    assert(kOffsetIsSimulating == 3140);

    // the flag sits immediately after the float it belongs to
    assert(kOffsetIsSimulating == kOffsetSimulationProgress + 4);
    // the weather floats are consecutive
    assert(kOffsetRainFraction == kOffsetWeatherFraction + 4);
    assert(kOffsetRainFractionNotIncludingSnow == kOffsetRainFraction + 4);
    // sunDirection is four floats and does not reach the day/night fraction
    assert(kOffsetSunDirection + 16 <= kOffsetTimeOfDayFraction);
    // the wide gap between the sun direction and the day/night fraction is real, not a bad derivation
    assert(kOffsetTimeOfDayFraction - kOffsetSunDirection >= 200);

    std::puts("world-clock-domain: PASS");
    return 0;
}
