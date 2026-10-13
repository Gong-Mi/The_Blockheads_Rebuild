#include "world_clock_domain.h"

// Layout sanity for the clock/weather domain. These hold the reasoning that the offsets alone cannot:
// which fields are adjacent, and which gaps are real gaps rather than mis-derived offsets.
namespace blockheads::recovered::world_clock {
namespace {

// the four weather floats are consecutive - 916, 920, 924 - with rainFraction and
// rainFractionNotIncludingSnow adjacent, which is why they are one byte apart in the ivar table's order
static_assert(kOffsetRainFraction == kOffsetWeatherFraction + 4);
static_assert(kOffsetRainFractionNotIncludingSnow == kOffsetRainFraction + 4);

// simulationProgress is a float and isSimulating is the one-byte flag right after it
static_assert(kOffsetIsSimulating == kOffsetSimulationProgress + 4);

// sunDirection is a 16-byte struct (four floats) and does NOT touch timeOfDayFraction at 880
static_assert(kOffsetSunDirection + 16 <= kOffsetTimeOfDayFraction);

// the clock itself is a double (8 bytes) and fastForward sits 286 bytes further on; the gap is real and
// is not asserted as a magic number - only the ordering that matters is.
static_assert(kOffsetFastForward > kOffsetSunDirection + 16);
static_assert(kOffsetFastForward - kOffsetWorldTime == 286);

}  // namespace
}  // namespace blockheads::recovered::world_clock
