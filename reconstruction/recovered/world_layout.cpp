#include "world_layout.h"

// The layout table is data; these asserts keep the two properties a reader relies on: it is sorted, and
// the entries the clock model also names resolve to the same offsets. A World layout that disagreed with
// world_clock_domain.h would be a genuine contradiction rather than a typo, so it is checked here.
namespace blockheads::recovered::world_layout {
namespace {

constexpr std::size_t offsetOf(std::string_view want) {
    for (const Field& f : kWorldFields)
        if (f.name == want) return f.offset;
    return static_cast<std::size_t>(-1);
}

static_assert(offsetOf("worldTime") == 648);
static_assert(offsetOf("fastForward") == 934);
static_assert(offsetOf("timeOfDayFraction") == 880);
static_assert(offsetOf("sunDirection") == 660);
static_assert(offsetOf("isSimulating") == 3140);

}  // namespace
}  // namespace blockheads::recovered::world_layout
