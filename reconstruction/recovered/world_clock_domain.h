// Recovered model: the World clock / weather / scalar domain.
//
// Every offset and cell below is DERIVED from the original's own literal pool (slot = wA + PIC base,
// cell = *(slot), offset = *(cell)) and cross-checked against `OBJC_IVAR_$_World.<name>`; the artifacts
// to read alongside this are CLOCK_DOMAIN_LAYOUT.md, LIVE_WORLD_CLOCK.md, FLOAT_GETTER_EMULATION.md and
// STRUCT_GETTER_EMULATION.md. The Python contract test re-derives all of it from the pinned library and
// compares it with this header, so the replacement and the evidence cannot drift apart.
//
// What was EXECUTED rather than inferred: worldTime, fastForward, doubleTimeUnlocked, isSimulating and
// needsRemoved run under an emulator with planted values and cell-rewrite negative controls; the four
// weather floats and simulationProgress likewise (intercepting the load that addresses the field);
// translation, highestPoint and sunDirection as struct returns.
//
// Two writer facts, both of which constrain the model more than the offsets do:
//   * `translation` (624) has exactly ONE write site in the whole binary: World -[setTranslation:] at
//     0x553204. The pinch/pan update reaches it by sending that selector - verified by trace - which is
//     why the update body itself writes the field zero times.
//   * resetPauseIdleTimer stores the constant 0.0f into offset 3264 (read out of its literal pool; the
//     store itself cannot be executed because its `vldr` is VFP, which the emulator rejects).
#pragma once

#include <cstddef>
#include <cstdint>

namespace blockheads::recovered::world_clock {

inline constexpr std::size_t kOffsetWorldTime = 648;  // double, 8 bytes
inline constexpr std::size_t kOffsetSunDirection = 660;  // struct4f, 16 bytes
inline constexpr std::size_t kOffsetTimeOfDayFraction = 880;  // float, 4 bytes
inline constexpr std::size_t kOffsetWeatherFraction = 916;  // float, 4 bytes
inline constexpr std::size_t kOffsetRainFraction = 920;  // float, 4 bytes
inline constexpr std::size_t kOffsetRainFractionNotIncludingSnow = 924;  // float, 4 bytes
inline constexpr std::size_t kOffsetFastForward = 934;  // char, 1 bytes
inline constexpr std::size_t kOffsetDoubleTimeUnlocked = 3072;  // char, 1 bytes
inline constexpr std::size_t kOffsetSimulationProgress = 3136;  // float, 4 bytes
inline constexpr std::size_t kOffsetIsSimulating = 3140;  // char, 1 bytes

// runtime ivar cells, useful when comparing against the binary
inline constexpr std::uint32_t kCellWorldTime = 0xf328f4;
inline constexpr std::uint32_t kCellSunDirection = 0xf32b6c;
inline constexpr std::uint32_t kCellTimeOfDayFraction = 0xf32b78;
inline constexpr std::uint32_t kCellWeatherFraction = 0xf32b7c;
inline constexpr std::uint32_t kCellRainFraction = 0xf32b80;
inline constexpr std::uint32_t kCellRainFractionNotIncludingSnow = 0xf32b84;
inline constexpr std::uint32_t kCellFastForward = 0xf32930;
inline constexpr std::uint32_t kCellDoubleTimeUnlocked = 0xf32a98;
inline constexpr std::uint32_t kCellSimulationProgress = 0xf32b0c;
inline constexpr std::uint32_t kCellIsSimulating = 0xf32afc;

static_assert(kOffsetWorldTime == 648);
static_assert(kOffsetFastForward == 934);

}  // namespace blockheads::recovered::world_clock
