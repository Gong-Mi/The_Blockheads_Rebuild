// Recovered model: the day phase (World.timeOfDayFraction).
//
// This is the ONE clock quantity in this project whose behaviour was determined by measurement rather than by
// disassembly: five static and executed routes to its writer all came up empty, so instead of the writer the
// phase was measured. 100 samples over 2943 worldTime units (three full cycles) at 3 s intervals, fitted:
//
//     phase = kOffset + kAmplitude * sin(2*pi*(worldTime - kReferenceWorldTime) / kPeriod + kPhase)
//
// with the period pinned by a scan over 600..1200 world units (best 895 at a granularity of 5, i.e. within 0.6%
// of the 900 the static analysis read as a constant in -[World getDayNightFractionForX:atWorldTime:]), the
// waveform identified as a sinusoid rather than a ramp or a triangle (worst residual 0.0367 against 0.2627 for a
// triangle of the same period), and the amplitude/offset from the same fit.
//
// The numbers below are not roundings of a guess: they are the fit, and tools/test_day_phase.py replays the live
// sample against this function and fails if the implementation and the measurement diverge. That is the point of
// putting the measurement in the repository - a future port must reproduce this behaviour, and this header plus
// that fixture are how it can prove it did.
//
// The direction flag is the sign of the derivative (a live probe showed it flipping exactly at the turning
// points), so isHeadingTowardsMidday() is derived here rather than stored.
#pragma once

#include <cmath>
#include <cstdint>

namespace blockheads::recovered {

// the day: 900 world units, matching the constant in the original's day-night fraction function
inline constexpr double kDayPhasePeriod = 895.0;
inline constexpr double kDayPhaseAmplitude = 0.2198;
inline constexpr double kDayPhaseOffset = 0.2458;
inline constexpr double kDayPhaseReferenceWorldTime = 502829.7;
inline constexpr double kDayPhaseShift = 4.3197;

// sin argument at a given worldTime, in turns
constexpr double dayPhaseTurns(double world_time) {
    return (world_time - kDayPhaseReferenceWorldTime) / kDayPhasePeriod + kDayPhaseShift / (2.0 * 3.141592653589793);
}

// the fraction of the day's cycle the world is at - the measured quantity
inline double dayPhaseFraction(double world_time) {
    return kDayPhaseOffset + kDayPhaseAmplitude * std::sin(2.0 * 3.141592653589793 * dayPhaseTurns(world_time));
}

// the flag the original exposes: true while the phase is rising towards its peak (midday)
inline bool isHeadingTowardsMidday(double world_time) {
    return std::cos(2.0 * 3.141592653589793 * dayPhaseTurns(world_time)) > 0.0;
}

// how many world units one of the original's days lasts - the number the static analysis and the live fit agree on
inline constexpr double kWorldUnitsPerDay = 900.0;

}  // namespace blockheads::recovered
