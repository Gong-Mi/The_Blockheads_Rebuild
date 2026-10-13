// The day phase, as measured on the running original.
//
// This replaces a sawtooth. The replacement used to compute the day fraction as
// fmod(worldSeconds, 900) / 900 - the "naive" 900-units-per-day reading - and the live measurement says that is
// the wrong WAVEFORM: the period is right (900 world units, which also matches the constant in the original's
// -[World getDayNightFractionForX:atWorldTime:]), but the phase is a SINUSOID, not a ramp.
//
// The evidence, all of it live and read-only from the running 1.7.5 original (build hash pinned at
// d09418e9c0865902054a71358dcff3264d47f7b24ede58667cb5ea0e6f269b96):
//
//   * 100 samples over 2943 worldTime units (three full cycles) at 3 s intervals
//   * period from peak-to-peak flag flips: 948.4 and 900.7 units, mean 924.5 - and a scan over 600..1200 units
//     puts the best fit at 895, within 0.6% of the static 900
//   * waveform: a sinusoid, worst residual 0.0367, against 0.2627 for a triangle of the same period
//   * amplitude 0.2198, offset 0.2458 - so the phase swings roughly 0.03..0.47 and never reaches 0 or 1
//   * the direction flag the original exposes flips exactly at the turning points, so it is the sign of this
//     derivative rather than a stored value
//
// The constants are the FIT, not roundings of a guess, and tools/test_day_phase.py replays the committed 100-sample
// fixture against this file: it fails if the implementation and the measurement diverge, and it separately checks
// the direction flag, which the fit knows nothing about. A wrong sign was caught that way during development - the
// first version dropped the minus the fit returned and came out anti-phase (worst residual 0.4677, 97 of 100 flags
// wrong).
//
// Where must it NOT be used: this is the day phase, not the clock. The world clock itself advances 20 units per
// real second while fastForward is set (a separate measured fact), and worldSeconds remains the source of truth
// for "how much world time has passed". This file answers only "what fraction of the day is it".
#pragma once

#include <cmath>

namespace blockheads {

// 900 world units per day: the static analysis read this constant in the original's day-night fraction function,
// and the live fit agrees with it to 0.6%.
inline constexpr double kWorldUnitsPerDay = 900.0;

namespace day_phase_fit {
// the fitted sinusoid, in the same units as the original's timeOfDayFraction
inline constexpr double kPeriod = 895.0;
inline constexpr double kAmplitude = 0.2198;
inline constexpr double kOffset = 0.2458;
inline constexpr double kReferenceWorldTime = 502829.7;
inline constexpr double kShift = 4.3197;  // radians; the fitted "-0.2198 * sin(...)" folded into the phase so the
                                          // amplitude stays positive and the derivative's sign means what it says
inline constexpr double kTwoPi = 6.283185307179586;

constexpr double turns(double world_seconds) {
    return (world_seconds - kReferenceWorldTime) / kPeriod + kShift / kTwoPi;
}
}  // namespace day_phase_fit

// the day fraction the original reports as World.timeOfDayFraction
inline double dayPhaseFraction(double world_seconds) {
    return day_phase_fit::kOffset
           + day_phase_fit::kAmplitude * std::sin(day_phase_fit::kTwoPi * day_phase_fit::turns(world_seconds));
}

// true while the day phase is rising towards its peak - the original's isHeadingTowardsMIdday, which a live probe
// showed flipping exactly at the turning points
inline bool isHeadingTowardsMidday(double world_seconds) {
    return std::cos(day_phase_fit::kTwoPi * day_phase_fit::turns(world_seconds)) > 0.0;
}

}  // namespace blockheads
