#include "accessor_triplets.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the typed-accessor triplet dispatcher family.
namespace blockheads::recovered {
namespace {

static_assert(sizeof(kTriplets) / sizeof(kTriplets[0]) == 12);

// Spot static checks: the pinned remove-cell table.
static_assert(tripletForType(0x11)->removeCell == 0x00ffe23564);  // torch
static_assert(tripletForType(0x13)->removeCell == 0x00ffe23628);  // ladder
static_assert(tripletForType(0x1e)->removeCell == 0x00ffe23618);  // egg
static_assert(tripletForType(0x1f)->removeCell == 0x00ffe2364c);  // window
static_assert(tripletForType(0x28)->removeCell == 0x00ffe23648);  // rail
static_assert(tripletForType(0x34)->removeCell == 0x00ffe23558);  // painting
static_assert(tripletForType(0x35)->removeCell == 0x00ffe2355c);  // column
static_assert(tripletForType(0x36)->removeCell == 0x00ffe23560);  // stairs
static_assert(tripletForType(0x37)->removeCell == 0x00ffe23640);  // motor
static_assert(tripletForType(0x38)->removeCell == 0x00ffe2362c);  // shaft
static_assert(tripletForType(0x14)->probesPosThenYMinus1);        // door
static_assert(tripletForType(0x2d)->probesPosThenYMinus1);        // workbench

}  // namespace
}  // namespace blockheads::recovered
