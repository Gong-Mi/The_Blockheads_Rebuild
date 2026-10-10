#include "particle_pool_slots.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the particle-pool-slots family.
namespace blockheads::recovered {
namespace {

static_assert(kParticlePoolCapacity == 2048);
static_assert(kParticleEffectArrayWords == 16384);
static_assert(kParticleRecordStride == 104);
static_assert(kParticleFreeSlotSentinel == 0x7fffffff);

}  // namespace
}  // namespace blockheads::recovered
