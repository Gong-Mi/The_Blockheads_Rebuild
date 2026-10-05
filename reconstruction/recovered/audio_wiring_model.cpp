#include "audio_wiring_model.h"

namespace blockheads::recovered::audio {
namespace {
static_assert(!kAudioWiring.empty());
static_assert(!kNotYetReferenced.empty());
static_assert(kAudioWiring.size() == 275);
static_assert(kNotYetReferenced.size() == 94);
}  // namespace
}  // namespace blockheads::recovered::audio
