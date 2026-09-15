#include "sound_manager.h"
#include <cstring>
namespace blockheads::recovered {
SoundManager* soundManagerInstance(SoundSingletonState& state, SoundSingletonRuntime& rt) {
    // 0xb88880..88c: plain shared slot, not call_once or thread-safe publication.
    if (!state.instance) {
        auto* allocated = rt.allocateMJSoundManager();
        // ObjC nil init produces nil; init may replace receiver or mutate the slot.
        auto* initialized = allocated ? rt.initWithMasterVolume(*allocated, 1.0f) : nullptr;
        state.instance = initialized; // 0xb88908 overwrites callback slot writes
    }
    return state.instance; // 0xb88918 reload
}
void SoundManager::setListenerPositionZoom(FrameVector2 position, float zoom) {
    // Raw vector copy precedes the AL call; zoom is a by-value float, no clamp.
    std::memcpy(&listenerPosition, &position, sizeof(position));
    const float x = listenerPosition.x;
    const float y = listenerPosition.y;
    const float z = 20.0f * zoom; // 0xb89f28 + 0xb89f34: f32 multiplication
    runtime_.listener3f(0x1004, x, y, z); // AL_POSITION, not a source transform
}
FrameVector2 SoundManager::listenerPos() const {
    FrameVector2 result;
    std::memcpy(&result, &listenerPosition, sizeof(result));
    return result;
}
float TranslationSoundBridge::wrapFmodf(float value, float divisor) {
    return math_.wrapFmodf(value, divisor);
}
WorldTranslationSound* TranslationSoundBridge::soundManagerInstance() {
    return recovered::soundManagerInstance(state_, singleton_);
}
}
