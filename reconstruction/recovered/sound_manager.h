#pragma once
#include "world_translation.h"
namespace blockheads::recovered {
class SoundALRuntime {
public:
    virtual ~SoundALRuntime() = default;
    virtual void listener3f(int parameter, float x, float y, float z) = 0;
};
// Logical state, not an Objective-C memory overlay. Borrowed runtime lifetime.
class SoundManager final : public WorldTranslationSound {
public:
    explicit SoundManager(SoundALRuntime& runtime) : runtime_(runtime) {}
    FrameVector2 listenerPosition{}; // original listenerPos ivar, offset 0x50
    void setListenerPositionZoom(FrameVector2 position, float zoom) override;
    FrameVector2 listenerPos() const;
private:
    SoundALRuntime& runtime_;
};
struct SoundSingletonState { SoundManager* instance{}; };
class SoundSingletonRuntime {
public:
    virtual ~SoundSingletonRuntime() = default;
    // Actual MJSoundManager class alloc, not the caller's dynamic class.
    virtual SoundManager* allocateMJSoundManager() = 0;
    // Full init body remains external. May return nil/substitute and mutate slot.
    virtual SoundManager* initWithMasterVolume(SoundManager& allocated, float volume) = 0;
};
SoundManager* soundManagerInstance(SoundSingletonState&, SoundSingletonRuntime&);
class SoundMathRuntime {
public:
    virtual ~SoundMathRuntime() = default;
    virtual float wrapFmodf(float value, float divisor) = 0;
};
// Executable translation->singleton->listener method linkage, not Android audio.
class TranslationSoundBridge final : public WorldTranslationRuntime {
public:
    TranslationSoundBridge(SoundSingletonState& state, SoundSingletonRuntime& singleton,
                           SoundMathRuntime& math) : state_(state), singleton_(singleton), math_(math) {}
    float wrapFmodf(float value, float divisor) override;
    WorldTranslationSound* soundManagerInstance() override;
private:
    SoundSingletonState& state_;
    SoundSingletonRuntime& singleton_;
    SoundMathRuntime& math_;
};
}
