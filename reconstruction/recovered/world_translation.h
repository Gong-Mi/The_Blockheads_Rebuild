#pragma once
#include "world_view_contracts.h"
namespace blockheads::recovered {
// Logical field extension; not an ARM ObjC memory-layout overlay.
struct WorldTranslationState : WorldViewContractsState {
    FrameVector2 translationGoal{}, roundedTranslation{};
    double pinchScale{};
};
class WorldTranslationSound {
public:
    virtual ~WorldTranslationSound() = default;
    virtual void setListenerPositionZoom(FrameVector2 position, float zoom) = 0;
};
class WorldTranslationRuntime {
public:
    virtual ~WorldTranslationRuntime() = default;
    // Imported __wrap_fmodf: two float bit patterns in r0/r1, float in r0.
    // No assumed implementation of the external Apportable math wrapper.
    virtual float wrapFmodf(float value, float divisor) = 0;
    // [MJSoundManager instance], may mutate state or return nil.
    virtual WorldTranslationSound* soundManagerInstance() = 0;
};
void worldSetTranslation(WorldTranslationState&, FrameVector2, WorldTranslationRuntime&);
}
