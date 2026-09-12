#pragma once
#include <cstdint>
#include <string_view>
namespace blockheads::recovered {
struct FrameVector2 { float x{}, y{}; };
class FrameWorld {
public:
    virtual ~FrameWorld() = default;
    virtual bool loadComplete() = 0;
    virtual bool isSimulating() = 0;
    virtual bool translatingToGoal() = 0;
    virtual bool takingPhoto() = 0;
    virtual FrameVector2 translation() = 0;
    virtual void setTranslation(FrameVector2 value) = 0;
    virtual std::int32_t worldWidthMacro() = 0;
    virtual void update(float dt, float accurateDT, double pinchScale, bool dragInProgress) = 0;
};
class FrameDefaults {
public:
    virtual ~FrameDefaults() = default;
    virtual void setFloat(float value, std::string_view key) = 0;
    virtual void setDouble(double value, std::string_view key) = 0;
};
// Typed recovered state, NOT the ARMv7 Objective-C memory layout or save format.
// Pointers are borrowed. Adapters/callbacks must keep captured objects alive.
struct GameViewState {
    FrameWorld* world{};
    bool hasRenderedFrameSinceActivate{};
    float timeCounter{};
    double totalGamePlayTimePassed{};
    bool scrolling{}, pinching{}, hasVelocity{}, pinchZooming{}, hasPinchVelocity{};
    FrameVector2 scrollVelocity{};
    double pinchScale{1.0};
    float pinchVelocity{}, lastPinchFactor{1.0f}, pinchStartScale{1.0f};
    bool isZoomingCameraOut{};
    float windowInfo[4]{}; // original inline float lanes, not guessed dimensions
    float projectionMatrix[16]{};
    float cameraZ{};
};
class FrameRuntime {
public:
    virtual ~FrameRuntime() = default;
    virtual FrameDefaults* standardUserDefaults() = 0;
    // Default executes recovered projection/camera math. Overrides model ObjC
    // dispatch and may synchronously mutate state; caller reloads after return.
    virtual void pinchScaleChanged(GameViewState& state);
    virtual float fmodFloat(float value, float divisor);
};
// Single-threaded logical method reconstruction. External effects are real
// interface calls, not precomputed snapshots. This is not yet a game adapter.
void updateGameView(GameViewState& state, FrameRuntime& runtime, float dt, float accurateDT);
}
