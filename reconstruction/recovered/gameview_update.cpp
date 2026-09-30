#include "gameview_update.h"
#include "pinch_return.h"
#include "translation_return.h"
#include "zoom_settle.h"
#include "projection_update.h"
#include <algorithm>
#include <cmath>
#include <cstring>
namespace blockheads::recovered {
void FrameRuntime::pinchScaleChanged(GameViewState& state) {
    const auto p = buildProjection({state.pinchScale, state.windowInfo[0], state.windowInfo[1]});
    std::copy(p.matrix, p.matrix + 16, state.projectionMatrix);
    state.cameraZ = p.cameraZ;
}
float FrameRuntime::fmodFloat(float value, float divisor) { return std::fmod(value, divisor); }
namespace {
FrameVector2 translation(FrameWorld* world) {
    return world ? world->translation() : FrameVector2{}; // original nil stret memset
}
std::int32_t widthMacro(FrameWorld* world) { return world ? world->worldWidthMacro() : 0; }
float widthTiles(std::int32_t macro) {
    // ARM LSL truncates to32 bits, then VCVT interprets those bits as signed.
    const std::uint32_t bits = static_cast<std::uint32_t>(macro) << 5;
    std::int32_t signedBits;
    std::memcpy(&signedBits, &bits, sizeof(bits));
    return static_cast<float>(signedBits);
}
bool goal(FrameWorld* world) { return world && world->translatingToGoal(); }
bool photo(FrameWorld* world) { return world && world->takingPhoto(); }
void saveScale(GameViewState& state, FrameRuntime& runtime) {
    auto* defaults = runtime.standardUserDefaults();
    // The provider may change pinchScale. Do NOT persist a cached snap target.
    const float value = static_cast<float>(state.pinchScale);
    if (defaults) defaults->setFloat(value, "pinchScale");
}
void scroll(GameViewState& state, float dt) {
    if (!state.hasVelocity) return;
    if (goal(state.world)) { state.hasVelocity=false; return; }
    // No hasVelocity re-check after the external goal query.
    const float scaledDt = dt * 4.0f;
    const float factor = static_cast<float>(1.0 - static_cast<double>(scaledDt));
    state.scrollVelocity.x = state.scrollVelocity.x * factor;
    state.scrollVelocity.y = state.scrollVelocity.y * factor;
    const float x2 = state.scrollVelocity.x * state.scrollVelocity.x;
    const float y2 = state.scrollVelocity.y * state.scrollVelocity.y;
    if (x2 + y2 < 0.1f) { state.hasVelocity=false; return; }
    auto* const setterReceiver = state.world; // fp-0xf8 BEFORE getter0x925e7c
    const auto t = translation(state.world);
    // Getter may change velocity/world. Velocity is reloaded, setter receiver isn't.
    const float dx = state.scrollVelocity.x * dt;
    const float dy = state.scrollVelocity.y * dt;
    if (setterReceiver) setterReceiver->setTranslation({t.x-dx, t.y-dy});
    const auto first = translation(state.world); //0x925f68
    if (first.x < 0.0f) {
        const float width = widthTiles(widthMacro(state.world)); //0x926000
        auto local = translation(state.world); //0x926058, after width query
        local.x = local.x + width;
        (void)local; // original modifies only a local stret buffer; NO setter
    } else {
        const auto second = translation(state.world); //0x9260e4, cannot reuse first
        const float width = widthTiles(widthMacro(state.world)); //0x926150
        if (second.x >= width) { // BLT skips unordered as well as less-than
            const float secondWidth = widthTiles(widthMacro(state.world)); //0x9261d0
            auto local = translation(state.world); //0x926228
            local.x = local.x - secondWidth;
            (void)local; // no invented wrap writeback
        }
    }
}
void pinch(GameViewState& state, FrameRuntime& runtime, float dt) {
    if (state.pinchZooming) {
        const auto r = stepPinchReturn({true,state.pinchScale},dt);
        state.pinchScale = r.state.pinchScale;
        if (r.persistScale) {
            state.pinchZooming=false;
            saveScale(state,runtime);
        }
        return; // consumed even when defaults callbacks change flags
    }
    if (!state.hasPinchVelocity) return;
    if (goal(state.world)) { state.hasPinchVelocity=false; return; }
    const float step = dt * 16.0f;
    const double factor = 1.0 - static_cast<double>(step);
    state.pinchVelocity = static_cast<float>(static_cast<double>(state.pinchVelocity) * factor);
    if (std::fabs(state.pinchVelocity) < 0.01f) { state.hasPinchVelocity=false; return; }
    const float movement = state.pinchVelocity * dt;
    state.lastPinchFactor = state.lastPinchFactor + movement;
    if (state.lastPinchFactor < 0.01f) { state.hasPinchVelocity=false; return; }
    const float quotient = state.pinchStartScale / state.lastPinchFactor;
    const double ratio = static_cast<double>(quotient);
    state.pinchScale = ratio; // visible BEFORE takingPhoto0x926624
    const double minimum = photo(state.world) ? 0.125 : 0.5;
    // fp-0x78 preserves the ratio across the query. A query's scale write loses.
    state.pinchScale = ratio < minimum ? minimum : ratio;
    runtime.pinchScaleChanged(state);
}
void returnTranslation(GameViewState& state, float dt) {
    if (goal(state.world)) return;
    const auto t = translation(state.world); // getter may mutate scale/window/world
    const auto r = stepTranslationReturn({t.x,t.y,state.windowInfo[3],state.pinchScale,
                                         dt,false,false,false});
    // Do not re-check scrolling/pinching/goal; this path was already selected.
    if (state.world) state.world->setTranslation({r.x,r.y}); // RELOADED receiver0x926a44
}
void settle(GameViewState& state, FrameRuntime& runtime, float dt, float maxScale) {
    if (state.isZoomingCameraOut) {
        const double zeroStep = static_cast<double>(dt) * 0.0;
        const double amount = zeroStep * state.pinchScale;
        state.pinchScale = state.pinchScale + amount;
        return;
    }
    if (state.pinching) return;
    if (photo(state.world)) return;
    if (state.pinchZooming) return; // reloaded AFTER query, unlike earlier two gates
    // Reuse only the callback-free numerical phase. All already-selected gates
    // and snapshot tail are disabled explicitly; effects execute below in order.
    const auto r = stepZoomSettle({state.pinchScale,state.pinchStartScale,
        state.lastPinchFactor,maxScale,dt,false,false,false,false,false});
    if (r.writeScale) state.pinchScale=r.pinchScale;
    if (r.persistScale) saveScale(state,runtime);
    if (r.notifyScaleChanged) runtime.pinchScaleChanged(state);
    // Original reloads ALL these fields after external callbacks.
    if (state.hasPinchVelocity) {
        state.pinchStartScale = static_cast<float>(static_cast<double>(state.lastPinchFactor)
                                                  * state.pinchScale);
    }
}
}
void updateGameView(GameViewState& state, FrameRuntime& runtime, float dt, float accurateDT) {
    if (!state.hasRenderedFrameSinceActivate) return;
    state.timeCounter = state.timeCounter + accurateDT;
    if (state.timeCounter > 10.0f) { // one increment, not a catch-up loop
        state.totalGamePlayTimePassed = state.totalGamePlayTimePassed + 10.0;
        auto* defaults = runtime.standardUserDefaults();
        const double currentTotal = state.totalGamePlayTimePassed;
        if (defaults) defaults->setDouble(currentTotal,"totalGamePlayTimePassed");
        state.timeCounter = state.timeCounter - 10.0f; // reload after setDouble
        (void)runtime.fmodFloat(static_cast<float>(state.totalGamePlayTimePassed),3600.0f);
        // fmod-result and matchMakerIsAddingToGame comparisons converge with no
        // additional field changes or control effects in the original method.
    }
    if (!state.world || !state.world->loadComplete()) return;
    const bool simulating = state.world && state.world->isSimulating();
    if (!simulating) {
        // Branch selection is made ONCE. Internal callbacks changing these flags
        // do not retroactively skip pinch or vertical return in this block.
        if (!state.scrolling && !state.pinching) {
            scroll(state,dt);
            pinch(state,runtime,dt);
            returnTranslation(state,dt);
        }
        const float maxScale = 40960.0f / state.windowInfo[1];
        if (state.pinchScale > static_cast<double>(maxScale)) state.pinchScale=maxScale;
        settle(state,runtime,dt,maxScale);
    }
    // World pointer and arguments are fresh after all effects, or after isSimulating.
    auto* const world = state.world;
    const double scale = state.pinchScale;
    const bool drag = state.scrolling || state.pinching;
    if (world) world->update(dt,accurateDT,scale,drag);
}
}
