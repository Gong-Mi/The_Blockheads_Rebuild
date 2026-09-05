#include "gameview_input.h"
#include <cmath>
namespace blockheads::recovered {
void pinchZoomToScale(GameViewState& self, float ignoredScale) {
    (void)ignoredScale; // 940f58 spill has no subsequent read.
    self.pinchZooming=true; // 940f68
    self.hasPinchVelocity=false; // 940f78
}
bool shouldAllowDoubleTap(const GameViewState& self) {
    return self.pinchScale > 3.0; // 940fc4 / MOVGT; unordered is false.
}
namespace {
FrameVector2 multiply(FrameVector2 v,float k) {return {v.x*k,v.y*k};}
FrameVector2 divide(FrameVector2 v,float k) {return {v.x/k,v.y/k};}
FrameVector2 subtract(FrameVector2 a,FrameVector2 b) {return {a.x-b.x,a.y-b.y};}
FrameVector2 add(FrameVector2 a,FrameVector2 b) {return {a.x+b.x,a.y+b.y};}
void photoFloor(GameViewState& s) {
    const double saved=s.pinchScale; // fp-128 / fp-152, survives ObjC call
    const bool photo=s.world && s.world->takingPhoto();
    const double minimum=photo ? 0.125 : 0.5;
    s.pinchScale=saved<minimum ? minimum : saved;
}
}
void pinchGesture(GameViewState& s,GameViewInputState& i,GameViewInputRuntime& r,
                  float factor,float velocity,std::int32_t state,
                  FrameVector2 center,std::int32_t numberOfTouches) {
    (void)numberOfTouches; // fp-80 is write-only throughout bounded method.
    s.pinchZooming=false; // 92d240, BEFORE every entry gate
    if (!s.world || !s.world->loadComplete()) return;
    auto* ui=s.world ? r.uiManager(*s.world) : nullptr; // 92d2bc
    if (ui && ui->currentTouchIsInAnyButtons()) return; // 92d2cc
    if (s.world && s.world->isSimulating()) return;
    if (!s.world || !r.allowsPanning(*s.world)) return;
    if (s.world) r.setTranslatingToGoal(*s.world,false); // 92d3c4
    if (state==1) {
        if (!s.scrolling) {
            if (s.world) r.startPinchOrPan(*s.world); // callback before zero store
            i.translationOffset={0.0f,0.0f};
        }
        i.pinchStartOffset=center;
        i.pinchStartOffset.x=i.pinchStartOffset.x-s.windowInfo[2];
        i.pinchStartOffset.y=i.pinchStartOffset.y-s.windowInfo[3];
        i.pinchStartOffset.y=-i.pinchStartOffset.y;
        s.pinchStartScale=static_cast<float>(s.pinchScale);
        s.pinchVelocity=0.0f;
        i.pinchOffset={0.0f,0.0f};
        s.lastPinchFactor=factor;
        s.pinchScale=static_cast<double>(s.pinchStartScale/factor);
        const float cap=40960.0f/s.windowInfo[1];
        if (s.pinchScale>static_cast<double>(cap)) s.pinchScale=cap;
        // Offset uses cap-limited scale BEFORE photo floor, not final scale.
        i.pinchStartOffset=multiply(i.pinchStartOffset,static_cast<float>(s.pinchScale));
        photoFloor(s);
        r.pinchScaleChanged(s);
        s.pinching=true; // callback mutations to this flag are overwritten
        return;
    }
    if (state==2) {
        s.lastPinchFactor=factor;
        s.pinchScale=static_cast<double>(s.pinchStartScale/factor);
        photoFloor(s);
        r.pinchScaleChanged(s); // original notifies BEFORE upper cap!
        const float cap=40960.0f/s.windowInfo[1]; // reload AFTER notification
        // Negated comparisons preserve original BGT/BMI unordered behavior.
        // Invalid velocity leaves old velocity AND old hasPinchVelocity intact.
        if (!(s.pinchScale>static_cast<double>(cap)) && !(s.pinchScale<0.5)
            && !std::isnan(velocity) && velocity>-100.0f && velocity<100.0f
            && std::isfinite(velocity)) {
            s.pinchVelocity=velocity;
            s.hasPinchVelocity=true;
        }
        if (s.pinchScale>static_cast<double>(cap)) {
            s.pinchScale=cap; // retains prior pinchOffset, no second notification
        } else {
            // 4d03c0 divides each lane directly (NOT reciprocal multiplication).
            // 92dc2c/30 immediate bits 0x3ccccccd == float 0.025.
            i.pinchOffset=multiply(subtract(divide(i.pinchStartOffset,factor),
                                           i.pinchStartOffset),0.025f);
            i.pinchOffset=subtract({0.0f,0.0f},i.pinchOffset); // preserve signed zero
        }
        auto offset=i.pinchOffset;
        if (s.scrolling) offset=add(offset,i.translationOffset);
        r.updateTranslation(s,offset); // self dispatch; NOT World.setTranslation
        return;
    }
    if (state==3 || state==4) s.pinching=false;
}
}
