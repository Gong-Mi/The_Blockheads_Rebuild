#include "pinch_inertia.h"
#include <iostream>
#include <cstdlib>
using namespace blockheads::recovered;
void check(bool ok,const char* s) { if(!ok) {std::cerr<<"FAIL: "<<s<<'\n';std::exit(1);} }
int main() {
    PinchInertiaState s{false,true,4.0f,1.9375f,1.0f,3.0};
    auto r=stepPinchInertia(s,false,false,0.03125f);
    check(r.notifyScaleChanged && r.state.pinchVelocity==2.0f && r.state.lastPinchFactor==2.0f && r.state.pinchScale==0.5,"decay factor then ratio");
    r=stepPinchInertia(s,true,false,0.03125f);
    check(!r.state.hasPinchVelocity && r.state.pinchVelocity==4 && !r.notifyScaleChanged,"goal cancellation before decay");
    s.pinchZooming=true;
    r=stepPinchInertia(s,true,false,0.03125f);
    check(r.state.hasPinchVelocity && !r.notifyScaleChanged,"return-to-one branch has priority");
    s.pinchZooming=false;s.hasPinchVelocity=false;
    check(!stepPinchInertia(s,false,false,0).notifyScaleChanged,"inactive");
    s.hasPinchVelocity=true;
    r=stepPinchInertia(s,false,false,0.0625f);
    check(!r.state.hasPinchVelocity && r.state.pinchVelocity==0 && r.state.lastPinchFactor==s.lastPinchFactor,"stop before factor update");
    s.lastPinchFactor=8;
    r=stepPinchInertia(s,false,false,0);
    check(r.state.pinchScale==0.5 && r.notifyScaleChanged,"normal lower bound");
    r=stepPinchInertia(s,false,true,0);
    check(r.state.pinchScale==0.125 && r.notifyScaleChanged,"photo lower bound");
    s.lastPinchFactor=0.005f;
    r=stepPinchInertia(s,false,false,0);
    check(!r.state.hasPinchVelocity && r.state.pinchScale==3 && !r.notifyScaleChanged,"factor threshold prevents division");
    s.lastPinchFactor=1;s.pinchStartScale=64;
    r=stepPinchInertia(s,false,false,0);
    check(r.state.pinchScale==64,"no upper clamp in this slice");
    std::cout<<"pinch-inertia: PASS\n";
}
