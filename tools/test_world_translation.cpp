// Behavioral checks must execute in Release/CI builds too.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "world_translation.h"
#include <cassert>
#include <cmath>
#include <cstring>
#include <limits>
#include <iostream>
#include <vector>
using namespace blockheads::recovered;
struct Runtime final : WorldTranslationRuntime, WorldTranslationSound {
    WorldTranslationState& s; std::vector<int> calls;
    FrameVector2 heard{}; float zoom{}; bool mutate{}, nil{}, mutateMath{};
    std::vector<float> args;
    explicit Runtime(WorldTranslationState& state):s(state){}
    float wrapFmodf(float x,float d) override {
        calls.push_back(1); args.push_back(x); args.push_back(d);
        if(mutateMath) { s.pinchScale=99; s.accurateTranslation={7,8}; }
        return std::fmod(x,d); // test boundary implementation, not original wrapper oracle
    }
    WorldTranslationSound* soundManagerInstance() override {
        calls.push_back(2);
        if(mutate) { assert(s.roundedTranslation.x==32.5f-std::fmod(32.5f,0.05f)); s.accurateTranslation={123,456}; s.pinchScale=0.125; }
        return nil ? nullptr : this;
    }
    void setListenerPositionZoom(FrameVector2 p,float z) override { calls.push_back(3); heard=p; zoom=z; }
};
#ifdef TRANSLATION_ASSIGNMENT_NEGATIVE_CONTROL
namespace blockheads::recovered {
void worldSetTranslation(WorldTranslationState& s,FrameVector2 p,WorldTranslationRuntime&) {s.accurateTranslation=p;}
}
#endif
static void check(float x,float goal,float expected,float eg) {
    WorldTranslationState s; s.worldWidthMacro=1; s.pinchScale=2; s.translationGoal={goal,77}; Runtime r(s);
    worldSetTranslation(s,{x,1.125f},r);
    assert(s.accurateTranslation.x==expected && s.accurateTranslation.y==1.125f);
    assert(s.translationGoal.x==eg && s.translationGoal.y==77);
    assert(s.roundedTranslation.x==x-std::fmod(x,0.05f));
    assert(s.roundedTranslation.y==1.125f-std::fmod(1.125f,0.05f));
    assert(r.heard.x==expected && r.zoom==2);
    assert((r.calls==std::vector<int>{1,1,2,3}));
}
int main(){
    check(32,32,0,0); check(96,96,64,64); check(-65,-65,-33,-33);
    check(0,-3,0,-3); check(-1,0,31,0); check(33,-2,1,-2);
    check(std::nextafter(32.f,0.f),99,std::nextafter(32.f,0.f),99);
    check(-0.0f,12,-0.0f,12);
    check(std::nextafter(32.f,INFINITY),32,std::nextafter(32.f,INFINITY)-32,0);
    {WorldTranslationState s; s.worldWidthMacro=1; s.pinchScale=1; Runtime r(s);
     worldSetTranslation(s,{-0.0f,-0.0f},r);
     assert(std::signbit(s.accurateTranslation.x) && std::signbit(s.accurateTranslation.y));
     assert(std::signbit(r.heard.x) && std::signbit(r.heard.y));}
    {WorldTranslationState s; s.worldWidthMacro=1; s.pinchScale=1; Runtime r(s);
     s.translationGoal={NAN,77}; worldSetTranslation(s,{33,2},r);
     assert(s.accurateTranslation.x==1 && std::isnan(s.translationGoal.x));
     worldSetTranslation(s,{-1,2},r);
     assert(s.accurateTranslation.x==31 && std::isnan(s.translationGoal.x));}
    {WorldTranslationState s; s.worldWidthMacro=1; s.pinchScale=INFINITY; Runtime r(s);
     worldSetTranslation(s,{1,2},r);
     assert(std::isinf(r.args[1]) && std::isinf(r.zoom));
     assert(s.roundedTranslation.x==0 && s.roundedTranslation.y==0);}
    {WorldTranslationState s; s.worldWidthMacro=1; s.pinchScale=2; Runtime r(s);r.mutate=true;
     worldSetTranslation(s,{32.5f,0},r);assert(r.heard.x==123 && r.heard.y==456 && r.zoom==0.125f);}
    {WorldTranslationState s; s.worldWidthMacro=1; s.pinchScale=0.25; Runtime r(s);r.nil=true;
     worldSetTranslation(s,{1,2},r);assert(r.args[1]==0.025f && r.args[3]==0.025f);assert(r.calls.back()==2);}
    {WorldTranslationState s; s.worldWidthMacro=1; s.pinchScale=2; Runtime r(s);r.mutateMath=true;
     worldSetTranslation(s,{1,2},r);assert(r.args[1]==0.05f && r.args[3]==0.05f);assert(r.heard.x==7 && r.zoom==99);}
    {WorldTranslationState s; s.worldWidthMacro=0x08000000; s.pinchScale=1; Runtime r(s);
     worldSetTranslation(s,{1,2},r);assert(s.accurateTranslation.x==1);}
    {WorldTranslationState s; s.worldWidthMacro=0x04000000; s.pinchScale=1; Runtime r(s);
     worldSetTranslation(s,{0,2},r);assert(s.accurateTranslation.x==2147483648.f);}
    {WorldTranslationState s; s.worldWidthMacro=1; s.pinchScale=std::numeric_limits<double>::quiet_NaN();Runtime r(s);
     worldSetTranslation(s,{std::numeric_limits<float>::quiet_NaN(),0},r);
     assert(std::isnan(s.accurateTranslation.x)&&std::isnan(r.args[1])&&std::isnan(r.zoom));}
    {WorldTranslationState s; s.worldWidthMacro=1; s.pinchScale=-INFINITY;Runtime r(s);
     worldSetTranslation(s,{INFINITY,-0.0f},r);assert(std::isinf(s.accurateTranslation.x));assert(r.args[1]==0.025f);assert(std::isnan(s.roundedTranslation.x));}
    std::cout<<"PASS: World.setTranslation wrap/goal/quantization/order/reread/NaN/ARM shift contracts\n";
}
