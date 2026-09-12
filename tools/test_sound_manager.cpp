#ifdef NDEBUG
#undef NDEBUG
#endif
#include "sound_manager.h"
#include <cassert>
#include <cmath>
#include <cstring>
#include <iostream>
#include <vector>
using namespace blockheads::recovered;
struct Runtime final : SoundALRuntime, SoundSingletonRuntime, SoundMathRuntime {
    std::vector<int> calls;
    SoundSingletonState slot;
    SoundManager allocated{*this}, substitute{*this};
    bool nilAlloc{}, nilInit{}, useSubstitute{}, mutateAL{};
    int param{}; FrameVector2 heard{}; float z{};
    SoundManager* allocateMJSoundManager() override {
        calls.push_back(1);
        // Callback mutation must not short-circuit the ensuing init/store.
        slot.instance=&substitute;
        return nilAlloc ? nullptr : &allocated;
    }
    SoundManager* initWithMasterVolume(SoundManager& p,float v) override {
        calls.push_back(2); assert(&p==&allocated && v==1.0f);
        return nilInit ? nullptr : useSubstitute ? &substitute : &allocated;
    }
    void listener3f(int p,float x,float y,float value) override {
        calls.push_back(3); param=p; heard={x,y}; z=value;
        assert(std::memcmp(&allocated.listenerPosition,&heard,sizeof(heard))==0);
        if(mutateAL) allocated.listenerPosition={99,100};
    }
    float wrapFmodf(float a,float b) override {calls.push_back(4); return std::fmod(a,b);}
};
#ifdef SOUND_ASSIGNMENT_NEGATIVE_CONTROL
namespace blockheads::recovered {
void SoundManager::setListenerPositionZoom(FrameVector2 p,float) {listenerPosition=p;}
FrameVector2 SoundManager::listenerPos() const {return listenerPosition;}
SoundManager* soundManagerInstance(SoundSingletonState& s,SoundSingletonRuntime&) {return s.instance;}
float TranslationSoundBridge::wrapFmodf(float v,float d) {return math_.wrapFmodf(v,d);}
WorldTranslationSound* TranslationSoundBridge::soundManagerInstance() {return recovered::soundManagerInstance(state_,singleton_);}
}
#endif
int main() {
    {Runtime r; auto* p=soundManagerInstance(r.slot,r);
     assert(p==&r.allocated && r.slot.instance==p);
     assert((r.calls==std::vector<int>{1,2}));
     assert(soundManagerInstance(r.slot,r)==p && r.calls.size()==2);}
    {Runtime r; r.useSubstitute=true;
     assert(soundManagerInstance(r.slot,r)==&r.substitute);}
    {Runtime r; r.nilAlloc=true;
     assert(soundManagerInstance(r.slot,r)==nullptr && r.slot.instance==nullptr);
     assert((r.calls==std::vector<int>{1}));
     soundManagerInstance(r.slot,r); assert(r.calls.size()==2);}
    {Runtime r; r.nilInit=true;
     assert(soundManagerInstance(r.slot,r)==nullptr && r.slot.instance==nullptr);
     soundManagerInstance(r.slot,r); assert((r.calls==std::vector<int>{1,2,1,2}));}
    {Runtime r; r.allocated.setListenerPositionZoom({1.25f,-2.5f},0.25f);
     assert(r.param==0x1004 && r.heard.x==1.25f && r.heard.y==-2.5f && r.z==5.0f);
     assert(r.allocated.listenerPos().x==1.25f && r.calls==std::vector<int>{3});}
    {Runtime r; const unsigned bits[2]={0x80000000u,0x7fc01234u}; FrameVector2 p;
     static_assert(sizeof(p)==sizeof(bits)); std::memcpy(&p,bits,sizeof(p));
     r.allocated.setListenerPositionZoom(p,-0.0f); auto q=r.allocated.listenerPos();
     assert(std::memcmp(&p,&q,sizeof(p))==0 && std::signbit(r.heard.x) && std::signbit(r.z));
     r.allocated.setListenerPositionZoom({0,0},INFINITY); assert(std::isinf(r.z));
     r.allocated.setListenerPositionZoom({0,0},NAN); assert(std::isnan(r.z));}
    {Runtime r; r.mutateAL=true; r.allocated.setListenerPositionZoom({2,3},2);
     assert(r.allocated.listenerPosition.x==99 && r.heard.x==2 && r.z==40);}
    {Runtime r; TranslationSoundBridge bridge(r.slot,r,r); WorldTranslationState world;
     world.worldWidthMacro=1; world.pinchScale=2;
     worldSetTranslation(world,{33,4},bridge);
     assert((r.calls==std::vector<int>{4,4,1,2,3}));
     assert(r.heard.x==1 && r.heard.y==4 && r.z==40);
     assert(r.allocated.listenerPos().x==world.accurateTranslation.x);}
    std::cout<<"PASS sound_manager: singleton/nil/substitution/listener/translation bridge\n";
}
