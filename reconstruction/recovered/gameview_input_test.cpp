#include "gameview_input.h"
#include <cassert>
#include <cmath>
#include <functional>
#include <limits>
#include <string>
#include <vector>
#include <iostream>
#ifdef NDEBUG
#error Assertions MUST stay enabled for Release acceptance
#endif
using namespace blockheads::recovered;
struct World final: FrameWorld {
 bool loaded=true, sim=false,photo=false; FrameVector2 t{}; int updates=0;
 std::function<void()> onLoad,onPhoto,onSim;
 bool loadComplete() override {if(onLoad)onLoad();return loaded;}
 bool isSimulating() override {if(onSim)onSim();return sim;}
 bool translatingToGoal() override{return false;}
 bool takingPhoto() override{if(onPhoto)onPhoto();return photo;}
 FrameVector2 translation() override{return t;}
 void setTranslation(FrameVector2 v) override{t=v;}
 std::int32_t worldWidthMacro() override{return 32;}
 void update(float,float,double,bool) override{++updates;}
};
struct Runtime final: GameViewInputRuntime,InputUI {
 std::vector<std::string> events; bool buttons=false,pan=true; FrameVector2 delivered{};
 std::function<void()> onStart,onChanged,onUI,onPan,onGoal,onButtons;
 InputUI* uiManager(FrameWorld&) override{events.push_back("ui");if(onUI)onUI();return this;}
 bool currentTouchIsInAnyButtons() override{events.push_back("buttons");if(onButtons)onButtons();return buttons;}
 bool allowsPanning(FrameWorld&) override{events.push_back("pan");if(onPan)onPan();return pan;}
 void setTranslatingToGoal(FrameWorld&,bool v) override{assert(!v);events.push_back("goal");if(onGoal)onGoal();}
 void startPinchOrPan(FrameWorld&) override{events.push_back("start");if(onStart)onStart();}
 void updateTranslation(GameViewState&,FrameVector2 v) override{events.push_back("translate");delivered=v;}
 FrameDefaults* standardUserDefaults() override{events.push_back("defaults");return nullptr;}
 void pinchScaleChanged(GameViewState& s) override{events.push_back("changed");FrameRuntime::pinchScaleChanged(s);if(onChanged)onChanged();}
};
struct Fixture {GameViewState s; GameViewInputState i;World w;Runtime r;
 Fixture(){s.world=&w;s.windowInfo[0]=800;s.windowInfo[1]=1024;s.windowInfo[2]=10;s.windowInfo[3]=20;s.pinchScale=4;}
 void go(int state=1,float factor=2,float velocity=3,int touches=2){pinchGesture(s,i,r,factor,velocity,state,{110,70},touches);}
};
int main(){
 const float nan=std::numeric_limits<float>::quiet_NaN();const float inf=std::numeric_limits<float>::infinity();
 {Fixture f;f.s.hasPinchVelocity=true;pinchZoomToScale(f.s,nan);assert(f.s.pinchZooming&&!f.s.hasPinchVelocity&&f.s.pinchScale==4);}
 {Fixture f;f.s.pinchScale=3;assert(!shouldAllowDoubleTap(f.s));f.s.pinchScale=std::nextafter(3.0,4.0);assert(shouldAllowDoubleTap(f.s));f.s.pinchScale=nan;assert(!shouldAllowDoubleTap(f.s));f.s.pinchScale=inf;assert(shouldAllowDoubleTap(f.s));}
 for(int gate=0;gate<5;++gate){Fixture f;f.s.pinchZooming=true;f.s.pinching=true;
  if(gate==0)f.s.world=nullptr;if(gate==1)f.w.loaded=false;if(gate==2)f.r.buttons=true;if(gate==3)f.w.sim=true;if(gate==4)f.r.pan=false;
  f.go();assert(!f.s.pinchZooming&&f.s.pinching&&f.s.pinchScale==4);assert(f.r.events.empty()||f.r.events.back()!="goal");}
 {Fixture f;f.s.hasPinchVelocity=true;f.go();assert(f.s.pinching&&f.s.hasPinchVelocity);assert(f.s.pinchStartScale==4&&f.s.lastPinchFactor==2&&f.s.pinchVelocity==0&&f.s.pinchScale==2);assert(f.i.pinchStartOffset.x==200&&f.i.pinchStartOffset.y==-100);assert(f.i.translationOffset.x==0&&f.i.pinchOffset.x==0);assert((f.r.events==std::vector<std::string>{"ui","buttons","pan","goal","start","changed"}));}
 {Fixture f;f.s.scrolling=true;f.i.translationOffset={7,8};f.go();assert(f.i.translationOffset.x==7&&f.r.events.size()==5);}
 {Fixture f;f.r.onStart=[&]{f.s.pinchScale=8;f.s.windowInfo[2]=20;f.i.translationOffset={99,99};};f.r.onChanged=[&]{f.s.pinching=false;};f.go();assert(f.s.pinchStartScale==8&&f.i.translationOffset.x==0&&f.i.pinchStartOffset.x==360&&f.s.pinching);}
 {Fixture f;f.s.pinchScale=0.2;f.go(1,1);assert(f.s.pinchScale==0.5);assert(f.i.pinchStartOffset.x==20);}
 {Fixture f;f.w.photo=true;f.s.pinchScale=0.0625;f.go(1,1);assert(f.s.pinchScale==0.125&&f.i.pinchStartOffset.x==6.25f);}
 {Fixture f;f.s.pinchScale=100;f.go(1,1);assert(f.s.pinchScale==40&&f.i.pinchStartOffset.x==4000);}
 {Fixture f;f.w.onPhoto=[&]{f.s.pinchScale=999;};f.go();assert(f.s.pinchScale==2);}
 {Fixture f;f.go();f.r.events.clear();f.go(2,4,7);assert(f.s.pinchScale==1&&f.s.pinchVelocity==7&&f.s.hasPinchVelocity);assert(f.i.pinchOffset.x==3.75f&&f.i.pinchOffset.y==-1.875f);assert(f.r.delivered.x==3.75f&&f.r.delivered.y==-1.875f);assert(f.r.events.back()=="translate");}
 {Fixture f;f.s.scrolling=true;f.i.translationOffset={7,8};f.i.pinchStartOffset={200,-100};f.s.pinchStartScale=4;f.go(2,4);assert(f.r.delivered.x==10.75f&&f.r.delivered.y==6.125f);}
 for(float v:{-100.0f,100.0f,nan,inf,-inf}){Fixture f;f.s.pinchStartScale=4;f.s.pinchVelocity=19;f.go(2,2,v);assert(!f.s.hasPinchVelocity&&f.s.pinchVelocity==19);}
 for(float v:{-99.0f,0.0f,99.0f}){Fixture f;f.s.pinchStartScale=4;f.go(2,2,v);assert(f.s.hasPinchVelocity&&f.s.pinchVelocity==v);}
 {Fixture f;f.s.hasPinchVelocity=true;f.s.pinchVelocity=19;f.s.pinchStartScale=100;f.i.pinchOffset={9,10};f.go(2,1);assert(f.s.pinchScale==40&&f.s.hasPinchVelocity&&f.s.pinchVelocity==19&&f.r.delivered.x==9);}
 {Fixture f;f.w.photo=true;f.s.pinchStartScale=.2f;f.go(2,1);assert(!f.s.hasPinchVelocity);}
 {Fixture f;f.s.pinchStartScale=4;f.r.onChanged=[&]{f.s.pinchScale=100;f.s.windowInfo[1]=2048;f.i.pinchOffset={9,10};};f.go(2,2);assert(f.s.pinchScale==20&&!f.s.hasPinchVelocity&&f.r.delivered.x==9);}
 for(int st:{0,3,4,5,-1}){Fixture f;f.s.pinching=true;f.s.hasPinchVelocity=true;f.go(st);assert(f.s.pinching==(st!=3&&st!=4));assert(f.s.hasPinchVelocity&&f.s.pinchScale==4);}
 {Fixture a,b;a.go(1,2,3,0);b.go(1,2,3,99);assert(a.s.pinchScale==b.s.pinchScale&&a.i.pinchStartOffset.y==b.i.pinchStartOffset.y);}
 {Fixture f;f.s.pinchStartScale=nan;f.go(2,2,3);assert(std::isnan(f.s.pinchScale)&&f.s.hasPinchVelocity);}
 {Fixture f;f.s.hasPinchVelocity=true;f.s.pinchVelocity=19;f.s.pinchStartScale=4;f.go(2,2,nan);assert(f.s.hasPinchVelocity&&f.s.pinchVelocity==19);}
 {Fixture f;f.s.pinchStartScale=4;f.go(2,0);assert(f.s.pinchScale==40&&!f.s.hasPinchVelocity);}
 {Fixture f;f.s.pinchStartScale=4;f.go(2,-2);assert(f.s.pinchScale==.5&&f.s.hasPinchVelocity);}
 {Fixture f;f.w.onLoad=[&]{f.s.world=nullptr;};f.go();assert(f.r.events.empty()&&f.s.pinchScale==4);}
 {Fixture f;f.r.onUI=[&]{f.s.world=nullptr;};f.go();assert((f.r.events==std::vector<std::string>{"ui","buttons"}));}
 {Fixture f;f.r.onPan=[&]{f.s.world=nullptr;};f.go();assert(f.s.pinching&&f.s.pinchScale==2&&f.r.events.back()=="changed");}
 {Fixture f;f.r.onGoal=[&]{f.s.scrolling=true;f.i.translationOffset={5,6};};f.go();assert(f.i.translationOffset.x==5&&f.r.events.size()==5);}
 {Fixture f;f.go();f.s.hasRenderedFrameSinceActivate=true;updateGameView(f.s,f.r,.01f,.01f);assert(f.w.updates==1&&f.s.pinching&&f.s.pinchScale==2);}
 std::cout<<"PASS gameview_input assertions enabled; gates/begin/change/end/NaN/callbacks/shared update\n";
}
