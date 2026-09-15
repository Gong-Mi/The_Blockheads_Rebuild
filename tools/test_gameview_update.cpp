#ifdef NDEBUG
#undef NDEBUG // These behavioral checks remain active in Release CTest builds.
#endif
#include "gameview_update.h"
#include "projection_update.h"
#include <limits>
#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdio>
#include <functional>
#include <string>
#include <vector>
using namespace blockheads::recovered;
struct Trace {
    std::vector<std::string> calls;
    std::function<void(const std::string&)> hook;
    void call(const std::string& name) { calls.push_back(name); if (hook) hook(name); }
    int count(const std::string& s) const { return static_cast<int>(std::count(calls.begin(), calls.end(), s)); }
};
struct World final : FrameWorld {
    Trace& trace; std::string name;
    bool loaded{true}, simulating{false}, goal{}, photo{};
    FrameVector2 position{100.0f, 500.0f}, written{};
    std::int32_t width{10};
    float dt{}, accurate{}; double scale{}; bool drag{};
    World(Trace& t, std::string n): trace(t), name(n) {}
    void event(const char* e) { trace.call(name + "." + e); }
    bool loadComplete() override { event("load"); return loaded; }
    bool isSimulating() override { event("sim"); return simulating; }
    bool translatingToGoal() override { event("goal"); return goal; }
    bool takingPhoto() override { event("photo"); return photo; }
    FrameVector2 translation() override { event("translation"); return position; }
    void setTranslation(FrameVector2 v) override { written=v; event("set"); }
    std::int32_t worldWidthMacro() override { event("width"); return width; }
    void update(float d, float a, double p, bool g) override {
        dt=d; accurate=a; scale=p; drag=g; event("update");
    }
};
struct Defaults final : FrameDefaults {
    Trace& trace; float f{}; double d{};
    explicit Defaults(Trace& t):trace(t) {}
    void setFloat(float value, std::string_view key) override {
        f=value; assert(key=="pinchScale"); trace.call("setFloat");
    }
    void setDouble(double value, std::string_view key) override {
        d=value; assert(key=="totalGamePlayTimePassed"); trace.call("setDouble");
    }
};
struct Runtime final : FrameRuntime {
    Trace& trace; Defaults defaults; bool nilDefaults{};
    float modValue{}, modDivisor{};
    explicit Runtime(Trace& t):trace(t),defaults(t) {}
    FrameDefaults* standardUserDefaults() override {
        trace.call("defaults"); return nilDefaults ? nullptr : &defaults;
    }
    void pinchScaleChanged(GameViewState& s) override {
        FrameRuntime::pinchScaleChanged(s); trace.call("notify");
    }
    float fmodFloat(float v, float d) override {
        modValue=v; modDivisor=d; trace.call("fmod"); return FrameRuntime::fmodFloat(v,d);
    }
};
struct Fixture {
    Trace trace; World a{trace,"A"}, b{trace,"B"}; Runtime rt{trace}; GameViewState s;
    Fixture() { s.world=&a; s.hasRenderedFrameSinceActivate=true;
                s.windowInfo[0]=1000; s.windowInfo[1]=1000; s.windowInfo[3]=1000; }
    void run(float dt=0.0f, float accurate=0.0f) { updateGameView(s,rt,dt,accurate); }
};
static void entry_and_forwarding() {
    { Fixture f; f.s.hasRenderedFrameSinceActivate=false; f.run(1,20); assert(f.trace.calls.empty()); }
    { Fixture f; f.a.simulating=true; f.s.pinchScale=100; f.s.scrolling=true;
      f.run(0.125f,0.25f); assert(f.s.timeCounter==0.25f);
      assert((f.trace.calls==std::vector<std::string>{"A.load","A.sim","A.update"}));
      assert(f.a.dt==0.125f && f.a.accurate==0.25f && f.a.scale==100 && f.a.drag); }
    { Fixture f; f.a.loaded=false; f.run(); assert((f.trace.calls==std::vector<std::string>{"A.load"})); }
    { Fixture f; f.s.world=nullptr; f.s.timeCounter=11; f.run();
      assert((f.trace.calls==std::vector<std::string>{"defaults","setDouble","fmod"}));
      assert(f.s.timeCounter==1 && f.s.totalGamePlayTimePassed==10); }
    { Fixture f; f.a.simulating=true; f.s.timeCounter=10; f.run(); assert(f.trace.count("defaults")==0); }
    { Fixture f; f.a.simulating=true; f.s.timeCounter=25; f.run();
      assert(f.trace.count("defaults")==1 && f.s.timeCounter==15 && f.s.totalGamePlayTimePassed==10); }
    { Fixture f; f.s.timeCounter=11; f.b.simulating=true;
      f.trace.hook=[&](const std::string& e) {
          if(e=="defaults") { f.s.totalGamePlayTimePassed=100; }
          if(e=="setDouble") { f.s.totalGamePlayTimePassed=200; f.s.timeCounter=42; }
          if(e=="fmod") f.s.world=&f.b;
      };
      f.run(); assert(f.rt.defaults.d==100 && f.s.timeCounter==32);
      assert(f.rt.modValue==200 && f.rt.modDivisor==3600);
      assert(f.trace.count("B.update")==1 && f.trace.count("A.load")==0); }
    { Fixture f; f.b.simulating=true;
      f.trace.hook=[&](const std::string& e) { if(e=="A.load") f.s.world=&f.b; };
      f.run(); assert((f.trace.calls==std::vector<std::string>{"A.load","B.sim","B.update"})); }
    { Fixture f; f.a.simulating=true;
      f.trace.hook=[&](const std::string& e) { if(e=="A.sim") { f.s.world=&f.b; f.s.pinchScale=8; } };
      f.run(); assert(f.trace.count("B.update")==1 && f.b.scale==8); }
    { Fixture f; f.rt.nilDefaults=true; f.a.simulating=true; f.s.timeCounter=11; f.run();
      assert(f.trace.count("defaults")==1 && f.trace.count("setDouble")==0 && f.trace.count("fmod")==1); }
}
static void baseline_and_scroll_order() {
    { Fixture f; f.run();
      assert((f.trace.calls==std::vector<std::string>{"A.load","A.sim","A.goal","A.translation","A.set","A.photo","A.update"})); }
    { Fixture f; f.s.hasVelocity=true; f.s.scrollVelocity={4,0};
      f.trace.hook=[&](const std::string& e) {
          if(e=="A.goal" && f.trace.count(e)==1) f.s.hasVelocity=false;
          if(e=="A.translation" && f.trace.count(e)==1) {
              f.s.world=&f.b; f.s.scrolling=true; f.s.scrollVelocity={4,8};
          }
      };
      f.run(0.125f);
      assert(f.a.written.x==99.5f && f.a.written.y==499.0f);
      assert(f.trace.count("A.set")==1 && f.trace.count("B.set")==1);
      assert(f.trace.count("B.goal")==1 && f.trace.count("B.translation")==3);
      assert(!f.s.hasVelocity && f.b.drag); }
    { Fixture f; f.s.hasVelocity=true; f.s.scrollVelocity={2,0}; f.a.position.x=-1;
      f.run();
      assert(f.trace.count("A.translation")==4 && f.trace.count("A.width")==1);
      assert(f.trace.count("A.set")==2 && f.a.written.x==-1); }
    { Fixture f; f.s.hasVelocity=true; f.s.scrollVelocity={2,0}; f.a.position.x=400;
      f.run();
      assert(f.trace.count("A.translation")==5 && f.trace.count("A.width")==2);
      assert(f.trace.count("A.set")==2 && f.a.written.x==400); }
    { Fixture f; f.s.hasVelocity=true; f.s.scrollVelocity={2,0};
      f.a.position.x=std::numeric_limits<float>::quiet_NaN();
      f.run();
      // VFP unordered gives NZCV=0011: BLT (N!=V) is taken at0x926174.
      // Unlike BPL, its fallthrough is ordered >=, not !(x < width).
      assert(f.trace.count("A.translation")==4 && f.trace.count("A.width")==1); }
    { Fixture f; f.s.hasVelocity=true; f.s.scrollVelocity={0.01f,0}; f.run();
      assert(!f.s.hasVelocity && f.trace.count("A.translation")==1 && f.trace.count("A.width")==0); }
}
static void pinch_callbacks_and_tail() {
    { Fixture f; f.a.position.y=0; f.b.photo=true;
      f.trace.hook=[&](const std::string& e) {
          if(e=="A.translation") { f.s.world=&f.b; f.s.pinchScale=2; f.s.windowInfo[3]=2000; }
          if(e=="B.set") f.s.windowInfo[1]=81920;
      };
      f.run(0.05f);
      assert(f.trace.count("A.set")==0 && f.trace.count("B.set")==1);
      assert(f.b.written.y==50.01f && f.s.pinchScale==0.5 && f.b.scale==0.5); }
    { Fixture f; f.s.pinchZooming=true; f.s.hasPinchVelocity=true; f.a.photo=true;
      f.trace.hook=[&](const std::string& e) {
          if(e=="defaults") { assert(!f.s.pinchZooming); f.s.pinchScale=2; }
          if(e=="setFloat") f.s.pinchScale=3;
      };
      f.run(); assert(f.rt.defaults.f==2 && f.s.pinchScale==3);
      assert(f.trace.count("A.goal")==1); // no same-frame pinch-velocity fallthrough
    }
    { Fixture f; f.s.hasPinchVelocity=true; f.s.pinchVelocity=1; f.s.pinchStartScale=0.75f;
      f.trace.hook=[&](const std::string& e) {
          if(e=="A.photo" && f.trace.count(e)==1) {
              assert(f.s.pinchScale==0.75); f.s.pinchScale=9; f.s.hasPinchVelocity=false;
          }
          if(e=="notify") {
              assert(f.s.pinchScale==0.75); // cached pre-query ratio wins
              f.s.pinchScale=1; f.s.hasPinchVelocity=true; f.s.lastPinchFactor=3;
          }
      };
      f.run(); assert(f.trace.count("notify")==1 && f.s.pinchStartScale==3);
      assert(f.a.scale==1 && f.trace.count("A.photo")==2); }
    { Fixture f; f.s.scrolling=true; f.s.pinchScale=0.55; f.s.hasPinchVelocity=true;
      f.trace.hook=[&](const std::string& e) {
          if(e=="defaults") { assert(f.s.pinchScale==0.5); f.s.pinchScale=9; }
          if(e=="setFloat") f.s.pinchScale=4;
          if(e=="notify") { assert(f.s.pinchScale==4); f.s.pinchScale=7; f.s.lastPinchFactor=5; }
      };
      f.run(0.1f); assert(f.rt.defaults.f==9 && f.s.pinchStartScale==35 && f.a.scale==7);
      assert((f.trace.calls==std::vector<std::string>{"A.load","A.sim","A.photo","defaults","setFloat","notify","A.update"})); }
    { Fixture f; f.s.scrolling=true; f.s.pinchScale=1.3;
      f.trace.hook=[&](const std::string& e) { if(e=="A.photo") f.s.isZoomingCameraOut=true; };
      f.run(); assert(f.trace.count("notify")==1); // don't re-test camera gate after query
    }
    { Fixture f; f.s.scrolling=true; f.s.hasPinchVelocity=true;
      f.trace.hook=[&](const std::string& e) { if(e=="A.photo") f.s.pinchZooming=true; };
      f.run(); assert(f.s.pinchStartScale==1 && f.trace.count("notify")==0); }
}
static void executable_projection_dependency() {
    Fixture f; f.s.scrolling=true; f.s.pinchScale=0.55;
    for (auto& value : f.s.projectionMatrix) value=777.0f;
    f.s.cameraZ=777.0f;
    f.run();
    assert(f.trace.count("notify")==1);
    const auto expected=buildProjection({f.s.pinchScale,f.s.windowInfo[0],f.s.windowInfo[1]});
    for (int i=0;i<16;++i) assert(f.s.projectionMatrix[i]==expected.matrix[i]);
    assert(f.s.projectionMatrix[11]==-1.0f && f.s.cameraZ==expected.cameraZ);
    assert(f.s.cameraZ!=777.0f);
}
int main() {
    entry_and_forwarding(); baseline_and_scroll_order(); pinch_callbacks_and_tail();
    executable_projection_dependency();
    std::puts("gameview-update: PASS");
}
