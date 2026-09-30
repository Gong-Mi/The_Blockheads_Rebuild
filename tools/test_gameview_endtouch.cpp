#ifdef NDEBUG
#error Assertions MUST stay enabled for Release acceptance
#endif
#include "gameview_end_touch.h"
#include "world_end_touch.h"
#include <cassert>
#include <cstdint>
#include <functional>
#include <iostream>
#include <string>
#include <vector>
using namespace blockheads::recovered;

struct World final : FrameWorld {
    std::vector<std::string>& events;
    bool loaded{true}, simulating{};
    std::function<void()> onLoad, onSim, onEnd;
    FrameVector2 lastPoint{};
    std::int32_t lastIndex{-1};
    explicit World(std::vector<std::string>& e) : events(e) {}
    bool loadComplete() override {
        events.push_back("load"); if (onLoad) onLoad(); return loaded;
    }
    bool isSimulating() override {
        events.push_back("sim"); if (onSim) onSim(); return simulating;
    }
    bool translatingToGoal() override { return false; }
    bool takingPhoto() override { return false; }
    FrameVector2 translation() override { return {}; }
    void setTranslation(FrameVector2) override {}
    std::int32_t worldWidthMacro() override { return 32; }
    void update(float, float, double, bool) override {}
    std::int8_t startTouch(FrameVector2, std::int32_t, std::int32_t) override { return 0; }
    std::int8_t touchIsInUI(FrameVector2) override { return 0; }
    void moveTouch(FrameVector2, std::int32_t) override {}
    void endTouch(FrameVector2 p, std::int32_t i) override {
        events.push_back("world-end"); lastPoint=p; lastIndex=i;
        if (onEnd) onEnd();
    }
    void cancelTouch(FrameVector2, std::int32_t) override {}
};
struct Menu final : GameViewEndTouchMenuUI {
    int calls{}; FrameVector2 point{};
    void endTouch(FrameVector2 p) override { ++calls; point=p; }
};
struct Fixture {
    std::vector<std::string> events;
    GameViewState state;
    GameViewStartTouchState touch;
    World a{events}, b{events};
    Menu menu;
    Fixture() { state.world = &a; }
    void go(FrameVector2 p={5.5f,-6.25f}, GameViewEndTouchMenuUI* m=nullptr) {
        endTouch(state, touch, m, p);
    }
};

int main() {
    // Menu route is exactly mainMenuUI != nil AND world == nil; the shared
    // tail still clears primaryTouchIsActiveInUI on every path (0x92c5e0).
    {
        Fixture f; f.state.world=nullptr; f.touch.primaryTouchIsActiveInUI=1;
        f.touch.secondaryTouchIsActiveInUI=1;
        f.go({3.5f,-2.25f}, &f.menu);
        assert(f.menu.calls==1 && f.menu.point.x==3.5f && f.menu.point.y==-2.25f);
        assert(f.events.empty());
        assert(f.touch.primaryTouchIsActiveInUI==0);
        assert(f.touch.secondaryTouchIsActiveInUI==1);  // never written
    }
    // Menu present with non-nil world: menu ivar!=0 but world!=nil -> World path.
    {
        Fixture f; f.touch.primaryTouchIsActiveInUI=-1;
        f.go({1,2}, &f.menu);
        assert(f.menu.calls==0);
        assert((f.events==std::vector<std::string>{"load","sim","world-end"}));
    }
    // loadComplete=0 skips isSimulating and the send, but still clears primary.
    {
        Fixture f; f.a.loaded=false; f.touch.primaryTouchIsActiveInUI=1;
        f.touch.secondaryTouchIsActiveInUI=1;
        f.go({1,2});
        assert((f.events==std::vector<std::string>{"load"}));
        assert(f.touch.primaryTouchIsActiveInUI==0 && f.a.lastIndex==-1);
    }
    // isSimulating!=0 skips the send but keeps the tail clear.
    {
        Fixture f; f.a.simulating=true; f.touch.primaryTouchIsActiveInUI=1;
        f.go({1,2});
        assert((f.events==std::vector<std::string>{"load","sim"}));
        assert(f.touch.primaryTouchIsActiveInUI==0 && f.a.lastIndex==-1);
    }
    // primary!=0 sends with literal index 0 and the untouched original point.
    {
        Fixture f; f.touch.primaryTouchIsActiveInUI=-1;
        f.touch.secondaryTouchIsActiveInUI=1;  // ignored once primary is active
        f.go({12.0f,18.0f});
        assert((f.events==std::vector<std::string>{"load","sim","world-end"}));
        assert(f.a.lastIndex==0);
        assert(f.a.lastPoint.x==12.0f && f.a.lastPoint.y==18.0f);
        assert(f.touch.primaryTouchIsActiveInUI==0);
    }
    // primary==0 AND secondary==0 still sends: this is the idle-UI tap path,
    // distinct from moveTouch where only primary gates the indexed send.
    {
        Fixture f; f.touch.primaryTouchIsActiveInUI=0;
        f.touch.secondaryTouchIsActiveInUI=0;
        f.go({7,8});
        assert((f.events==std::vector<std::string>{"load","sim","world-end"}));
        assert(f.a.lastIndex==0);
    }
    // primary==0 AND secondary!=0 is the only no-send combination after gates.
    {
        Fixture f; f.touch.primaryTouchIsActiveInUI=0;
        f.touch.secondaryTouchIsActiveInUI=1;
        f.go({7,8});
        assert((f.events==std::vector<std::string>{"load","sim"}));
        assert(f.touch.primaryTouchIsActiveInUI==0 && f.a.lastIndex==-1);
    }
    // Signed-byte semantics: +1 counts as active under ldrsb/cmp (same send
    // path as -1 above; the original never normalizes to bool).
    {
        Fixture f; f.touch.primaryTouchIsActiveInUI=1;
        f.go();
        assert((f.events==std::vector<std::string>{"load","sim","world-end"}));
        assert(f.a.lastIndex==0 && f.touch.primaryTouchIsActiveInUI==0);
    }
    // Receiver reloads: loadComplete callback may swap the world; the indexed
    // send reloads self.world once more and hits the new receiver.
    {
        Fixture f; f.a.onSim=[&]{ f.state.world=&f.b; };
        f.touch.primaryTouchIsActiveInUI=1;
        f.go({4,5});
        assert((f.events==std::vector<std::string>{"load","sim","world-end"}));
        assert(f.b.lastIndex==0 && f.a.lastIndex==-1);
    }
    // loadComplete can nil the world; then isSimulating is nil-dispatch false,
    // the send receiver reload is nil (no message), primary still cleared.
    {
        Fixture f; f.a.onLoad=[&]{ f.state.world=nullptr; };
        f.touch.primaryTouchIsActiveInUI=1; f.touch.secondaryTouchIsActiveInUI=1;
        f.go({4,5});
        assert((f.events==std::vector<std::string>{"load"}));
        assert(f.touch.primaryTouchIsActiveInUI==0);
    }
    // Nil world from entry: nil loadComplete is ObjC false; nothing but the
    // tail clear happens (no menu send either).
    {
        Fixture f; f.state.world=nullptr;
        f.touch.primaryTouchIsActiveInUI=-1;
        f.go({9,9});
        assert(f.events.empty() && f.touch.primaryTouchIsActiveInUI==0);
    }
    // World -[endTouch:index:] is pure forwarding: one self-dispatch of
    // doEndTouch:with wasCancelled pinned to 0 and index preserved verbatim.
    {
        struct Sink final : WorldEndTouchSink {
            std::vector<std::string>& events; int calls{}; std::int8_t cancelled{9};
            std::int32_t index{-9}; FrameVector2 point{};
            explicit Sink(std::vector<std::string>& e) : events(e) {}
            void doEndTouch(FrameVector2 p, std::int8_t w, std::int32_t i) override {
                ++calls; point=p; cancelled=w; index=i; events.push_back("do-end");
            }
        };
        std::vector<std::string> events; Sink sink{events};
        worldEndTouch(nullptr, {1,2}, 3);
        assert(events.empty() && sink.calls==0);
        worldEndTouch(&sink, {-4.25f, 6.5f}, 7);
        assert(sink.calls==1 && sink.cancelled==0 && sink.index==7);
        assert(sink.point.x==-4.25f && sink.point.y==6.5f);
        assert((events==std::vector<std::string>{"do-end"}));
        // Negative and zero indices pass through unchanged (only GameView's
        // direct send pins the literal 0 at 0x0092c5cc).
        worldEndTouch(&sink, {0,0}, -2);
        assert(sink.index==-2 && sink.calls==2);
    }
    std::cout << "PASS gameview_endtouch gates, idle-UI indexed send, receiver reloads, universal primary clear, doEndTouch forwarding\n";
}
