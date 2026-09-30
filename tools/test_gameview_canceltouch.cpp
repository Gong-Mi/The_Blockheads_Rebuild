#ifdef NDEBUG
#error Assertions MUST stay enabled for Release acceptance
#endif
#include "gameview_cancel_touch.h"
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
    std::function<void()> onLoad, onSim, onCancel;
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
    void endTouch(FrameVector2, std::int32_t) override {}
    void cancelTouch(FrameVector2 p, std::int32_t i) override {
        events.push_back("world-cancel"); lastPoint=p; lastIndex=i;
        if (onCancel) onCancel();
    }
};
struct Menu final : GameViewCancelTouchMenuUI {
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
    void go(FrameVector2 p={5.5f,-6.25f}, GameViewCancelTouchMenuUI* m=nullptr) {
        cancelTouch(state, touch, m, p);
    }
};

int main() {
    // Menu route: mainMenuUI != nil AND world == nil sends END (not cancel)
    // and skips the world-path startTouchHasntMoved clear; the tail clear
    // still runs on every path.
    {
        Fixture f; f.state.world=nullptr; f.touch.primaryTouchIsActiveInUI=1;
        f.touch.secondaryTouchIsActiveInUI=1; f.touch.startTouchHasntMoved=1;
        f.go({3.5f,-2.25f}, &f.menu);
        assert(f.menu.calls==1 && f.menu.point.x==3.5f && f.menu.point.y==-2.25f);
        assert(f.events.empty());
        assert(f.touch.primaryTouchIsActiveInUI==0);
        assert(f.touch.startTouchHasntMoved==1);  // world-path-only store
    }
    // loadComplete=0: tail clear only; no send, no latch clear.
    {
        Fixture f; f.a.loaded=false; f.touch.primaryTouchIsActiveInUI=1;
        f.touch.secondaryTouchIsActiveInUI=1; f.touch.startTouchHasntMoved=1;
        f.go({1,2});
        assert((f.events==std::vector<std::string>{"load"}));
        assert(f.touch.primaryTouchIsActiveInUI==0);
        assert(f.touch.startTouchHasntMoved==1 && f.a.lastIndex==-1);
    }
    // isSimulating!=0: same shape as the load gate.
    {
        Fixture f; f.a.simulating=true; f.touch.primaryTouchIsActiveInUI=1;
        f.touch.startTouchHasntMoved=1;
        f.go({1,2});
        assert((f.events==std::vector<std::string>{"load","sim"}));
        assert(f.touch.startTouchHasntMoved==1 && f.a.lastIndex==-1);
    }
    // primary!=0 sends cancelTouch: with literal index 0, then clears BOTH
    // startTouchHasntMoved and the shared primary byte.
    {
        Fixture f; f.touch.primaryTouchIsActiveInUI=-1;
        f.touch.secondaryTouchIsActiveInUI=1; f.touch.startTouchHasntMoved=1;
        f.go({12.0f,18.0f});
        assert((f.events==std::vector<std::string>{"load","sim","world-cancel"}));
        assert(f.a.lastIndex==0);
        assert(f.a.lastPoint.x==12.0f && f.a.lastPoint.y==18.0f);
        assert(f.touch.startTouchHasntMoved==0 && f.touch.primaryTouchIsActiveInUI==0);
    }
    // primary==0 AND secondary==0: idle-UI path still sends.
    {
        Fixture f; f.touch.primaryTouchIsActiveInUI=0;
        f.touch.secondaryTouchIsActiveInUI=0; f.touch.startTouchHasntMoved=1;
        f.go({7,8});
        assert((f.events==std::vector<std::string>{"load","sim","world-cancel"}));
        assert(f.a.lastIndex==0 && f.touch.startTouchHasntMoved==0);
    }
    // primary==0 AND secondary!=0: NO send, but the join at 0x0092c81c still
    // clears startTouchHasntMoved — the skip path is NOT a bare tail jump.
    {
        Fixture f; f.touch.primaryTouchIsActiveInUI=0;
        f.touch.secondaryTouchIsActiveInUI=1; f.touch.startTouchHasntMoved=1;
        f.go({7,8});
        assert((f.events==std::vector<std::string>{"load","sim"}));
        assert(f.a.lastIndex==-1 && f.touch.startTouchHasntMoved==0);
        assert(f.touch.primaryTouchIsActiveInUI==0);
    }
    // Receiver reloads: isSimulating callback swaps the world; the send
    // reloads self.world and hits the new receiver.
    {
        Fixture f; f.a.onSim=[&]{ f.state.world=&f.b; };
        f.touch.primaryTouchIsActiveInUI=1;
        f.go({4,5});
        assert((f.events==std::vector<std::string>{"load","sim","world-cancel"}));
        assert(f.b.lastIndex==0 && f.a.lastIndex==-1);
    }
    // loadComplete can nil the world: isSimulating is nil-dispatch false,
    // the send reload is nil, but the join still clears the latch.
    {
        Fixture f; f.a.onLoad=[&]{ f.state.world=nullptr; };
        f.touch.primaryTouchIsActiveInUI=1; f.touch.secondaryTouchIsActiveInUI=1;
        f.touch.startTouchHasntMoved=1;
        f.go({4,5});
        assert((f.events==std::vector<std::string>{"load"}));
        assert(f.touch.startTouchHasntMoved==0 && f.touch.primaryTouchIsActiveInUI==0);
    }
    // The forwarding pair: identical body, wasCancelled 1 vs pinned 0.
    {
        struct Sink final : WorldEndTouchSink {
            std::vector<std::pair<std::int8_t,std::int32_t>> got;
            void doEndTouch(FrameVector2, std::int8_t w, std::int32_t i) override {
                got.emplace_back(w, i);
            }
        };
        Sink sink;
        worldCancelTouch(nullptr, {1,2}, 3);
        assert(sink.got.empty());
        worldCancelTouch(&sink, {-4.25f, 6.5f}, 7);
        worldEndTouch(&sink, {-4.25f, 6.5f}, 7);
        assert(sink.got.size()==2);
        assert(sink.got[0].first==1 && sink.got[0].second==7);  // cancel: 1
        assert(sink.got[1].first==0 && sink.got[1].second==7);  // end: 0
    }
    std::cout << "PASS gameview_canceltouch end-not-cancel menu send, join latch clear, idle-UI send, receiver reloads, forwarding-pair wasCancelled 1/0\n";
}
