#ifdef NDEBUG
#error Assertions MUST stay enabled for Release acceptance
#endif
#include "gameview_move_touch.h"
#include "world_move_touch.h"
#include <cassert>
#include <cmath>
#include <functional>
#include <iostream>
#include <limits>
#include <string>
#include <vector>
using namespace blockheads::recovered;

struct UI final : WorldMoveTouchUI {
    std::vector<std::string>& events;
    int calls{};
    FrameVector2 point{};
    std::int32_t index{-1};
    std::function<void()> onMove;
    explicit UI(std::vector<std::string>& e) : events(e) {}
    void moveTouch(FrameVector2 p, std::int32_t i) override {
        ++calls; point=p; index=i; events.push_back("ui-move");
        if (onMove) onMove();
    }
};
struct Menu final : GameViewMoveTouchMenuUI {
    int calls{}; FrameVector2 point{};
    void moveTouch(FrameVector2 p) override { ++calls; point=p; }
};
struct World final : FrameWorld {
    std::vector<std::string>& events;
    bool loaded{true}, simulating{};
    std::function<void()> onLoad, onSim, onMove;
    WorldMoveTouchUI* ui{};
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
    void moveTouch(FrameVector2 p, std::int32_t i) override {
        events.push_back("world-move"); lastPoint=p; lastIndex=i;
        if (onMove) onMove();
        worldMoveTouch(ui, p, i);
    }
    void endTouch(FrameVector2, std::int32_t) override {}
};
struct Fixture {
    std::vector<std::string> events;
    GameViewState state;
    GameViewStartTouchState touch;
    World a{events}, b{events};
    UI ui{events};
    Menu menu;
    Fixture() {
        state.world=&a; a.ui=&ui; b.ui=&ui;
        touch.startTouchHasntMoved=1;
        touch.startTouchPos={10.0f,20.0f};
    }
    void go(FrameVector2 p={11.0f,21.0f}, GameViewMoveTouchMenuUI* m=nullptr) {
        moveTouch(state,touch,m,p);
    }
};

int main() {
    // Menu route is exactly mainMenuUI != nil AND world == nil.
    {
        Fixture f; f.state.world=nullptr; f.go({3.5f,-2.25f},&f.menu);
        assert(f.menu.calls==1 && f.menu.point.x==3.5f && f.menu.point.y==-2.25f);
        assert(f.events.empty());
        assert(f.touch.startTouchHasntMoved==1);
    }
    // No menu and nil world: ObjC nil loadComplete returns zero, so no effects.
    {
        Fixture f; f.state.world=nullptr; f.go({20,30});
        assert(f.events.empty() && f.ui.calls==0);
        assert(f.touch.startTouchHasntMoved==1);
    }
    // loadComplete=0 short-circuits before simulation, forwarding, and threshold.
    {
        Fixture f; f.a.loaded=false; f.touch.primaryTouchIsActiveInUI=1;
        f.go({20,30});
        assert((f.events==std::vector<std::string>{"load"}));
        assert(f.touch.startTouchHasntMoved==1 && f.ui.calls==0);
    }
    // isSimulating!=0 also returns before either callback or threshold store.
    {
        Fixture f; f.a.simulating=true; f.touch.primaryTouchIsActiveInUI=1;
        f.go({20,30});
        assert((f.events==std::vector<std::string>{"load","sim"}));
        assert(f.touch.startTouchHasntMoved==1 && f.ui.calls==0);
    }
    // Active UI forwards to World with literal index 0, then World forwards
    // unchanged CGPoint/index to UIManager. Exactly 2.0 is not over threshold.
    {
        Fixture f; f.touch.primaryTouchIsActiveInUI=-1;
        f.go({12.0f,18.0f});
        assert((f.events==std::vector<std::string>{"load","sim","world-move","ui-move"}));
        assert(f.a.lastIndex==0 && f.ui.index==0);
        assert(f.a.lastPoint.x==12.0f && f.a.lastPoint.y==18.0f);
        assert(f.ui.point.x==12.0f && f.ui.point.y==18.0f);
        assert(f.touch.startTouchHasntMoved==1);
    }
    // primaryTouchIsActiveInUI gates only World forwarding; the local drag
    // latch is cleared on strict ordered abs(delta)>2.0 even when inactive.
    {
        Fixture f; f.touch.primaryTouchIsActiveInUI=0;
        f.go({std::nextafter(12.0f,13.0f),20.0f});
        assert((f.events==std::vector<std::string>{"load","sim"}));
        assert(f.touch.startTouchHasntMoved==0);
    }
    // Y is an independent strict threshold; negative movement uses absolute value.
    {
        Fixture f; f.touch.primaryTouchIsActiveInUI=0;
        f.go({10.0f,std::nextafter(18.0f,0.0f)});
        assert(f.touch.startTouchHasntMoved==0);
    }
    // Callback mutation of the receiver: every World message reloads self.world.
    {
        Fixture f;
        f.a.onSim=[&]{ f.state.world=&f.b; };
        f.touch.primaryTouchIsActiveInUI=1;
        f.go({11,21});
        assert((f.events==std::vector<std::string>{"load","sim","world-move","ui-move"}));
        assert(f.b.lastIndex==0 && f.a.lastIndex==-1);
    }
    // A load callback can nil the World. Later nil messages are no-ops, but the
    // local threshold still runs after both gates, as in the original body.
    {
        Fixture f;
        f.a.onLoad=[&]{ f.state.world=nullptr; };
        f.touch.primaryTouchIsActiveInUI=1;
        f.go({13,20});
        assert((f.events==std::vector<std::string>{"load"}));
        assert(f.touch.startTouchHasntMoved==0 && f.ui.calls==0);
    }
    // World/UI callback changes startTouchPos before the VFP comparison; the
    // method reloads both coordinates after the callback and keeps the latch.
    {
        Fixture f;
        f.ui.onMove=[&]{ f.touch.startTouchPos={13,20}; };
        f.touch.primaryTouchIsActiveInUI=1;
        f.go({13,20});
        assert(f.ui.calls==1 && f.touch.startTouchHasntMoved==1);
    }
    // VFP ordered comparison: NaN on X does not clear by itself; Y still decides.
    {
        Fixture f; const float nan=std::numeric_limits<float>::quiet_NaN();
        f.touch.primaryTouchIsActiveInUI=0;
        f.go({nan,22.0f}); assert(f.touch.startTouchHasntMoved==1);
        f.go({nan,std::nextafter(22.0f,23.0f)});
        assert(f.touch.startTouchHasntMoved==0);
    }
    // World -[moveTouch:index:] nil-dispatch is a no-op; non-nil forwards once.
    {
        std::vector<std::string> events; UI ui{events};
        worldMoveTouch(nullptr,{4,5},7); assert(events.empty());
        worldMoveTouch(&ui,{4,5},7);
        assert(ui.calls==1 && ui.index==7 && ui.point.x==4 && ui.point.y==5);
    }
    std::cout << "PASS gameview_movetouch gates, indexed UI forwarding, callback reload, strict VFP drag threshold\n";
}
