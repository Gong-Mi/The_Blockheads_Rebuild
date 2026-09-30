#ifdef NDEBUG
#error Assertions MUST stay enabled for Release acceptance
#endif
#include "gameview_secondary_touch.h"
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
    std::function<void()> onLoad, onSim;
    std::int8_t endLast{-1}, cancelLast{-1};
    explicit World(std::vector<std::string>& e) : events(e) {}
    bool loadComplete() override { events.push_back("load"); if (onLoad) onLoad(); return loaded; }
    bool isSimulating() override { events.push_back("sim"); if (onSim) onSim(); return simulating; }
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
        events.push_back("world-end"); endLast = static_cast<std::int8_t>(i);
        lastX=p.x; lastY=p.y;
    }
    void cancelTouch(FrameVector2 p, std::int32_t i) override {
        events.push_back("world-cancel"); cancelLast = static_cast<std::int8_t>(i);
        lastX=p.x; lastY=p.y;
    }
    float lastX{}, lastY{};
};
struct Fix {
    std::vector<std::string> events;
    GameViewState state;
    GameViewStartTouchState prim;
    GameViewSecondaryTouchState sec;
    World a{events}, b{events};
    Fix() { state.world = &a; }
    void end(FrameVector2 p={5.5f,-6.25f}) { endSecondaryTouch(state, prim, sec, p); }
    void cancel(FrameVector2 p={5.5f,-6.25f}) { cancelSecondaryTouch(state, prim, sec, p); }
};

int main() {
    // Not started: the whole body collapses to the tail clear; no gates, no send.
    {
        Fix f; f.sec.secondaryTouchStarted=0; f.sec.secondaryStartTouchHasntMoved=1;
        f.prim.primaryTouchIsActiveInUI=1;
        f.end();
        assert(f.events.empty());
        assert(f.prim.secondaryTouchIsActiveInUI==0);
        assert(f.sec.secondaryStartTouchHasntMoved==1);  // end has no latch write
    }
    // Started + load gate zero: tail clear only.
    {
        Fix f; f.sec.secondaryTouchStarted=1; f.a.loaded=false;
        f.prim.primaryTouchIsActiveInUI=1; f.sec.secondaryStartTouchHasntMoved=1;
        f.end();
        assert((f.events==std::vector<std::string>{"load"}));
        assert(f.prim.secondaryTouchIsActiveInUI==0 && f.a.endLast==-1);
    }
    // Started + simulating: no send, tail clear.
    {
        Fix f; f.sec.secondaryTouchStarted=-1; f.a.simulating=true;
        f.prim.primaryTouchIsActiveInUI=1;
        f.end();
        assert((f.events==std::vector<std::string>{"load","sim"}));
        assert(f.prim.secondaryTouchIsActiveInUI==0 && f.a.endLast==-1);
    }
    // secondary!=0 sends endTouch:index: with literal 1 and the original point.
    {
        Fix f; f.sec.secondaryTouchStarted=1; f.prim.secondaryTouchIsActiveInUI=-1;
        f.prim.primaryTouchIsActiveInUI=0;  // gate uses secondary first; primary irrelevant
        f.end({12.0f,18.0f});
        assert((f.events==std::vector<std::string>{"load","sim","world-end"}));
        assert(f.a.endLast==1);
        assert(f.a.lastX==12.0f && f.a.lastY==18.0f);
        assert(f.prim.secondaryTouchIsActiveInUI==0);   // tail cleared SECONDARY byte
        // secondary byte was 0 at entry (never normalized), -1 came from
        // assignment; primary is NOT written by this body.
        assert(f.prim.primaryTouchIsActiveInUI==0);
    }
    // primary==0 and secondary==0: the mirror of the primary pair's idle gate —
    // the idle PRIMARY byte lets the secondary release forward.
    {
        Fix f; f.sec.secondaryTouchStarted=1; f.prim.secondaryTouchIsActiveInUI=0;
        f.prim.primaryTouchIsActiveInUI=0;
        f.end();
        assert((f.events==std::vector<std::string>{"load","sim","world-end"}));
        assert(f.a.endLast==1);
    }
    // secondary==0 AND primary!=0: the ONLY no-send combination.
    {
        Fix f; f.sec.secondaryTouchStarted=1; f.prim.secondaryTouchIsActiveInUI=0;
        f.prim.primaryTouchIsActiveInUI=1;
        f.end();
        assert((f.events==std::vector<std::string>{"load","sim"}));
        assert(f.a.endLast==-1);
    }
    // cancelSecondaryTouch: send cancels with literal 1 and clears the latch.
    {
        Fix f; f.sec.secondaryTouchStarted=1; f.prim.secondaryTouchIsActiveInUI=1;
        f.sec.secondaryStartTouchHasntMoved=1;
        f.cancel({4.5f,9.25f});
        assert((f.events==std::vector<std::string>{"load","sim","world-cancel"}));
        assert(f.a.cancelLast==1 && f.a.lastX==4.5f && f.a.lastY==9.25f);
        assert(f.sec.secondaryStartTouchHasntMoved==0);
        assert(f.prim.secondaryTouchIsActiveInUI==0);
    }
    // cancel skip path (secondary==0, primary!=0): NO send but the join STILL
    // clears the latch — same shape as the primary cancel join.
    {
        Fix f; f.sec.secondaryTouchStarted=1; f.prim.secondaryTouchIsActiveInUI=0;
        f.prim.primaryTouchIsActiveInUI=-1; f.sec.secondaryStartTouchHasntMoved=1;
        f.cancel();
        assert((f.events==std::vector<std::string>{"load","sim"}));
        assert(f.a.cancelLast==-1 && f.sec.secondaryStartTouchHasntMoved==0);
    }
    // Started gate uses raw signed byte: -1 enters, 0 does not.
    {
        Fix f; f.sec.secondaryTouchStarted=-1; f.prim.primaryTouchIsActiveInUI=0;
        f.end();
        assert(f.a.endLast==1);
        f.sec.secondaryTouchStarted=0; f.prim.secondaryTouchIsActiveInUI=1;
        Fix g; g.sec.secondaryTouchStarted=0;
        g.end(); assert(g.events.empty());
    }
    // Receiver reload: isSimulating callback swaps world; send hits the new
    // receiver; nil-world chain messages are ObjC nil-dispatch false.
    {
        Fix f; f.sec.secondaryTouchStarted=1; f.prim.secondaryTouchIsActiveInUI=1;
        f.a.onSim=[&]{ f.state.world=&f.b; };
        f.cancel();
        assert((f.events==std::vector<std::string>{"load","sim","world-cancel"}));
        assert(f.b.cancelLast==1 && f.a.cancelLast==-1);
    }
    {
        Fix f; f.state.world=nullptr; f.sec.secondaryTouchStarted=1;
        f.prim.secondaryTouchIsActiveInUI=1; f.prim.primaryTouchIsActiveInUI=0;
        f.end();
        assert(f.events.empty() && f.prim.secondaryTouchIsActiveInUI==0);
    }
    std::cout << "PASS secondary end/cancel mirror pair: started gate byte, index literal 1, own-OR-other-idle send, secondary tail clear, cancel latch join\n";
}
