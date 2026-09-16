#include "gameview_starttouch.h"
#include <cassert>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <iostream>
#ifdef NDEBUG
#error Assertions MUST stay enabled for Release acceptance
#endif
using namespace blockheads::recovered;
struct World final : FrameWorld {
    bool loaded = true, sim = false;
    std::int8_t startResult = 0, inUIResult = 0;
    FrameVector2 t{}, lastStartPoint{}, lastUIPoint{};
    std::int32_t lastTapCount = -1, lastIndex = -1;
    std::function<void()> onLoad;
    std::function<void()> onSim;
    std::vector<std::string>* events{};
    bool loadComplete() override {
        if (events) events->push_back("load");
        if (onLoad) onLoad();
        return loaded;
    }
    bool isSimulating() override {
        if (events) events->push_back("sim");
        if (onSim) onSim();
        return sim;
    }
    bool translatingToGoal() override { return false; }
    bool takingPhoto() override { return false; }
    FrameVector2 translation() override { return t; }
    void setTranslation(FrameVector2) override {}
    std::int32_t worldWidthMacro() override { return 32; }
    void update(float, float, double, bool) override {}
    std::int8_t startTouch(FrameVector2 point, std::int32_t tapCount,
                           std::int32_t index) override {
        if (events) events->push_back("start");
        lastStartPoint = point;
        lastTapCount = tapCount;
        lastIndex = index;
        return startResult;
    }
    std::int8_t touchIsInUI(FrameVector2 point) override {
        if (events) events->push_back("ui");
        lastUIPoint = point;
        return inUIResult;
    }
};
struct Menu final : StartTouchMenuUI {
    FrameVector2 point{};
    std::int32_t tapCount = -1;
    int calls = 0;
    void startTouch(FrameVector2 p, std::int32_t tap) override {
        ++calls;
        point = p;
        tapCount = tap;
    }
};
struct Runtime final : GameViewStartTouchRuntime {
    std::int32_t tapCount = 1;
    int calls = 0;
    std::function<void()> onTap;
    std::int32_t touchTapCount() override {
        ++calls;
        if (onTap) onTap();
        return tapCount;
    }
};
struct Fixture {
    GameViewState s;
    GameViewStartTouchState st;
    World w;
    Menu menu;
    Runtime r;
    std::vector<std::string> events;
    Fixture() {
        s.world = &w;
        w.events = &events;
        st.startTouchHasntMoved = 7;
        st.primaryTouchIsActiveInUI = 9;
        st.startTouchPos = {99, 88};
    }
    void go(FrameVector2 p = {3.5f, -2.25f}) {
        startTouch(s, st, &menu, r, p);
    }
};
int main() {
    // Menu path: menuUI != nil AND world == nil; tapCount dispatched once.
    {
        Fixture f;
        f.s.world = nullptr;
        f.r.tapCount = 4;
        f.go({1.5f, -2.25f});
        assert(f.menu.calls == 1);
        assert(f.menu.point.x == 1.5f && f.menu.point.y == -2.25f);
        assert(f.menu.tapCount == 4);
        assert(f.r.calls == 1);
        assert(f.events.empty());
        assert(f.st.startTouchHasntMoved == 0 && f.st.primaryTouchIsActiveInUI == 0);
        assert(f.st.startTouchPos.x == 99 && f.st.startTouchPos.y == 88);
    }
    // World != nil forces the world path even when menuUI is present.
    {
        Fixture f;
        f.go();
        assert(f.menu.calls == 0);
        assert(f.r.calls == 1);
        assert(!f.events.empty() && f.events.front() == "load");
    }
    // Nil world with nil menu: only the flag clears execute.
    {
        Fixture f;
        f.s.world = nullptr;
        StartTouchMenuUI* noMenu = nullptr;
        startTouch(f.s, f.st, noMenu, f.r, {0, 0});
        assert(f.r.calls == 0 && f.events.empty());
        assert(f.st.startTouchHasntMoved == 0 && f.st.primaryTouchIsActiveInUI == 0);
        assert(f.st.startTouchPos.x == 99);
    }
    // loadComplete == 0: gate returns before tapCount and startTouch.
    {
        Fixture f;
        f.w.loaded = false;
        f.go();
        assert((f.events == std::vector<std::string>{"load"}));
        assert(f.r.calls == 0);
        assert(f.st.primaryTouchIsActiveInUI == 0);
        assert(f.st.startTouchPos.x == 99);
    }
    // isSimulating != 0: gate returns before tapCount and startTouch.
    {
        Fixture f;
        f.w.sim = true;
        f.go();
        assert((f.events == std::vector<std::string>{"load", "sim"}));
        assert(f.r.calls == 0);
        assert(f.st.startTouchPos.x == 99);
    }
    // Full world path, touchIsInUI != 0: no startTouchPos write; byte passthrough.
    {
        Fixture f;
        f.r.tapCount = 6;
        f.w.startResult = -1;
        f.w.inUIResult = 1;
        f.go({3.5f, -2.25f});
        assert((f.events == std::vector<std::string>{"load", "sim", "start", "ui"}));
        assert(f.r.calls == 1);
        assert(f.w.lastTapCount == 6 && f.w.lastIndex == 0);
        assert(f.w.lastStartPoint.x == 3.5f && f.w.lastStartPoint.y == -2.25f);
        assert(f.w.lastUIPoint.x == 3.5f && f.w.lastUIPoint.y == -2.25f);
        assert(f.st.primaryTouchIsActiveInUI == -1); // signed-char passthrough
        assert(f.st.startTouchHasntMoved == 0);
        assert(f.st.startTouchPos.x == 99 && f.st.startTouchPos.y == 88);
    }
    // touchIsInUI == 0: startTouchHasntMoved=1 and full-word CGPoint store.
    {
        Fixture f;
        f.w.startResult = 1;
        f.w.inUIResult = 0;
        f.go({3.5f, -2.25f});
        assert(f.st.primaryTouchIsActiveInUI == 1);
        assert(f.st.startTouchHasntMoved == 1);
        assert(f.st.startTouchPos.x == 3.5f && f.st.startTouchPos.y == -2.25f);
    }
    // Gate ordering: both byte flags are cleared before loadComplete runs.
    {
        Fixture f;
        f.w.onLoad = [&] {
            assert(f.st.startTouchHasntMoved == 0);
            assert(f.st.primaryTouchIsActiveInUI == 0);
        };
        f.go();
    }
    // Callback mutation: loadComplete nils the world; the original still sends
    // isSimulating/startTouch/touchIsInUI to nil (no callee executed), the
    // result bytes become 0, and the final stores DO execute.
    {
        Fixture f;
        f.w.onLoad = [&] { f.s.world = nullptr; };
        f.go({5, 6});
        assert((f.events == std::vector<std::string>{"load"}));
        assert(f.r.calls == 1); // tapCount is still dispatched after the gates
        assert(f.st.primaryTouchIsActiveInUI == 0);
        assert(f.st.startTouchHasntMoved == 1);
        assert(f.st.startTouchPos.x == 5 && f.st.startTouchPos.y == 6);
    }
    // Raw bit-pattern point survives the full-word store untouched.
    {
        Fixture f;
        const float x = 1.0e-20f, y = -3.0e18f;
        f.go({x, y});
        assert(f.st.startTouchPos.x == x && f.st.startTouchPos.y == y);
    }
    std::cout << "PASS gameview_starttouch menu/world gates, byte stores, "
                 "nil-dispatch chain, callback reload\n";
}
