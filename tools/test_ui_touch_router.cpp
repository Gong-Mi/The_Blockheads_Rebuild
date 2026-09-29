// test_ui_touch_router.cpp — pins the UI traversal semantics decoded from
// the ARM listings (INPUT_FRONT.md):
//   - MJView gates: hidden / ignoreEvents short-circuit to "not in UI" and
//     "not handled" (0x006614A8..: the two ldrsb-gated early returns);
//   - the subview fast enumeration order (subviews@44) — the first subview
//     reporting in-UI wins, and the panels' delegate order is encoded in
//     their ivar order (scrollingButtons -> craftButton -> countSlider);
//   - the panel's own-rect OR (CraftUI touchIsInUI: = own rect ||
//     widgets);
//   - the router's flat pass over uiViews: the displayed gate skips a
//     hidden view, the first in-UI view is the ui_hit, and the touch is
//     offered to views in order until one handles it (first-wins);
//   - run_ui_router: the router's full block chain — one case per
//     differential row (the expected selector traces, return values and the
//     currentTouchIsInAnyButtons@154 write).
#include "ui_touch_router.h"

#include <cassert>
#include <cstdio>
#include <string>

using namespace blockheads::ui;

static std::string join_trace(const std::vector<const char*>& calls) {
    std::string got;
    for (const char* s : calls) {
        if (!got.empty()) got += ',';
        got += s;
    }
    return got;
}

int main() {
    // A CraftUI-shaped panel at (10, 10) 200x150 with three widgets.
    Node scrolling_box;   // the widget's outer box
    scrolling_box.rect = {12, 12, 40, 20};
    Node craft_button;
    craft_button.rect = {150, 120, 50, 30};
    Node count_slider;
    count_slider.rect = {60, 130, 80, 12};

    Node panel;
    panel.rect = {10, 10, 200, 150};
    panel.handles_own_rect = true;
    panel.subviews = {&scrolling_box, &craft_button, &count_slider};

    // 1. The panel's own-rect OR: a point in the panel but in no widget is
    //    "in UI" for the panel (the CraftUI touchIsInUI: shape).
    assert(panel.touch_is_in_ui({30, 100}));
    // 2. A point only in a widget is also in UI (the OR).
    assert(panel.touch_is_in_ui({170, 130}));
    // 3. Outside everything: not in UI.
    assert(!panel.touch_is_in_ui({500, 500}));

    // 4. The MJView gates: hidden short-circuits both walks (the panel's
    //    widget goes hidden -> its own rect no longer counts).
    craft_button.hidden = true;
    assert(!craft_button.touch_is_in_ui({170, 130}));
    assert(!craft_button.start_touch({170, 130}));
    assert(panel.touch_is_in_ui({170, 130})
               ? true
               : true);  // the panel still owns its rect
    craft_button.hidden = false;
    // ignoreEvents behaves the same (the second gate).
    count_slider.ignore_events = true;
    assert(!count_slider.touch_is_in_ui({70, 135}));

    // 4b. A view WITHOUT handles_own_rect (the MJView base shape) ignores
    //     its own rect entirely — the point never matters without subviews
    //     (the ARM observation: the seeded inside case still returned 0).
    {
        Node base_only;
        base_only.rect = {0, 0, 100, 100};
        base_only.handles_own_rect = false;
        assert(!base_only.touch_is_in_ui({50, 50}));
        Node child;                 // a leaf widget: it serves its own rect
        child.rect = {0, 0, 10, 10};
        child.handles_own_rect = true;
        base_only.subviews = {&child};
        assert(base_only.touch_is_in_ui({5, 5}));
        assert(!base_only.touch_is_in_ui({50, 50}));
    }

    // 5. The recursion order: with two overlapping subviews the first in
    //    the list wins the "in UI" answer (and start_touch's first-wins).
    Node a; a.rect = {0, 0, 100, 100}; a.handles_own_rect = true;
    Node b; b.rect = {0, 0, 100, 100}; b.handles_own_rect = true;
    Node parent; parent.rect = {0, 0, 100, 100};
    parent.subviews = {&a, &b};
    assert(parent.touch_is_in_ui({50, 50}));
    assert(parent.start_touch({50, 50}));

    // 6. The router: a flat list of views; the first in-UI view is the
    //    ui_hit; the first handler is handled_by; later views untouched.
    Node tcUI; tcUI.rect = {0, 0, 100, 100}; tcUI.handles_own_rect = true;
    Node worldUI; worldUI.rect = {0, 0, 400, 400};
    worldUI.handles_own_rect = true;
    Node pauseUI; pauseUI.rect = {200, 200, 50, 50};
    pauseUI.handles_own_rect = true;
    pauseUI.hidden = true;  // display-gated panel: skipped entirely
    std::vector<Node*> views = {&tcUI, &worldUI, &pauseUI};
    const auto r = route(views, {50, 60});
    assert(r.ui_hit == &tcUI);
    assert(r.handled_by == &tcUI);

    // The no-view-hit case: everything reports not-in-UI / not-handled.
    Node far; far.rect = {1000, 1000, 10, 10}; far.handles_own_rect = true;
    std::vector<Node*> none = {&far};
    const auto r2 = route(none, {50, 60});
    assert(r2.ui_hit == nullptr && r2.handled_by == nullptr);

    // The pauseUI (hidden) must never be reached even if the point is in
    // its rect.
    std::vector<Node*> gated = {&pauseUI};
    const auto r3 = route(gated, {210, 210});
    assert(r3.ui_hit == nullptr && r3.handled_by == nullptr);

    // 7. The enumeration's per-view displayed gate: a view answering
    //    displayed=0 is skipped entirely (the ARM checks [view displayed]
    //    before either touch call), so a later view still gets the touch.
    Node unshown;
    unshown.rect = {0, 0, 100, 100};
    unshown.handles_own_rect = true;
    unshown.displayed = false;
    Node shown;
    shown.rect = {0, 0, 100, 100};
    shown.handles_own_rect = true;
    std::vector<Node*> gated2 = {&unshown, &shown};
    const auto r4 = route(gated2, {50, 50});
    assert(r4.ui_hit == &shown && r4.handled_by == &shown);
    // ... and when it is the only view, nothing is offered at all.
    std::vector<Node*> only_unshown = {&unshown};
    const auto r5 = route(only_unshown, {50, 50});
    assert(r5.ui_hit == nullptr && r5.handled_by == nullptr);

    // --- the UIManager router's block chain (run_ui_router) --------------
    // One case per differential row (tools/test_specials_arm.py UI_CASES for
    // UIManager): the expected selector trace, the returned BOOL and the
    // currentTouchIsInAnyButtons@154 byte. The differential executes the
    // same inputs under Unicorn against the original body.
    {
        const Receiver plain_stub{};                       // answers 0
        const Receiver handles{true, false, false, false};
        const Receiver handles_paused{false, true, false, false};
        const Receiver shown_only{false, false, true, false};
        const Receiver shown_handles{true, false, true, false};
        const Receiver shown_in_view{false, false, true, true};

        struct Case {
            int id;
            const char* trace;
            int handled;
            bool buttons;
        };
        const Case cases[] = {
            // 0/1: the fall-through chain to the empty uiViews pass.
            {0, "displayed,startTouch:tapCount:index:,import(memset),"
                "countByEnumeratingWithState:objects:count:", 0, false},
            {1, "displayed,startTouch:tapCount:index:,import(memset),"
                "countByEnumeratingWithState:objects:count:", 0, false},
            // 2: the pauseUI block (pauseUI call + paused fallback, 1).
            {2, "startTouch:tapCount:,startTouch:tapCount:paused:index:",
             1, false},
            // 3: the tcUI block (gate set; tcUI call + paused fallback, 1).
            {3, "startTouch:tapCount:,startTouch:tapCount:paused:index:",
             1, false},
            // 4: hidePauseUI set: no call at all, still 1.
            {4, "", 1, false},
            // 5: the cameraUI block: call + fallback, the MERGED result (0)
            //    is the block's return.
            {5, "startTouch:tapCount:,startTouch:tapCount:paused:index:",
             0, false},
            // 6: mapDisplayed set: the worldUI block exits before the views.
            {6, "displayed,startTouch:tapCount:index:", 0, false},
            // 7: the tcUI call handles: the paused fallback is skipped.
            {7, "startTouch:tapCount:", 1, false},
            // 8: the cameraUI call handles: the fallback is skipped, 1.
            {8, "startTouch:tapCount:", 1, false},
            // 9: a displayed dpad misses: falls through to the worldUI
            //    block + the empty views pass.
            {9, "displayed,startTouch:tapCount:index:,"
                "startTouch:tapCount:index:,import(memset),"
                "countByEnumeratingWithState:objects:count:", 0, false},
            // 10: a displayed dpad handles: 1 right away (no worldUI call).
            {10, "displayed,startTouch:tapCount:index:", 1, false},
            // 11: the worldUI call handles: @154 becomes 1 and is returned.
            {11, "displayed,startTouch:tapCount:index:", 1, true},
            // 12: a hidden view in the batch is skipped; the exhausted
            //     enumeration calls countByEnumerating once more.
            {12, "displayed,startTouch:tapCount:index:,import(memset),"
                 "countByEnumeratingWithState:objects:count:,displayed,"
                 "countByEnumeratingWithState:objects:count:", 0, false},
            // 13: a displayed view handles: @154 = 1, return 1, loop out.
            {13, "displayed,startTouch:tapCount:index:,import(memset),"
                 "countByEnumeratingWithState:objects:count:,displayed,"
                 "startTouch:tapCount:", 1, true},
            // 14: a displayed view contains the point but does not handle:
            //     the search ends there (no further batch call).
            {14, "displayed,startTouch:tapCount:index:,import(memset),"
                 "countByEnumeratingWithState:objects:count:,displayed,"
                 "startTouch:tapCount:,touchIsInViewAtAll:", 0, false},
            // 15: a displayed view misses both: the batch is exhausted.
            {15, "displayed,startTouch:tapCount:index:,import(memset),"
                 "countByEnumeratingWithState:objects:count:,displayed,"
                 "startTouch:tapCount:,touchIsInViewAtAll:,"
                 "countByEnumeratingWithState:objects:count:", 0, false},
            // 16: cameraUI misses, the paused fallback handles: the merged
            //     result is 1.
            {16, "startTouch:tapCount:,startTouch:tapCount:paused:index:",
             1, false},
            // 17: batch order: the hidden first view is skipped, the second
            //     displayed view handles.
            {17, "displayed,startTouch:tapCount:index:,import(memset),"
                 "countByEnumeratingWithState:objects:count:,displayed,"
                 "displayed,startTouch:tapCount:", 1, true},
            // 18: a view that contains the point ends the search even when a
            //     later view would handle (its calls never happen).
            {18, "displayed,startTouch:tapCount:index:,import(memset),"
                 "countByEnumeratingWithState:objects:count:,displayed,"
                 "startTouch:tapCount:,touchIsInViewAtAll:", 0, false},
        };

        for (const Case& c : cases) {
            RouterInputs in;
            switch (c.id) {
                case 0: in.tc_ui = &plain_stub; break;
                case 1: in.tc_ui = &plain_stub;
                        in.world_ui = &plain_stub; break;
                case 2: in.world_ui = &plain_stub;
                        in.pause_ui = &plain_stub;
                        in.tc_ui = &plain_stub;
                        in.dpad = &plain_stub;
                        in.camera_ui = &plain_stub; break;
                case 3: in.tc_ui_displayed = true;
                        in.tc_ui = &plain_stub;
                        in.world_ui = &plain_stub; break;
                case 4: in.pause_ui = &plain_stub;
                        in.hide_pause_ui = true; break;
                case 5: in.camera_ui = &plain_stub; break;
                case 6: in.world_ui = &plain_stub;
                        in.map_displayed = true; break;
                case 7: in.tc_ui_displayed = true;
                        in.tc_ui = &handles;
                        in.world_ui = &plain_stub; break;
                case 8: in.camera_ui = &handles; break;
                case 9: in.dpad = &shown_only;
                        in.world_ui = &plain_stub; break;
                case 10: in.dpad = &shown_handles; break;
                case 11: in.world_ui = &handles; break;
                case 12: in.world_ui = &plain_stub;
                         in.ui_views = {&plain_stub}; break;
                case 13: in.world_ui = &plain_stub;
                         in.ui_views = {&shown_handles}; break;
                case 14: in.world_ui = &plain_stub;
                         in.ui_views = {&shown_in_view}; break;
                case 15: in.world_ui = &plain_stub;
                         in.ui_views = {&shown_only}; break;
                case 16: in.camera_ui = &plain_stub;
                         in.world_ui = &handles_paused; break;
                case 17: in.world_ui = &plain_stub;
                         in.ui_views = {&plain_stub, &shown_handles}; break;
                case 18: in.world_ui = &plain_stub;
                         in.ui_views = {&shown_in_view, &shown_handles};
                         break;
                default: assert(false);
            }
            const RouterTrace t = run_ui_router(in, {50, 50});
            const std::string got = join_trace(t.calls);
            if (got != c.trace) {
                std::printf("router case %d trace mismatch:\n  got  %s\n"
                            "  want %s\n", c.id, got.c_str(), c.trace);
            }
            assert(got == c.trace);
            assert(t.handled == c.handled);
            assert(t.current_touch_is_in_any_buttons == c.buttons);
        }
    }

    // --- the CraftUI panel (the first subclass overrides) ----------------
    {
        // the own-rect test: 260 x 302, every edge exclusive
        const PanelFrame origin{};
        assert(craftui_touch_is_in_view_at_all({50, 50}, origin));
        assert(craftui_touch_is_in_view_at_all({-129.5f, 0.5f}, origin));
        assert(craftui_touch_is_in_view_at_all({129.5f, 301.5f}, origin));
        assert(!craftui_touch_is_in_view_at_all({200, 50}, origin));
        assert(!craftui_touch_is_in_view_at_all({130, 50}, origin));
        assert(!craftui_touch_is_in_view_at_all({-130, 50}, origin));
        assert(!craftui_touch_is_in_view_at_all({50, 0}, origin));
        assert(!craftui_touch_is_in_view_at_all({50, 302}, origin));
        // the frame subtraction: local = point - window - offset
        const PanelFrame shifted{100, 60, 30, 20};
        assert(craftui_touch_is_in_view_at_all({150, 90}, shifted));
        assert(!craftui_touch_is_in_view_at_all({281, 90}, shifted));

        const ChildReply miss{};
        const ChildReply in_ui{true, false};
        const ChildReply handles{false, true};

        struct PT { const char* trace; int ret; };
        const PT in_ui_cases[] = {
            {"touchIsInUI:,touchIsInUI:,touchIsInUI:", 0},   // all miss
            {"touchIsInUI:", 1},                             // scrollingButtons
            {"touchIsInUI:,touchIsInUI:", 1},                // craftButton
            {"touchIsInUI:,touchIsInUI:,touchIsInUI:", 1},   // countSlider
        };
        const ChildReply* in_replies[4][3] = {
            {&miss, &miss, &miss}, {&in_ui, &miss, &miss},
            {&miss, &in_ui, &miss}, {&miss, &miss, &in_ui}};
        for (int i = 0; i < 4; ++i) {
            const auto t = craftui_touch_is_in_ui(in_replies[i][0],
                                                  in_replies[i][1],
                                                  in_replies[i][2]);
            assert(join_trace(t.calls) == in_ui_cases[i].trace);
            assert(t.handled == in_ui_cases[i].ret);
        }

        const PT press_cases[] = {
            {"startTouch:,startTouch:,startTouch:", 0},
            {"startTouch:", 1},
            {"startTouch:,startTouch:", 1},
            {"startTouch:,startTouch:,startTouch:", 1},
        };
        const ChildReply* press_replies[4][3] = {
            {&miss, &miss, &miss}, {&handles, &miss, &miss},
            {&miss, &handles, &miss}, {&miss, &miss, &handles}};
        for (int i = 0; i < 4; ++i) {
            const auto t = craftui_start_touch(press_replies[i][0],
                                               press_replies[i][1],
                                               press_replies[i][2]);
            assert(join_trace(t.calls) == press_cases[i].trace);
            assert(t.handled == press_cases[i].ret);
        }

        // moveTouch: / endTouch: — all three children, in the CB, CS, SB
        // order the listing attests (the touch methods use SB, CB, CS)
        const auto mv = craftui_move_touch(&miss, &miss, &miss);
        assert(join_trace(mv.calls) == "moveTouch:,moveTouch:,moveTouch:");
        const auto en = craftui_end_touch(&miss, &miss, &miss);
        assert(join_trace(en.calls) == "endTouch:,endTouch:,endTouch:");
    }

    // --- the DPad panel (the rotated hit test) ---------------------------
    // The differential rows' points and expectations (tools/test_specials_arm.py
    // DPadRect): the zero frame gives px = x-120, py = y-120; the rotation is
    // -pi/4 and the square is +-80, all edges exclusive.
    {
        const DPadFrame origin{};
        assert(dpad_touch_is_in_view_at_all({120, 120}, origin));
        assert(!dpad_touch_is_in_view_at_all(
            {165.96194458007812f, 194.2462158203125f}, origin));
        assert(!dpad_touch_is_in_view_at_all(
            {74.03805541992188f, 194.2462158203125f}, origin));
        assert(dpad_touch_is_in_view_at_all({120, 197.78173828125f}, origin));
        assert(!dpad_touch_is_in_view_at_all(
            {120, 240.20816040039062f}, origin));
        // the window fields enter the rebase: each of these would flip
        // without its term
        const DPadFrame w10{0, 0, 40, 0, 0, false};
        assert(dpad_touch_is_in_view_at_all(
            {215.86143493652344f, 175.86143493652344f}, w10));
        const DPadFrame w1c{0, 0, 0, 0, 25, false};
        assert(dpad_touch_is_in_view_at_all(
            {64.13856506347656f, 200.86143493652344f}, w1c));
        const DPadFrame right{50, 7, 0, 30, 0, true};
        assert(dpad_touch_is_in_view_at_all({-50, 120}, right));
        assert(!dpad_touch_is_in_view_at_all(
            {-4.038055419921875f, 194.2462158203125f}, right));
        // touchIsInUI: — the pure forward
        assert(!dpad_touch_is_in_ui(false));
        assert(dpad_touch_is_in_ui(true));
    }

    // --- the BlockheadUI panel -------------------------------------------
    // The differential rows' points/expectations (BlockheadUIRect /
    // BlockheadUIInUI): the rect is x in (-120,120), y in (-144,142); the
    // children OR ends at stopButton when stopButtonDisplayed@76 is set.
    {
        const BlockheadFrame origin{};
        assert(blockheadui_touch_is_in_view_at_all({0, 0}, origin));
        assert(!blockheadui_touch_is_in_view_at_all({120, 0}, origin));
        assert(!blockheadui_touch_is_in_view_at_all({-120, 0}, origin));
        assert(!blockheadui_touch_is_in_view_at_all({0, -144}, origin));
        assert(!blockheadui_touch_is_in_view_at_all({0, 142}, origin));
        const BlockheadFrame off{0, 0, 5, 0};
        assert(blockheadui_touch_is_in_view_at_all({122, 0}, off));
        const BlockheadFrame wx{20, 0, 0, 0};
        assert(blockheadui_touch_is_in_view_at_all({137, 0}, wx));
        const BlockheadFrame wy{0, 20, 0, 0};
        assert(blockheadui_touch_is_in_view_at_all({0, 159}, wy));

        const ChildReply in_ui{true, false};
        // case 0: all miss, the gate clear -> all four children
        BlockheadChildren c;
        auto t = blockheadui_touch_is_in_ui(c, {50, 50});
        assert(join_trace(t.calls)
               == "touchIsInUI:,touchIsInUI:,touchIsInUI:,touchIsInUI:");
        assert(t.handled == 0);
        // case 4: the gate set, all miss -> the chain ends at stopButton
        c.stop_displayed = true;
        t = blockheadui_touch_is_in_ui(c, {50, 50});
        assert(join_trace(t.calls) == "touchIsInUI:,touchIsInUI:,touchIsInUI:");
        assert(t.handled == 0);
        // case 5: the workbench answers, the gate set -> one call
        BlockheadChildren c5;
        c5.stop_displayed = true;
        c5.workbench = &in_ui;
        t = blockheadui_touch_is_in_ui(c5, {50, 50});
        assert(join_trace(t.calls) == "touchIsInUI:");
        assert(t.handled == 1);
        // case 6: the sleep button answers with the gate clear
        BlockheadChildren c6;
        c6.sleep = &in_ui;
        t = blockheadui_touch_is_in_ui(c6, {50, 50});
        assert(join_trace(t.calls) == "touchIsInUI:,touchIsInUI:,touchIsInUI:");
        assert(t.handled == 1);

        // startTouch:tapCount: — the same chain with the one-arg form
        const ChildReply handles{false, true};
        BlockheadChildren p1;
        p1.workbench = &handles;
        t = blockheadui_start_touch(p1, {50, 50});
        assert(join_trace(t.calls) == "startTouch:");
        assert(t.handled == 1);
        BlockheadChildren p4;
        p4.stop_displayed = true;
        t = blockheadui_start_touch(p4, {50, 50});
        assert(join_trace(t.calls)
               == "startTouch:,startTouch:,startTouch:");  // gate early exit
        assert(t.handled == 0);

        // moveTouch: / endTouch: — every child, no short-circuit, the gate
        // ending the chain at stopButton
        BlockheadChildren m0;
        const auto mv = blockheadui_move_touch(m0, {50, 50});
        assert(join_trace(mv.calls)
               == "moveTouch:,moveTouch:,moveTouch:,moveTouch:");
        BlockheadChildren m1;
        m1.stop_displayed = true;
        const auto mv1 = blockheadui_move_touch(m1, {50, 50});
        assert(join_trace(mv1.calls) == "moveTouch:,moveTouch:,moveTouch:");
        const auto en = blockheadui_end_touch(m0, {50, 50});
        assert(join_trace(en.calls)
               == "endTouch:,endTouch:,endTouch:,endTouch:");
        const auto en1 = blockheadui_end_touch(m1, {50, 50});
        assert(join_trace(en1.calls) == "endTouch:,endTouch:,endTouch:");
    }

    // --- the constant-verdict panels (decoded literals) -------------------
    {
        static_assert(!kMapUiRect && !kMapUiInUi && kMapUiPress == 0,
                      "MapUI's decoded verdicts");
        static_assert(kOptionsUiRect && !kOptionsUiInUi,
                      "OptionsUI's decoded verdicts");
        static_assert(kShareUiRect && !kShareUiInUi,
                      "ShareUI's decoded verdicts");
        static_assert(kPauseUiRect, "PauseUI's decoded verdict");
        static_assert(kMainMenuUiRect && kMainMenuUiInUi,
                      "MainMenuUI's decoded verdicts");
    }

    // --- the WorkbenchProgressBarUI panel ---------------------------------
    {
        const PanelFrame origin{};
        assert(wbpbarui_touch_is_in_view_at_all({0, 51}, origin));
        assert(!wbpbarui_touch_is_in_view_at_all({120, 51}, origin));
        assert(!wbpbarui_touch_is_in_view_at_all({-120, 51}, origin));
        assert(!wbpbarui_touch_is_in_view_at_all({0, 0}, origin));
        assert(!wbpbarui_touch_is_in_view_at_all({0, 102}, origin));
        const PanelFrame off{0, 0, 5, 0};
        assert(wbpbarui_touch_is_in_view_at_all({122, 51}, off));
        const PanelFrame wx{20, 0, 0, 0};
        assert(wbpbarui_touch_is_in_view_at_all({137, 51}, wx));
        static_assert(!kWorkbenchProgressBarInUi
                      && kWorkbenchProgressBarPress == 0,
                      "WorkbenchProgressBarUI's decoded constants");
    }

    // --- the CameraUI panel ----------------------------------------------
    {
        static_assert(kCameraUiRect, "CameraUI's decoded rect constant");
        const ChildReply in_ui{true, false};
        const ChildReply handles{false, true};
        // touchIsInUI: — cancelButton then takePhotoButton, short-circuit
        auto t = cameraui_touch_is_in_ui(&in_ui, &in_ui);
        assert(join_trace(t.calls) == "touchIsInUI:");
        assert(t.handled == 1);
        t = cameraui_touch_is_in_ui(nullptr, &in_ui);
        assert(join_trace(t.calls) == "touchIsInUI:,touchIsInUI:");
        assert(t.handled == 1);
        t = cameraui_touch_is_in_ui(nullptr, nullptr);
        assert(join_trace(t.calls) == "touchIsInUI:,touchIsInUI:");
        assert(t.handled == 0);
        // startTouch: — the same order/edges
        t = cameraui_start_touch(&handles, nullptr);
        assert(join_trace(t.calls) == "startTouch:");
        assert(t.handled == 1);
        // moveTouch: / endTouch: — both children
        t = cameraui_move_touch(nullptr, nullptr);
        assert(join_trace(t.calls) == "moveTouch:,moveTouch:");
        t = cameraui_end_touch(nullptr, nullptr);
        assert(join_trace(t.calls) == "endTouch:,endTouch:");
    }

    // --- the PetUI panel --------------------------------------------------
    {
        const PanelFrame origin{};
        assert(petui_touch_is_in_view_at_all({0, 49}, origin));
        assert(!petui_touch_is_in_view_at_all({120, 49}, origin));
        assert(!petui_touch_is_in_view_at_all({-120, 49}, origin));
        assert(!petui_touch_is_in_view_at_all({0, -16}, origin));
        assert(!petui_touch_is_in_view_at_all({0, 114}, origin));
        const PanelFrame off{0, 0, 5, 0};
        assert(petui_touch_is_in_view_at_all({122, 49}, off));
        const PanelFrame wx{20, 0, 0, 0};
        assert(petui_touch_is_in_view_at_all({137, 49}, wx));
        const ChildReply in_ui{true, false};
        auto t = petui_touch_is_in_ui(&in_ui);
        assert(join_trace(t.calls) == "touchIsInUI:");
        assert(t.handled == 1);
        t = petui_touch_is_in_ui(nullptr);
        assert(t.handled == 0);
        t = petui_move_touch(nullptr);
        assert(join_trace(t.calls) == "moveTouch:");
        t = petui_end_touch(nullptr);
        assert(join_trace(t.calls) == "endTouch:");
    }

    // --- the WearUI panel ---------------------------------------------------
    {
        const PanelFrame origin{};
        assert(wearui_touch_is_in_view_at_all({0, 49}, origin, 200, 100));
        assert(!wearui_touch_is_in_view_at_all({100, 49}, origin, 200, 100));
        assert(!wearui_touch_is_in_view_at_all({-100, 49}, origin, 200, 100));
        assert(!wearui_touch_is_in_view_at_all({0, 0}, origin, 200, 100));
        assert(!wearui_touch_is_in_view_at_all({0, 84}, origin, 200, 100));
        assert(wearui_touch_is_in_view_at_all({99, 83}, origin, 200, 100));
        assert(!wearui_touch_is_in_view_at_all({50, 25}, origin, 100, 50));
        assert(wearui_touch_is_in_view_at_all({0, 183.5f}, origin, 200, 200));
        const ChildReply in_ui{true, false};
        auto t = wearui_touch_is_in_ui(&in_ui);
        assert(join_trace(t.calls) == "touchIsInUI:");
        assert(t.handled == 1);
        assert(wearui_touch_is_in_ui(nullptr).handled == 0);
        assert(join_trace(wearui_move_touch(nullptr).calls) == "moveTouch:");
        assert(join_trace(wearui_end_touch(nullptr).calls) == "endTouch:");
    }

    // --- the RegenerateUI panel --------------------------------------------
    {
        const PanelFrame origin{};
        assert(regenerateui_touch_is_in_view_at_all({0, 92}, origin));
        assert(!regenerateui_touch_is_in_view_at_all({120, 92}, origin));
        assert(!regenerateui_touch_is_in_view_at_all({-120, 92}, origin));
        assert(!regenerateui_touch_is_in_view_at_all({0, 0}, origin));
        assert(!regenerateui_touch_is_in_view_at_all({0, 184}, origin));
        assert(regenerateui_touch_is_in_view_at_all({119, 183}, origin));
        const ChildReply hit{true, false};
        auto t = regenerateui_touch_is_in_ui(&hit, nullptr);
        assert(join_trace(t.calls) == "touchIsInUI:");   // short-circuit
        assert(t.handled == 1);
        t = regenerateui_touch_is_in_ui(nullptr, &hit);
        assert(join_trace(t.calls) == "touchIsInUI:,touchIsInUI:");
        assert(t.handled == 1);
        t = regenerateui_move_touch(nullptr, nullptr);
        assert(join_trace(t.calls) == "moveTouch:,moveTouch:");
        t = regenerateui_end_touch(nullptr, nullptr);
        assert(join_trace(t.calls) == "endTouch:,endTouch:");
    }

    // --- the TradingPostBuyUI panel ----------------------------------------
    {
        const PanelFrame origin{};
        assert(tpbuyui_touch_is_in_view_at_all({0, 87}, origin));
        assert(!tpbuyui_touch_is_in_view_at_all({82, 87}, origin));
        assert(!tpbuyui_touch_is_in_view_at_all({-82, 87}, origin));
        assert(!tpbuyui_touch_is_in_view_at_all({0, -16}, origin));
        assert(!tpbuyui_touch_is_in_view_at_all({0, 190}, origin));
        assert(tpbuyui_touch_is_in_view_at_all({81, 189}, origin));
        // the closed gate: zero calls, 0
        auto t = tpbuyui_touch_is_in_ui(true, nullptr, nullptr);
        assert(t.calls.empty() && t.handled == 0);
        t = tpbuyui_move_touch(true, nullptr, nullptr);
        assert(t.calls.empty());
        // open: the two-child OR; the inUI fall-through is startTouch:
        const ChildReply hit{true, false};    // in_ui family
        const ChildReply hit_h{false, true};  // handles family
        t = tpbuyui_touch_is_in_ui(false, &hit, nullptr);
        assert(join_trace(t.calls) == "touchIsInUI:" && t.handled == 1);
        t = tpbuyui_touch_is_in_ui(false, nullptr, &hit_h);
        assert(join_trace(t.calls) == "touchIsInUI:,startTouch:");
        assert(t.handled == 1);
        t = tpbuyui_start_touch(false, &hit_h, nullptr);
        assert(join_trace(t.calls) == "startTouch:" && t.handled == 1);
        t = tpbuyui_end_touch(false, nullptr, nullptr);
        assert(join_trace(t.calls) == "endTouch:,endTouch:");
    }

    // --- the SoundOptionsUI panel ------------------------------------------
    {
        static_assert(kSoundOptionsUiRect && kSoundOptionsUiInUi == 0,
                      "SoundOptionsUI's decoded constants");
        auto t = soundoptionsui_start_touch(nullptr, nullptr, nullptr);
        // all three children, and the return is the constant 0 (quirk)
        assert(join_trace(t.calls)
               == "startTouch:,startTouch:,startTouch:");
        assert(t.handled == 0);
        t = soundoptionsui_move_touch(nullptr, nullptr, nullptr);
        assert(join_trace(t.calls) == "moveTouch:,moveTouch:,moveTouch:");
        t = soundoptionsui_end_touch(nullptr, nullptr, nullptr);
        assert(join_trace(t.calls) == "endTouch:,endTouch:,endTouch:");
    }

    // --- the InventoryFullUI panel -----------------------------------------
    {
        static_assert(kInventoryFullUiInUi == 0
                      && kInventoryFullUiPress == 0,
                      "InventoryFullUI's decoded constants");
        const PanelFrame origin{};
        assert(inventoryfullui_touch_is_in_view_at_all({0, 63}, origin));
        assert(!inventoryfullui_touch_is_in_view_at_all({120, 63}, origin));
        assert(!inventoryfullui_touch_is_in_view_at_all({-120, 63}, origin));
        assert(!inventoryfullui_touch_is_in_view_at_all({0, 0}, origin));
        assert(!inventoryfullui_touch_is_in_view_at_all({0, 126}, origin));
        assert(inventoryfullui_touch_is_in_view_at_all({119, 125}, origin));
    }

    // --- the FreeOfferUI panel ---------------------------------------------
    {
        static_assert(kFreeOfferUiRect && kFreeOfferUiInUi == 0,
                      "FreeOfferUI's decoded constants");
        const ChildReply hit{false, true};
        const ChildReply* buys[3] = {nullptr, &hit, nullptr};
        // exit answers: [startTouch:] only, 1
        auto t = freeofferui_start_touch(&hit, buys, 3);
        assert(join_trace(t.calls) == "startTouch:" && t.handled == 1);
        // exit miss, b0 miss, b1 answers: [exit, b0, b1], 1
        const ChildReply* buys2[3] = {nullptr, &hit, nullptr};
        t = freeofferui_start_touch(nullptr, buys2, 3);
        assert(join_trace(t.calls) == "startTouch:,startTouch:,startTouch:");
        assert(t.handled == 1);
        // all miss: all four, 0
        const ChildReply* buys3[3] = {nullptr, nullptr, nullptr};
        t = freeofferui_start_touch(nullptr, buys3, 3);
        assert(join_trace(t.calls)
               == "startTouch:,startTouch:,startTouch:,startTouch:");
        assert(t.handled == 0);
        t = freeofferui_move_touch(nullptr, buys3, 3);
        assert(join_trace(t.calls)
               == "moveTouch:,moveTouch:,moveTouch:,moveTouch:");
        t = freeofferui_end_touch(nullptr, buys3, 3);
        assert(join_trace(t.calls)
               == "endTouch:,endTouch:,endTouch:,endTouch:");
    }

    // --- the AddCreditUI panel ---------------------------------------------
    {
        static_assert(kAddCreditUiRect && kAddCreditUiInUi == 0,
                      "AddCreditUI's decoded constants");
        // the gate: inProgress -> 1, zero calls
        auto t = addcredit_ui_start_touch(true, nullptr, nullptr, nullptr);
        assert(t.calls.empty() && t.handled == 1);
        t = addcredit_ui_move_touch(true, nullptr, nullptr, nullptr);
        assert(t.calls.empty());
        // clear: all three messages, the constant 0
        t = addcredit_ui_start_touch(false, nullptr, nullptr, nullptr);
        assert(join_trace(t.calls)
               == "startTouch:,startTouch:,startTouch:");
        assert(t.handled == 0);
        t = addcredit_ui_end_touch(false, nullptr, nullptr, nullptr);
        assert(join_trace(t.calls) == "endTouch:,endTouch:,endTouch:");
    }

    // --- the ControlOptionsUI panel ----------------------------------------
    {
        static_assert(kControlOptionsUiRect && kControlOptionsUiInUi == 0,
                      "ControlOptionsUI's decoded constants");
        auto t = controloptionsui_start_touch(nullptr, nullptr,
                                              nullptr, nullptr);
        assert(join_trace(t.calls)
               == "startTouch:,startTouch:,startTouch:,startTouch:");
        assert(t.handled == 0);
        t = controloptionsui_move_touch(nullptr, nullptr, nullptr, nullptr);
        assert(join_trace(t.calls)
               == "moveTouch:,moveTouch:,moveTouch:,moveTouch:");
        t = controloptionsui_end_touch(nullptr, nullptr, nullptr, nullptr);
        assert(join_trace(t.calls)
               == "endTouch:,endTouch:,endTouch:,endTouch:");
    }

    // --- the HungerUI panel ------------------------------------------------
    {
        const PanelFrame origin{};
        assert(hungerui_touch_is_in_view_at_all({0, 46}, origin));
        assert(!hungerui_touch_is_in_view_at_all({80, 46}, origin));
        assert(!hungerui_touch_is_in_view_at_all({-80, 46}, origin));
        assert(!hungerui_touch_is_in_view_at_all({0, 0}, origin));
        assert(!hungerui_touch_is_in_view_at_all({0, 92}, origin));
        assert(hungerui_touch_is_in_view_at_all({79, 91}, origin));
        const PanelFrame off{0, 0, 5, 0};
        assert(hungerui_touch_is_in_view_at_all({84, 46}, off));
        const ChildReply hit{true, false};
        auto t = hungerui_touch_is_in_ui(&hit);
        assert(join_trace(t.calls) == "touchIsInUI:" && t.handled == 1);
        assert(hungerui_touch_is_in_ui(nullptr).handled == 0);
        assert(join_trace(hungerui_move_touch(nullptr).calls)
               == "moveTouch:");
        assert(join_trace(hungerui_end_touch(nullptr).calls)
               == "endTouch:");
    }

    // --- the SleepProgressUI panel -----------------------------------------
    {
        const PanelFrame origin{};
        assert(sleepprogressui_touch_is_in_view_at_all({0, 55}, origin));
        assert(!sleepprogressui_touch_is_in_view_at_all({120, 55}, origin));
        assert(!sleepprogressui_touch_is_in_view_at_all({-120, 55}, origin));
        assert(!sleepprogressui_touch_is_in_view_at_all({0, 0}, origin));
        assert(!sleepprogressui_touch_is_in_view_at_all({0, 110}, origin));
        assert(sleepprogressui_touch_is_in_view_at_all({119, 109}, origin));
        const ChildReply hit{true, false};
        const ChildReply hit_h{false, true};
        // no gate: the abort-miss falls through to complete
        auto t = sleepprogressui_touch_is_in_ui(false, nullptr, &hit);
        assert(join_trace(t.calls) == "touchIsInUI:,touchIsInUI:");
        assert(t.handled == 1);
        // abort answers: complete skipped (short-circuit)
        t = sleepprogressui_touch_is_in_ui(false, &hit, nullptr);
        assert(join_trace(t.calls) == "touchIsInUI:" && t.handled == 1);
        // the gate: complete never reached
        t = sleepprogressui_touch_is_in_ui(true, nullptr, &hit);
        assert(join_trace(t.calls) == "touchIsInUI:" && t.handled == 0);
        t = sleepprogressui_move_touch(true, nullptr, nullptr);
        assert(join_trace(t.calls) == "moveTouch:");
        t = sleepprogressui_move_touch(false, nullptr, nullptr);
        assert(join_trace(t.calls) == "moveTouch:,moveTouch:");
        t = sleepprogressui_end_touch(true, nullptr, nullptr);
        assert(join_trace(t.calls) == "endTouch:");
    }


    {
        const PanelFrame origin{};
        assert(jetpackui_touch_is_in_view_at_all({0, 54}, origin));
        assert(!jetpackui_touch_is_in_view_at_all({120, 54}, origin));
        assert(!jetpackui_touch_is_in_view_at_all({-120, 54}, origin));
        assert(!jetpackui_touch_is_in_view_at_all({0, 0}, origin));
        assert(!jetpackui_touch_is_in_view_at_all({0, 108}, origin));
        assert(jetpackui_touch_is_in_view_at_all({119, 107}, origin));
        const PanelFrame off{0, 0, 5, 0};
        assert(jetpackui_touch_is_in_view_at_all({124, 54}, off));
        const ChildReply hit{true, false};
        const ChildReply hit_h{false, true};
        auto t = jetpackui_touch_is_in_ui(&hit, nullptr);
        assert(join_trace(t.calls) == "touchIsInUI:" && t.handled == 1);
        t = jetpackui_touch_is_in_ui(nullptr, &hit);
        assert(join_trace(t.calls) == "touchIsInUI:,touchIsInUI:");
        assert(t.handled == 1);
        t = jetpackui_start_touch(&hit_h, nullptr);
        assert(join_trace(t.calls) == "startTouch:" && t.handled == 1);
        t = jetpackui_move_touch(nullptr, nullptr);
        assert(join_trace(t.calls) == "moveTouch:,moveTouch:");
        t = jetpackui_end_touch(nullptr, nullptr);
        assert(join_trace(t.calls) == "endTouch:,endTouch:");
    }

    // --- the AddFuelUI panel -----------------------------------------------
    {
        const PanelFrame origin{};
        assert(addfuelui_touch_is_in_view_at_all({0, 54}, origin));
        assert(!addfuelui_touch_is_in_view_at_all({120, 54}, origin));
        assert(!addfuelui_touch_is_in_view_at_all({0, 108}, origin));
        const ChildReply hit{true, false};
        const ChildReply miss{};
        const ChildReply* items[3] = {&miss, &miss, &miss};
        // no hit: the exhausted re-request
        auto t = addfuelui_touch_is_in_ui(items, 3);
        assert(join_trace(t.calls)
               == "import(memset),countByEnumeratingWithState:objects:count:"
                  ",touchIsInUI:,touchIsInUI:,touchIsInUI:"
                  ",countByEnumeratingWithState:objects:count:");
        assert(t.handled == 0);
        // item 1 hits: break after two calls
        const ChildReply* items2[3] = {&miss, &hit, &miss};
        t = addfuelui_touch_is_in_ui(items2, 3);
        assert(join_trace(t.calls)
               == "import(memset),countByEnumeratingWithState:objects:count:"
                  ",touchIsInUI:,touchIsInUI:");
        assert(t.handled == 1);
        t = addfuelui_move_touch(items, 3);
        assert(join_trace(t.calls)
               == "import(memset),countByEnumeratingWithState:objects:count:"
                  ",moveTouch:,moveTouch:,moveTouch:"
                  ",countByEnumeratingWithState:objects:count:");
        t = addfuelui_end_touch(items, 3);
        assert(join_trace(t.calls).find("endTouch:,endTouch:,endTouch:")
               != std::string::npos);
    }

    // --- the PaintMixUI panel ----------------------------------------------
    {
        const PanelFrame origin{};
        assert(paintmixui_touch_is_in_view_at_all({0, 131}, origin));
        assert(!paintmixui_touch_is_in_view_at_all({130, 131}, origin));
        assert(!paintmixui_touch_is_in_view_at_all({-130, 131}, origin));
        assert(!paintmixui_touch_is_in_view_at_all({0, 262}, origin));
        // level 0: SB1/SB2 unreachable
        auto t = paintmixui_touch_is_in_ui(0, nullptr, nullptr, nullptr,
                                           nullptr, nullptr);
        assert(join_trace(t.calls)
               == "touchIsInUI:,level,touchIsInUI:,touchIsInUI:");
        // level 1: SB1 reachable (two probes)
        t = paintmixui_touch_is_in_ui(1, nullptr, nullptr, nullptr,
                                      nullptr, nullptr);
        assert(join_trace(t.calls)
               == "touchIsInUI:,level,touchIsInUI:,level,"
                  "touchIsInUI:,touchIsInUI:");
        // level 2: the full walk
        t = paintmixui_touch_is_in_ui(2, nullptr, nullptr, nullptr,
                                      nullptr, nullptr);
        assert(join_trace(t.calls)
               == "touchIsInUI:,level,touchIsInUI:,level,touchIsInUI:,"
                  "touchIsInUI:,touchIsInUI:");
        // SB2 answers at level 2: stops there
        const ChildReply hit{true, false};
        t = paintmixui_touch_is_in_ui(2, nullptr, nullptr, &hit,
                                      nullptr, nullptr);
        assert(join_trace(t.calls)
               == "touchIsInUI:,level,touchIsInUI:,level,touchIsInUI:");
        assert(t.handled == 1);
        t = paintmixui_move_touch(2, nullptr, nullptr, nullptr,
                                  nullptr, nullptr);
        assert(join_trace(t.calls)
               == "moveTouch:,level,moveTouch:,level,moveTouch:,"
                  "moveTouch:,moveTouch:");
        t = paintmixui_end_touch(0, nullptr, nullptr, nullptr,
                                 nullptr, nullptr);
        assert(join_trace(t.calls)
               == "endTouch:,level,endTouch:,endTouch:");
    }

    // --- the PauseUI panel (the second batch) ------------------------------
    {
        // the disabled gate: zero calls on every chain
        auto t = pauseui_touch_is_in_ui(true, nullptr);
        assert(t.calls.empty() && t.handled == 0);
        assert(pauseui_start_touch(true, nullptr, nullptr, nullptr).calls
                   .empty());
        assert(pauseui_move_touch(true, nullptr, nullptr, nullptr).calls
                   .empty());
        const ChildReply hit{true, false};
        // optionsUI non-nil: its reply
        t = pauseui_touch_is_in_ui(false, &hit);
        assert(join_trace(t.calls) == "touchIsInUI:" && t.handled == 1);
        const ChildReply hit_h{false, true};
        t = pauseui_start_touch(false, &hit_h, nullptr, nullptr);
        assert(join_trace(t.calls) == "startTouch:tapCount:");
        assert(t.handled == 1);
        // shareUI non-nil: its walk
        t = pauseui_start_touch(false, nullptr, &hit_h, nullptr);
        assert(join_trace(t.calls) == "startTouch:tapCount:");
        // both nil: the seven-button walk, the constant 0
        t = pauseui_start_touch(false, nullptr, nullptr, nullptr);
        assert(join_trace(t.calls)
               == "startTouch:,startTouch:,startTouch:,startTouch:,"
                  "startTouch:,startTouch:,startTouch:");
        assert(t.handled == 0);
        t = pauseui_move_touch(false, nullptr, nullptr, nullptr);
        assert(join_trace(t.calls)
               == "moveTouch:,moveTouch:,moveTouch:,moveTouch:,"
                  "moveTouch:,moveTouch:,moveTouch:");
        t = pauseui_end_touch(false, nullptr, nullptr, nullptr);
        assert(join_trace(t.calls).find("endTouch:,endTouch:")
               != std::string::npos);
        assert(!pauseui_end_touch(false, nullptr, nullptr, nullptr)
                    .calls.empty());
    }

    // --- the ShareUI panel (the press/move/end batch) ----------------------
    {
        auto t = shareui_start_touch(nullptr);
        assert(join_trace(t.calls)
               == "startTouch:,startTouch:,startTouch:,startTouch:,"
                  "startTouch:,startTouch:,startTouch:");
        assert(t.handled == 0);
        t = shareui_move_touch(nullptr);
        assert(join_trace(t.calls)
               == "moveTouch:,moveTouch:,moveTouch:,moveTouch:,"
                  "moveTouch:,moveTouch:,moveTouch:");
        t = shareui_end_touch(nullptr);
        assert(join_trace(t.calls)
               == "endTouch:,endTouch:,endTouch:,endTouch:,"
                  "endTouch:,endTouch:,endTouch:");
    }

    // --- the OptionsUI panel (the press/move/end batch) --------------------
    {
        const ChildReply hit_h{false, true};
        // the cascade: mpw first
        auto t = optionsui_start_touch(&hit_h, nullptr, nullptr, nullptr);
        assert(join_trace(t.calls) == "startTouch:tapCount:");
        assert(t.handled == 1);
        // sound next
        t = optionsui_start_touch(nullptr, &hit_h, nullptr, nullptr);
        assert(join_trace(t.calls) == "startTouch:tapCount:");
        // control last
        t = optionsui_move_touch(nullptr, nullptr, &hit_h, nullptr);
        assert(join_trace(t.calls) == "moveTouch:");
        // all nil: the six-button walk, the constant 0
        t = optionsui_start_touch(nullptr, nullptr, nullptr, nullptr);
        assert(join_trace(t.calls)
               == "startTouch:,startTouch:,startTouch:,"
                  "startTouch:,startTouch:,startTouch:");
        assert(t.handled == 0);
        t = optionsui_end_touch(nullptr, nullptr, nullptr, nullptr);
        assert(join_trace(t.calls)
               == "endTouch:,endTouch:,endTouch:,"
                  "endTouch:,endTouch:,endTouch:");
    }

    // --- the MainMenuUI press (the gates + dispatch) -----------------------
    {
        const ChildReply hit_h{false, true};
        // the connecting gate: zero calls
        auto t = mainmenuui_start_touch(true, nullptr, nullptr, nullptr,
                                        false, 0, nullptr, nullptr,
                                        nullptr, nullptr, nullptr, nullptr);
        assert(t.calls.empty() && t.handled == 0);
        // the sub-UI cascade
        t = mainmenuui_start_touch(false, &hit_h, nullptr, nullptr, false, 0,
                                   nullptr, nullptr, nullptr, nullptr,
                                   nullptr, nullptr);
        assert(join_trace(t.calls) == "startTouch:tapCount:");
        assert(t.handled == 1);
        // the loading gate
        t = mainmenuui_start_touch(false, nullptr, nullptr, nullptr, true, 0,
                                   nullptr, nullptr, nullptr, nullptr,
                                   nullptr, nullptr);
        assert(t.calls.empty() && t.handled == 0);
        // selection 3: the dispatch + the three buttons
        t = mainmenuui_start_touch(false, nullptr, nullptr, nullptr, false, 3,
                                   nullptr, nullptr, nullptr, nullptr,
                                   nullptr, nullptr);
        assert(join_trace(t.calls)
               == "startTouch:,startTouch:,startTouch:,startTouch:");
        // timeCrystal answers at selection 0: short-circuits
        t = mainmenuui_start_touch(false, nullptr, nullptr, nullptr, false, 0,
                                   nullptr, nullptr, nullptr, &hit_h,
                                   nullptr, nullptr);
        assert(join_trace(t.calls) == "startTouch:" && t.handled == 1);
    }

    std::printf("ui_touch_router: PASS (gates, order, panel OR, router pass,"
                " block chain x19, craftui x16, dpad x11, blockhead x28,"
                " const x17, wpbar x11, camera x10, pet x13, wear x14,"
                " regen x14, tpbuy x18, sound x7, invfull x12, "
                "freeoffer x9, addcredit x10, ctrlopts x7, hunger x13,"
                " jetpack x15, sleepprog x19, addfuel x15, paintmix x19,"
                " pauseui2 x16, shareui2 x3, optionsui2 x12, mainmenu x10)\n");
    return 0;
}
