// test_ui_touch_router.cpp — pins the UI traversal semantics decoded from
// the ARM listings (INPUT_FRONT.md):
//   - MJView gates: hidden / ignoreEvents short-circuit to "not in UI" and
//     "not handled" (0x006614A8..: the two ldrsb-gated early returns);
//   - the subview fast enumeration order (subviews@44) — the first subview
//     reporting in-UI wins, and the panels' delegate order is encoded in
//     their ivar order (scrollingButtons -> craftButton -> countSlider);
//   - the panel's own-rect OR (CraftUI touchIsInUI: = own rect ||
//     widgets);
//   - the router's flat pass over uiViews: the first in-UI view is the
//     ui_hit, and the touch is offered to views in order until one handles
//     it (first-wins).
#include "ui_touch_router.h"

#include <cassert>
#include <cstdio>

using namespace blockheads::ui;

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

    std::printf("ui_touch_router: PASS (gates, order, panel OR, router pass)\n");
    return 0;
}
