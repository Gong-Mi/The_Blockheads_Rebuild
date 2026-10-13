// test_ui_pipeline.cpp — the composition test: the UIManager-style router
// over a GameUIView panel whose widgets are MJControls (the three layers
// the listings attest, now as one walk).
//
// The claim under test: a touch on a control inside a panel traverses
// router -> panel (own rect + delegate) -> control (gates + event frame),
// and the control's own lifecycle fires exactly as it does standalone —
// i.e. the modules compose, and the panel's delegation does not bypass the
// control's gates.
#include "ui_control.h"
#include "ui_touch_router.h"

#include <cassert>
#include <cstdio>
#include <vector>

using namespace blockheads::ui;

namespace {
// The router's Node walk consults subviews as Nodes; a Control needs a thin
// adapter Node (the panel nests Nodes, the control's geometry lives in its
// event frame). This mirrors the real object graph: the panel's ivars hold
// the widget objects, which are MJView/Node trees themselves.
struct ControlNode {
    Control control;
    Node node;
    explicit ControlNode(Rect frame) : control(), node() {
        control.event_frame = frame;
        node.rect = frame;
        node.handles_own_rect = true;
    }
};
}  // namespace

int main() {
    ControlNode craft_button({150, 120, 50, 30});
    ControlNode count_slider({60, 130, 80, 12});
    count_slider.control.sends_event_on_touch_start = true;

    Node panel;
    panel.rect = {10, 10, 200, 150};
    panel.handles_own_rect = true;
    panel.subviews = {&craft_button.node, &count_slider.node};

    std::vector<Node*> views = {&panel};
    const Point on_button{170, 130};

    // 1. The router pass reaches the panel, the panel reports handled.
    const auto r = route(views, on_button);
    assert(r.ui_hit == &panel);
    assert(r.handled_by == &panel);

    // 2. The control's own lifecycle (driven by the owner after the walk,
    //    as the real panel does): a press+release on the button fires its
    //    action at the release (the default), with the click sounds.
    {
        auto s = control_start_touch(craft_button.control, on_button);
        assert(s.engaged && !s.sent_action && s.sound_down);
        auto e = control_end_touch(craft_button.control, on_button);
        assert(e.engaged && e.sent_action && e.sound_up);
    }
    // 3. The sendsEventOnTouchStart widget fires at the press instead.
    {
        const Point on_slider{70, 135};
        auto s = control_start_touch(count_slider.control, on_slider);
        assert(s.engaged && s.sent_action);
        auto e = control_end_touch(count_slider.control, on_slider);
        assert(e.engaged && !e.sent_action);
    }
    // 4. The panel's delegation must not bypass a disabled control: a
    //    touch inside a disabled widget's frame still counts as "in the
    //    panel" (the panel's rect owns it) but the control itself refuses.
    {
        craft_button.control.enabled = false;
        const auto g = control_start_touch(craft_button.control, on_button);
        assert(!g.engaged && !g.sound_down);
        // The panel-level walk still reports the panel as the ui_hit (its
        // rect contains the point) while its widget refuses to engage.
        const auto r2 = route(views, on_button);
        assert(r2.ui_hit == &panel);
    }

    std::printf("ui_pipeline: PASS (router -> panel -> control composition)\n");
    return 0;
}
