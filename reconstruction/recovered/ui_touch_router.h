// ui_touch_router.h — the UI family's touch traversal, modelled from the
// ARM-attested listings (INPUT_FRONT.md):
//   - GameUIView (the panel base): touchIsInViewAtAll: = the panel's own rect
//     test; touchIsInUI: / startTouch:tapCount: = the own-rect test OR-ed
//     with / delegating to the widget children (CraftUI 0x00B80EB4..);
//   - MJView (the widget base): touchIsInUI: / startTouch: = the `hidden`
//     and `ignoreEvents` gates, then the fast enumeration over subviews@44
//     recursing into each subview, then the view's own frame test
//     (0x006614A8.., disasm_mjview_touch.txt);
//   - the UIManager router's flat pass over uiViews@140 (0x00AD7748..) —
//     plus `run_ui_router` below: the router's FULL block chain as decoded
//     from disasm_uimanager_starttouch.txt.
//
// The model parameterises the *traversal*; per-class geometry arrives as
// rects (the listing-verified pattern: point minus windowInfo, then the
// frame/translationOffset comparison).
#pragma once

#include <vector>

namespace blockheads::ui {

struct Rect {
    float x = 0.0f, y = 0.0f, w = 0.0f, h = 0.0f;

    bool contains(float px, float py) const {
        return px >= x && px <= x + w && py >= y && py <= y + h;
    }
};

struct Point {
    float x = 0.0f, y = 0.0f;
};

// A node in the UI tree: what a panel/widget contributes to the traversal.
struct Node {
    Rect rect;
    bool displayed = true;       // GameUIView -displayed (the uiViews@140
                                 // enumeration's per-view gate)
    bool hidden = false;         // MJView -hidden gate
    bool ignore_events = false;  // MJView -ignoreEvents gate
    bool handles_own_rect = false;  // panels handle their own rect; MJView
                                    // falls through to the frame test
    std::vector<Node*> subviews;    // MJView.subviews@44 / the panels'
                                    // scrollingButtons/craftButton/...
    void* tag = nullptr;            // the concrete widget (opaque here)

    // The MJView-shaped hit test (hidden/ignore gates, subview recursion,
    // then the frame test). The panel form is expressed with the same walk.
    bool touch_is_in_ui(Point p) const;
    // The MJView-shaped handling walk; returns the aggregate "handled".
    bool start_touch(Point p) const;
};

// The UIManager router: the flat pass over the top-level views; the first
// one reporting "in UI" wins, and start_touch is offered to each in order
// until one reports handled (the decoding in INPUT_FRONT.md).
struct RouterResult {
    Node* ui_hit = nullptr;       // the first view whose touch_is_in_ui said yes
    Node* handled_by = nullptr;   // the first view whose start_touch said yes
};

RouterResult route(std::vector<Node*>& views, Point p);

// --- the UIManager router's full block chain -----------------------------
// UIManager -startTouch:tapCount:index: (0x00AD7748..0x00AD8048, 576w) walks
// its UI ivars in order; each block offers the touch to its receiver and
// (for the three panel blocks) to worldUI with `paused:`. `run_ui_router`
// models that chain, the events the ARM differential records
// (tools/test_specials_arm.py) and the currentTouchIsInAnyButtons@154 byte.
//
// A Receiver is what a differential fixture makes the receiver's methods
// answer (the stub graph answers 0 unless the case pins a 1): the call
// replies are inputs here, like the boxed values of the loader models.
struct Receiver {
    bool handles = false;         // [x startTouch:tapCount:...] -> 1
    bool handles_paused = false;  // [x startTouch:tapCount:paused:index:...] -> 1
    bool displayed = false;       // [x displayed] -> 1
    bool in_view = false;         // [x touchIsInViewAtAll:] -> 1
};

struct RouterInputs {
    // the UIManager block gates (the ivars that switch blocks on/off)
    bool tc_ui_displayed = false;  // @40: block 1 (tcUI) runs only when set
    bool hide_pause_ui = false;    // @148: block 2 (pauseUI) returns 1 with
                                   //       no call at all when set
    bool map_displayed = false;    // @152: block 5 exits before the uiViews
                                   //       pass when set
    // the receivers (nullptr = nil)
    const Receiver* tc_ui = nullptr;      // @32
    const Receiver* world_ui = nullptr;   // @20
    const Receiver* pause_ui = nullptr;   // @24
    const Receiver* camera_ui = nullptr;  // @100
    const Receiver* dpad = nullptr;       // @36
    std::vector<const Receiver*> ui_views;  // @140
};

struct RouterTrace {
    // the objc_msgSend selectors the ARM records, in order; "import(memset)"
    // is the enumeration-setup memset the harness records as an import
    std::vector<const char*> calls;
    bool current_touch_is_in_any_buttons = false;  // the @154 byte's value
    int handled = 0;                               // the returned BOOL
};

// The point/tapCount/index flow to the receivers; their geometry and
// arguments are outside this model, so the receivers' replies stand in.
RouterTrace run_ui_router(const RouterInputs& in, Point p);

}  // namespace blockheads::ui
