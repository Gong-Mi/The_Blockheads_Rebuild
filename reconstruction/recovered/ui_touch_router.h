// ui_touch_router.h — the UI family's touch traversal, modelled from the
// ARM-attested listings (INPUT_FRONT.md):
//   - GameUIView (the panel base): touchIsInViewAtAll: = the panel's own rect
//     test; touchIsInUI: / startTouch:tapCount: = the own-rect test OR-ed
//     with / delegating to the widget children (CraftUI 0x00B80EB4..);
//   - MJView (the widget base): touchIsInUI: / startTouch: = the `hidden`
//     and `ignoreEvents` gates, then the fast enumeration over subviews@44
//     recursing into each subview, then the view's own frame test
//     (0x006614A8.., disasm_mjview_touch.txt);
//   - the UIManager router's flat pass over uiViews@140 (0x00AD7748..).
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

}  // namespace blockheads::ui
