// ui_touch_router.cpp — the traversal (see ui_touch_router.h).
#include "ui_touch_router.h"

namespace blockheads::ui {

bool Node::touch_is_in_ui(Point p) const {
    // MJView: the gates first (hidden / ignoreEvents) -> not in UI.
    if (hidden || ignore_events) return false;
    // The fast enumeration over subviews, in order. The ARM listing settles
    // that the base view has NO self frame test at all: with no subviews the
    // enumeration's first call returns 0 and the method returns 0 without
    // ever looking at the point (disasm_mjview_touchisinui.txt).
    for (const Node* sub : subviews) {
        if (sub->touch_is_in_ui(p)) return true;
    }
    // Only the panel subclasses (GameUIView-shaped) serve their own rect.
    return handles_own_rect && rect.contains(p.x, p.y);
}

bool Node::start_touch(Point p) const {
    if (hidden || ignore_events) return false;
    // The subview recursion aggregates as "handled" (MJView stores it in a
    // local and returns it).
    for (const Node* sub : subviews) {
        if (sub->start_touch(p)) return true;
    }
    // The view's own frame test: a hit inside its rect counts as handled
    // for the widgets that respond (the concrete behaviour layer decides;
    // the traversal structure is what this model fixes).
    return rect.contains(p.x, p.y);
}

RouterResult route(std::vector<Node*>& views, Point p) {
    RouterResult out;
    for (Node* v : views) {
        if (out.ui_hit == nullptr && v->touch_is_in_ui(p)) {
            out.ui_hit = v;
        }
        if (out.handled_by == nullptr && v->start_touch(p)) {
            out.handled_by = v;
            break;  // the router offers the touch until one handles it
        }
    }
    return out;
}

}  // namespace blockheads::ui
