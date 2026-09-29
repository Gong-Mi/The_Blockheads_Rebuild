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
        // The router's uiViews enumeration gates every view on [view
        // displayed] first (the GameUIView base's displayed@4; the ARM
        // never calls the view's touch methods when it answers 0).
        if (!v->displayed) continue;
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

namespace {

// The three call forms the router's blocks use; each records the selector
// and returns the receiver's reply (0 on a nil receiver: msgSend to nil).
bool call_plain(const Receiver* r, RouterTrace& t) {
    t.calls.push_back("startTouch:tapCount:");
    return r != nullptr && r->handles;
}

bool call_paused(const Receiver* r, RouterTrace& t) {
    t.calls.push_back("startTouch:tapCount:paused:index:");
    return r != nullptr && r->handles_paused;
}

bool call_index(const Receiver* r, RouterTrace& t) {
    t.calls.push_back("startTouch:tapCount:index:");
    return r != nullptr && r->handles;
}

}  // namespace

RouterTrace run_ui_router(const RouterInputs& in, Point p) {
    (void)p;  // the point/tapCount/index reach the receivers; the receivers'
              // replies (the fixture) stand in for their geometry here
    RouterTrace t;

    // Block 1 (0x00AD77A8..): gated on tcUIDisplayed@40 — when it is set
    // the tcUI call runs, and only a zero result falls through to the
    // worldUI paused: fallback; either way the block returns 1.
    if (in.tc_ui_displayed) {
        if (!call_plain(in.tc_ui, t)) call_paused(in.world_ui, t);
        t.handled = 1;
        return t;
    }

    // Block 2 (0x00AD78B0..): a nil pauseUI falls through to the cameraUI
    // block; a set hidePauseUI@148 returns 1 with NO call at all; otherwise
    // the pauseUI call + the paused fallback, always returning 1.
    if (in.pause_ui != nullptr) {
        if (in.hide_pause_ui) {
            t.handled = 1;
            return t;
        }
        if (!call_plain(in.pause_ui, t)) call_paused(in.world_ui, t);
        t.handled = 1;
        return t;
    }

    // Block 3 (0x00AD7A38..): a nil cameraUI falls through to the dpad
    // block; otherwise the cameraUI call + the paused fallback, and the
    // MERGED result is the block's return value (this block stores the call
    // result — unlike blocks 1/2 which store an unconditional 1).
    if (in.camera_ui != nullptr) {
        bool r = call_plain(in.camera_ui, t);
        if (!r) r = call_paused(in.world_ui, t);
        t.handled = r ? 1 : 0;
        return t;
    }

    // Block 4 (0x00AD7B70..): [dpad displayed] gates the dpad call (a real
    // call — the stub answers 0); a nonzero dpad result returns 1, a miss
    // falls through (no paused fallback here).
    t.calls.push_back("displayed");
    if (in.dpad != nullptr && in.dpad->displayed) {
        if (call_index(in.dpad, t)) {
            t.handled = 1;
            return t;
        }
    }

    // Block 5 (0x00AD7C3C..): the worldUI call's result lands in
    // currentTouchIsInAnyButtons@154 (a real state write); a nonzero result
    // or a displayed map ends the route with that byte as the result.
    const bool world_r = call_index(in.world_ui, t);
    t.current_touch_is_in_any_buttons = world_r;
    if (world_r || in.map_displayed) {
        t.handled = t.current_touch_is_in_any_buttons ? 1 : 0;
        return t;
    }

    // Block 6 (0x00AD7CFC..0x00AD7FA8): the uiViews@140 fast enumeration.
    // Per view: the displayed gate, the call (a hit sets @154 and returns
    // 1), then touchIsInViewAtAll: — a view that contains the point ends
    // the search (with @154 as the result), and so does an exhausted
    // enumeration. The enumeration's setup memset is recorded as an import.
    t.calls.push_back("import(memset)");
    t.calls.push_back("countByEnumeratingWithState:objects:count:");
    bool exited_in_view = false;
    for (const Receiver* v : in.ui_views) {
        t.calls.push_back("displayed");
        if (v == nullptr || !v->displayed) continue;
        if (call_plain(v, t)) {
            t.current_touch_is_in_any_buttons = true;
            t.handled = 1;
            return t;
        }
        t.calls.push_back("touchIsInViewAtAll:");
        if (v->in_view) {  // the loop exits without another batch call
            exited_in_view = true;
            break;
        }
    }
    if (!exited_in_view && !in.ui_views.empty()) {
        // one batch: the exhausted enumeration calls countByEnumerating once
        // more, which returns 0
        t.calls.push_back("countByEnumeratingWithState:objects:count:");
    }
    t.handled = t.current_touch_is_in_any_buttons ? 1 : 0;
    return t;
}

// --- the CraftUI panel ---------------------------------------------------

bool craftui_touch_is_in_view_at_all(Point p, const PanelFrame& f) {
    // the ARM: x = point.x - windowInfo[+8] - translationOffset.x, y the
    // same with +0xc/+4; then x > -130 && x < 130 && y > 0 && y < 302
    // (four fused compares, every edge exclusive)
    const float x = p.x - f.window_x - f.offset_x;
    const float y = p.y - f.window_y - f.offset_y;
    return x > -130.0f && x < 130.0f && y > 0.0f && y < 302.0f;
}

namespace {

bool child_in_ui(const ChildReply* c, PanelTrace& t) {
    t.calls.push_back("touchIsInUI:");
    return c != nullptr && c->in_ui;
}

bool child_start(const ChildReply* c, PanelTrace& t) {
    t.calls.push_back("startTouch:");
    return c != nullptr && c->handles;
}

void child_move(const ChildReply* c, PanelTrace& t) {
    (void)c;
    t.calls.push_back("moveTouch:");
}

void child_end(const ChildReply* c, PanelTrace& t) {
    (void)c;
    t.calls.push_back("endTouch:");
}

}  // namespace

PanelTrace craftui_touch_is_in_ui(const ChildReply* sb, const ChildReply* cb,
                                  const ChildReply* cs) {
    PanelTrace t;
    bool any = child_in_ui(sb, t);
    if (!any) any = child_in_ui(cb, t);
    if (!any) any = child_in_ui(cs, t);
    t.handled = any ? 1 : 0;
    return t;
}

PanelTrace craftui_start_touch(const ChildReply* sb, const ChildReply* cb,
                               const ChildReply* cs) {
    PanelTrace t;
    bool any = child_start(sb, t);
    if (!any) any = child_start(cb, t);
    if (!any) any = child_start(cs, t);
    t.handled = any ? 1 : 0;
    return t;
}

PanelTrace craftui_move_touch(const ChildReply* sb, const ChildReply* cb,
                              const ChildReply* cs) {
    PanelTrace t;
    child_move(cb, t);
    child_move(cs, t);
    child_move(sb, t);
    return t;
}

PanelTrace craftui_end_touch(const ChildReply* sb, const ChildReply* cb,
                             const ChildReply* cs) {
    PanelTrace t;
    child_end(cb, t);
    child_end(cs, t);
    child_end(sb, t);
    return t;
}

}  // namespace blockheads::ui
