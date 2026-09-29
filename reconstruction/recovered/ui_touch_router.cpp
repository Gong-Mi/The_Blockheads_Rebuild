// ui_touch_router.cpp — the traversal (see ui_touch_router.h).
#include "ui_touch_router.h"

#include <cmath>
#include <cstdint>
#include <cstring>

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

// --- the DPad panel -------------------------------------------------------

namespace {

// the fixed rotation angle, arm-attested as the r3 bits 0xBF490FDB
// (movw #0x0fdb + movt #0xbf49) = -0.7853982 = -pi/4
float dpad_rotation_angle() {
    std::uint32_t bits = 0xBF490FDBu;
    float a = 0.0f;
    std::memcpy(&a, &bits, sizeof(a));
    return a;
}

}  // namespace

bool dpad_touch_is_in_view_at_all(Point p, const DPadFrame& f) {
    // the ARM's exact f32 op order (the listing's vsub/vadd chains)
    const float x1 = p.x - f.window_x;
    const float y1 = p.y - f.window_y;
    float px;
    if (f.right_side) {
        const float b = (f.window_x - f.w14) - 200.0f;
        px = (x1 - b) - 80.0f;
    } else {
        const float a = ((-f.window_x) + f.w10) + 40.0f;
        px = (x1 - a) - 80.0f;
    }
    // the y chain's middle constant is +40 (the same pool entry as A's)
    const float py = (y1 - ((f.w1c - f.window_y) + 40.0f)) - 80.0f;
    // the helper (0x0070591C): out.x = x*cos - y*sin, out.y = y*cos + x*sin
    const float ang = dpad_rotation_angle();
    const float ca = std::cos(ang);
    const float sa = std::sin(ang);
    const float rx = (px * ca) - (py * sa);
    const float ry = (py * ca) + (px * sa);
    return rx > -80.0f && rx < 80.0f && ry > -80.0f && ry < 80.0f;
}

bool dpad_touch_is_in_ui(bool in_view_at_all) { return in_view_at_all; }

// --- the BlockheadUI panel ------------------------------------------------

bool blockheadui_touch_is_in_view_at_all(Point p, const BlockheadFrame& f) {
    const float x = p.x - f.window_x - f.offset_x;
    const float y = p.y - f.window_y - f.offset_y;
    return x > -120.0f && x < 120.0f && y > -144.0f && y < 142.0f;
}

PanelTrace blockheadui_touch_is_in_ui(const BlockheadChildren& c, Point p) {
    (void)p;  // the local point feeds the children; their replies stand in
    PanelTrace t;
    bool any = child_in_ui(c.workbench, t);
    if (!any) any = child_in_ui(c.name_edit, t);
    if (c.stop_displayed) {
        // the stopButtonDisplayed@76 regime: the chain ends at stopButton
        if (!any) any = child_in_ui(c.stop, t);
        t.handled = any ? 1 : 0;
        return t;
    }
    if (!any) any = child_in_ui(c.sleep, t);
    if (!any) any = child_in_ui(c.meditate, t);
    t.handled = any ? 1 : 0;
    return t;
}

PanelTrace blockheadui_start_touch(const BlockheadChildren& c, Point p) {
    (void)p;
    PanelTrace t;
    bool any = child_start(c.workbench, t);
    if (!any) any = child_start(c.name_edit, t);
    if (c.stop_displayed) {
        if (!any) any = child_start(c.stop, t);
        t.handled = any ? 1 : 0;
        return t;
    }
    if (!any) any = child_start(c.sleep, t);
    if (!any) any = child_start(c.meditate, t);
    t.handled = any ? 1 : 0;
    return t;
}

namespace {

// the void methods' chains: every child in order (no short-circuit), the
// gate ending the chain at stopButton
void blockhead_move_end_chain(const BlockheadChildren& c, PanelTrace& t,
                              const char* selector) {
    (void)c;
    t.calls.push_back(selector);   // getWorkbenchButton@80
    t.calls.push_back(selector);   // nameEditButton@96
    if (c.stop_displayed) {
        t.calls.push_back(selector);   // stopButton@92; the chain ends
        return;
    }
    t.calls.push_back(selector);   // sleepButton@84
    t.calls.push_back(selector);   // meditateButton@88
}

}  // namespace

PanelTrace blockheadui_move_touch(const BlockheadChildren& c, Point p) {
    (void)p;
    PanelTrace t;
    blockhead_move_end_chain(c, t, "moveTouch:");
    return t;
}

PanelTrace blockheadui_end_touch(const BlockheadChildren& c, Point p) {
    (void)p;
    PanelTrace t;
    blockhead_move_end_chain(c, t, "endTouch:");
    return t;
}

// --- the WorkbenchProgressBarUI panel -------------------------------------

bool wbpbarui_touch_is_in_view_at_all(Point p, const PanelFrame& f) {
    // the ARM's four fused compares; the rebase is the CraftUI frame kit
    // with translationOffset at 120 (/124)
    const float x = p.x - f.window_x - f.offset_x;
    const float y = p.y - f.window_y - f.offset_y;
    return x > -120.0f && x < 120.0f && y > 0.0f && y < 102.0f;
}

// --- the CameraUI panel ---------------------------------------------------

PanelTrace cameraui_touch_is_in_ui(const ChildReply* cancel,
                                   const ChildReply* photo) {
    PanelTrace t;
    bool any = child_in_ui(cancel, t);
    if (!any) any = child_in_ui(photo, t);
    t.handled = any ? 1 : 0;
    return t;
}

PanelTrace cameraui_start_touch(const ChildReply* cancel,
                                const ChildReply* photo) {
    PanelTrace t;
    bool any = child_start(cancel, t);
    if (!any) any = child_start(photo, t);
    t.handled = any ? 1 : 0;
    return t;
}

PanelTrace cameraui_move_touch(const ChildReply* cancel,
                               const ChildReply* photo) {
    (void)cancel;
    (void)photo;
    PanelTrace t;
    t.calls.push_back("moveTouch:");   // cancelButton@104
    t.calls.push_back("moveTouch:");   // takePhotoButton@108
    return t;
}

PanelTrace cameraui_end_touch(const ChildReply* cancel,
                              const ChildReply* photo) {
    (void)cancel;
    (void)photo;
    PanelTrace t;
    t.calls.push_back("endTouch:");    // cancelButton@104
    t.calls.push_back("endTouch:");    // takePhotoButton@108
    return t;
}

// --- the PetUI panel ------------------------------------------------------

bool petui_touch_is_in_view_at_all(Point p, const PanelFrame& f) {
    const float x = p.x - f.window_x - f.offset_x;
    const float y = p.y - f.window_y - f.offset_y;
    return x > -120.0f && x < 120.0f && y > -16.0f && y < 114.0f;
}

PanelTrace petui_touch_is_in_ui(const ChildReply* name_edit) {
    PanelTrace t;
    const bool r = child_in_ui(name_edit, t);
    t.handled = r ? 1 : 0;
    return t;
}

PanelTrace petui_start_touch(const ChildReply* name_edit) {
    PanelTrace t;
    const bool r = child_start(name_edit, t);
    t.handled = r ? 1 : 0;
    return t;
}

PanelTrace petui_move_touch(const ChildReply* name_edit) {
    (void)name_edit;
    PanelTrace t;
    t.calls.push_back("moveTouch:");   // nameEditButton@52
    return t;
}

PanelTrace petui_end_touch(const ChildReply* name_edit) {
    (void)name_edit;
    PanelTrace t;
    t.calls.push_back("endTouch:");    // nameEditButton@52
    return t;
}

// --- the WearUI panel -----------------------------------------------------

bool wearui_touch_is_in_view_at_all(Point p, const PanelFrame& f,
                                    float w, float h) {
    const float x1 = p.x - f.window_x - f.offset_x;
    const float y1 = p.y - f.window_y - f.offset_y;
    // the ARM: vcvt.f64.f32 the local x, vmul.f64 by 0.5, compare in double
    const double xd = static_cast<double>(x1);
    const double lo = static_cast<double>(-w) * 0.5;
    const double hi = static_cast<double>(w) * 0.5;
    if (!(xd > lo)) return false;
    if (!(xd < hi)) return false;
    if (y1 <= 0.0f) return false;
    return y1 < (h - 16.0f);
}

PanelTrace wearui_touch_is_in_ui(const ChildReply* wear_button) {
    PanelTrace t;
    const bool r = child_in_ui(wear_button, t);
    t.handled = r ? 1 : 0;
    return t;
}

PanelTrace wearui_start_touch(const ChildReply* wear_button) {
    PanelTrace t;
    const bool r = child_start(wear_button, t);
    t.handled = r ? 1 : 0;
    return t;
}

PanelTrace wearui_move_touch(const ChildReply* wear_button) {
    (void)wear_button;
    PanelTrace t;
    t.calls.push_back("moveTouch:");   // wearButton@60
    return t;
}

PanelTrace wearui_end_touch(const ChildReply* wear_button) {
    (void)wear_button;
    PanelTrace t;
    t.calls.push_back("endTouch:");    // wearButton@60
    return t;
}

// --- the RegenerateUI panel -----------------------------------------------

bool regenerateui_touch_is_in_view_at_all(Point p, const PanelFrame& f) {
    const float x = p.x - f.window_x - f.offset_x;
    const float y = p.y - f.window_y - f.offset_y;
    return x > -120.0f && x < 120.0f && y > 0.0f && y < 184.0f;
}

PanelTrace regenerateui_touch_is_in_ui(const ChildReply* die,
                                       const ChildReply* complete) {
    PanelTrace t;
    bool any = child_in_ui(die, t);
    if (!any) any = child_in_ui(complete, t);
    t.handled = any ? 1 : 0;
    return t;
}

PanelTrace regenerateui_start_touch(const ChildReply* die,
                                    const ChildReply* complete) {
    PanelTrace t;
    bool any = child_start(die, t);
    if (!any) any = child_start(complete, t);
    t.handled = any ? 1 : 0;
    return t;
}

PanelTrace regenerateui_move_touch(const ChildReply* die,
                                   const ChildReply* complete) {
    (void)die;
    (void)complete;
    PanelTrace t;
    t.calls.push_back("moveTouch:");   // dieButton@120
    t.calls.push_back("moveTouch:");   // completeButton@124
    return t;
}

PanelTrace regenerateui_end_touch(const ChildReply* die,
                                  const ChildReply* complete) {
    (void)die;
    (void)complete;
    PanelTrace t;
    t.calls.push_back("endTouch:");    // dieButton@120
    t.calls.push_back("endTouch:");    // completeButton@124
    return t;
}

// --- the TradingPostBuyUI panel -------------------------------------------

bool tpbuyui_touch_is_in_view_at_all(Point p, const PanelFrame& f) {
    const float x = p.x - f.window_x - f.offset_x;
    const float y = p.y - f.window_y - f.offset_y;
    return x > -82.0f && x < 82.0f && y > -16.0f && y < 190.0f;
}

PanelTrace tpbuyui_touch_is_in_ui(bool closed, const ChildReply* slider,
                                  const ChildReply* buy) {
    PanelTrace t;
    if (closed) {
        t.handled = 0;                 // closed gate: zero calls
        return t;
    }
    bool any = child_in_ui(slider, t);
    // the ARM's fall-through messages buyButton with startTouch:
    if (!any) any = child_start(buy, t);
    t.handled = any ? 1 : 0;
    return t;
}

PanelTrace tpbuyui_start_touch(bool closed, const ChildReply* slider,
                               const ChildReply* buy) {
    PanelTrace t;
    if (closed) {
        t.handled = 0;
        return t;
    }
    bool any = child_start(slider, t);
    if (!any) any = child_start(buy, t);
    t.handled = any ? 1 : 0;
    return t;
}

PanelTrace tpbuyui_move_touch(bool closed, const ChildReply* slider,
                              const ChildReply* buy) {
    (void)slider;
    (void)buy;
    PanelTrace t;
    if (closed) return t;              // gate skips both calls
    t.calls.push_back("moveTouch:");   // countSlider@164
    t.calls.push_back("moveTouch:");   // buyButton@192
    return t;
}

PanelTrace tpbuyui_end_touch(bool closed, const ChildReply* slider,
                             const ChildReply* buy) {
    (void)slider;
    (void)buy;
    PanelTrace t;
    if (closed) return t;
    t.calls.push_back("endTouch:");    // countSlider@164
    t.calls.push_back("endTouch:");    // buyButton@192
    return t;
}

// --- the SoundOptionsUI panel ---------------------------------------------

PanelTrace soundoptionsui_start_touch(const ChildReply* ok,
                                      const ChildReply* music,
                                      const ChildReply* sound) {
    (void)ok;
    (void)music;
    (void)sound;
    PanelTrace t;
    t.calls.push_back("startTouch:");  // OKButton@104
    t.calls.push_back("startTouch:");  // musicSlider@112
    t.calls.push_back("startTouch:");  // soundSlider@120
    t.handled = 0;                     // the constant local (quirk)
    return t;
}

PanelTrace soundoptionsui_move_touch(const ChildReply* ok,
                                     const ChildReply* music,
                                     const ChildReply* sound) {
    (void)ok;
    (void)music;
    (void)sound;
    PanelTrace t;
    t.calls.push_back("moveTouch:");   // OKButton@104
    t.calls.push_back("moveTouch:");   // musicSlider@112
    t.calls.push_back("moveTouch:");   // soundSlider@120
    return t;
}

PanelTrace soundoptionsui_end_touch(const ChildReply* ok,
                                    const ChildReply* music,
                                    const ChildReply* sound) {
    (void)ok;
    (void)music;
    (void)sound;
    PanelTrace t;
    t.calls.push_back("endTouch:");    // OKButton@104
    t.calls.push_back("endTouch:");    // musicSlider@112
    t.calls.push_back("endTouch:");    // soundSlider@120
    return t;
}

// --- the InventoryFullUI panel --------------------------------------------

bool inventoryfullui_touch_is_in_view_at_all(Point p,
                                             const PanelFrame& f) {
    const float x = p.x - f.window_x - f.offset_x;
    const float y = p.y - f.window_y - f.offset_y;
    return x > -120.0f && x < 120.0f && y > 0.0f && y < 126.0f;
}

// --- the FreeOfferUI panel ------------------------------------------------

PanelTrace freeofferui_start_touch(const ChildReply* exit_btn,
                                   const ChildReply* const* buy_arr,
                                   int offer_count) {
    PanelTrace t;
    bool local = child_start(exit_btn, t);      // exitButton@152
    for (int i = 0; i < offer_count; ++i) {
        if (!local) local = child_start(buy_arr[i], t);  // buyButton[i]
    }
    t.handled = local ? 1 : 0;
    return t;
}

PanelTrace freeofferui_move_touch(const ChildReply* exit_btn,
                                  const ChildReply* const* buy_arr,
                                  int offer_count) {
    (void)exit_btn;
    (void)buy_arr;
    PanelTrace t;
    t.calls.push_back("moveTouch:");            // exitButton@152
    for (int i = 0; i < offer_count; ++i) {
        t.calls.push_back("moveTouch:");        // buyButton[i]
    }
    return t;
}

PanelTrace freeofferui_end_touch(const ChildReply* exit_btn,
                                 const ChildReply* const* buy_arr,
                                 int offer_count) {
    (void)exit_btn;
    (void)buy_arr;
    PanelTrace t;
    t.calls.push_back("endTouch:");             // exitButton@152
    for (int i = 0; i < offer_count; ++i) {
        t.calls.push_back("endTouch:");         // buyButton[i]
    }
    return t;
}

}  // namespace blockheads::ui
