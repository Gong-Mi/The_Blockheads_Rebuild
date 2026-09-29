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

// --- the AddCreditUI panel ------------------------------------------------

PanelTrace addcredit_ui_start_touch(bool in_progress,
                                    const ChildReply* cancel,
                                    const ChildReply* week,
                                    const ChildReply* month) {
    (void)cancel;
    (void)week;
    (void)month;
    PanelTrace t;
    if (in_progress) {
        t.handled = 1;                 // gate: 1, zero calls
        return t;
    }
    t.calls.push_back("startTouch:");  // cancelButton@128
    t.calls.push_back("startTouch:");  // add1WeekButton@132
    t.calls.push_back("startTouch:");  // add1MonthButton@136
    t.handled = 0;                     // the constant local (quirk)
    return t;
}

PanelTrace addcredit_ui_move_touch(bool in_progress,
                                   const ChildReply* cancel,
                                   const ChildReply* week,
                                   const ChildReply* month) {
    (void)cancel;
    (void)week;
    (void)month;
    PanelTrace t;
    if (in_progress) return t;         // gate: no calls
    t.calls.push_back("moveTouch:");   // cancelButton@128
    t.calls.push_back("moveTouch:");   // add1WeekButton@132
    t.calls.push_back("moveTouch:");   // add1MonthButton@136
    return t;
}

PanelTrace addcredit_ui_end_touch(bool in_progress,
                                  const ChildReply* cancel,
                                  const ChildReply* week,
                                  const ChildReply* month) {
    (void)cancel;
    (void)week;
    (void)month;
    PanelTrace t;
    if (in_progress) return t;
    t.calls.push_back("endTouch:");    // cancelButton@128
    t.calls.push_back("endTouch:");    // add1WeekButton@132
    t.calls.push_back("endTouch:");    // add1MonthButton@136
    return t;
}

// --- the ControlOptionsUI panel -------------------------------------------

PanelTrace controloptionsui_start_touch(const ChildReply* ok,
                                        const ChildReply* tilt,
                                        const ChildReply* direct,
                                        const ChildReply* dpad_side) {
    (void)ok;
    (void)tilt;
    (void)direct;
    (void)dpad_side;
    PanelTrace t;
    t.calls.push_back("startTouch:");  // OKButton@104
    t.calls.push_back("startTouch:");  // tiltControlButton@112
    t.calls.push_back("startTouch:");  // directControlButton@120
    t.calls.push_back("startTouch:");  // dpadSideButton@128
    t.handled = 0;                     // the constant local (quirk)
    return t;
}

PanelTrace controloptionsui_move_touch(const ChildReply* ok,
                                       const ChildReply* tilt,
                                       const ChildReply* direct,
                                       const ChildReply* dpad_side) {
    (void)ok;
    (void)tilt;
    (void)direct;
    (void)dpad_side;
    PanelTrace t;
    t.calls.push_back("moveTouch:");   // OKButton@104
    t.calls.push_back("moveTouch:");   // tiltControlButton@112
    t.calls.push_back("moveTouch:");   // directControlButton@120
    t.calls.push_back("moveTouch:");   // dpadSideButton@128
    return t;
}

PanelTrace controloptionsui_end_touch(const ChildReply* ok,
                                      const ChildReply* tilt,
                                      const ChildReply* direct,
                                      const ChildReply* dpad_side) {
    (void)ok;
    (void)tilt;
    (void)direct;
    (void)dpad_side;
    PanelTrace t;
    t.calls.push_back("endTouch:");    // OKButton@104
    t.calls.push_back("endTouch:");    // tiltControlButton@112
    t.calls.push_back("endTouch:");    // directControlButton@120
    t.calls.push_back("endTouch:");    // dpadSideButton@128
    return t;
}

// --- the HungerUI panel ---------------------------------------------------

bool hungerui_touch_is_in_view_at_all(Point p, const PanelFrame& f) {
    const float x = p.x - f.window_x - f.offset_x;
    const float y = p.y - f.window_y - f.offset_y;
    return x > -80.0f && x < 80.0f && y > 0.0f && y < 92.0f;
}

PanelTrace hungerui_touch_is_in_ui(const ChildReply* eat) {
    PanelTrace t;
    const bool r = child_in_ui(eat, t);
    t.handled = r ? 1 : 0;
    return t;
}

PanelTrace hungerui_start_touch(const ChildReply* eat) {
    PanelTrace t;
    const bool r = child_start(eat, t);
    t.handled = r ? 1 : 0;
    return t;
}

PanelTrace hungerui_move_touch(const ChildReply* eat) {
    (void)eat;
    PanelTrace t;
    t.calls.push_back("moveTouch:");   // eatButton@68
    return t;
}

PanelTrace hungerui_end_touch(const ChildReply* eat) {
    (void)eat;
    PanelTrace t;
    t.calls.push_back("endTouch:");    // eatButton@68
    return t;
}

// --- the JetPackUI panel --------------------------------------------------

bool jetpackui_touch_is_in_view_at_all(Point p, const PanelFrame& f) {
    const float x = p.x - f.window_x - f.offset_x;
    const float y = p.y - f.window_y - f.offset_y;
    return x > -120.0f && x < 120.0f && y > 0.0f && y < 108.0f;
}

PanelTrace jetpackui_touch_is_in_ui(const ChildReply* add_fuel,
                                    const ChildReply* free_flight) {
    PanelTrace t;
    bool any = child_in_ui(add_fuel, t);
    if (!any) any = child_in_ui(free_flight, t);
    t.handled = any ? 1 : 0;
    return t;
}

PanelTrace jetpackui_start_touch(const ChildReply* add_fuel,
                                 const ChildReply* free_flight) {
    PanelTrace t;
    bool any = child_start(add_fuel, t);
    if (!any) any = child_start(free_flight, t);
    t.handled = any ? 1 : 0;
    return t;
}

PanelTrace jetpackui_move_touch(const ChildReply* add_fuel,
                                const ChildReply* free_flight) {
    (void)add_fuel;
    (void)free_flight;
    PanelTrace t;
    t.calls.push_back("moveTouch:");   // addFuelButton@44
    t.calls.push_back("moveTouch:");   // freeFlightButton@48
    return t;
}

PanelTrace jetpackui_end_touch(const ChildReply* add_fuel,
                               const ChildReply* free_flight) {
    (void)add_fuel;
    (void)free_flight;
    PanelTrace t;
    t.calls.push_back("endTouch:");    // addFuelButton@44
    t.calls.push_back("endTouch:");    // freeFlightButton@48
    return t;
}

// --- the SleepProgressUI panel --------------------------------------------

bool sleepprogressui_touch_is_in_view_at_all(Point p,
                                             const PanelFrame& f) {
    const float x = p.x - f.window_x - f.offset_x;
    const float y = p.y - f.window_y - f.offset_y;
    return x > -120.0f && x < 120.0f && y > 0.0f && y < 110.0f;
}

PanelTrace sleepprogressui_touch_is_in_ui(bool is_meditation,
                                          const ChildReply* abort_btn,
                                          const ChildReply* complete_btn) {
    PanelTrace t;
    bool local = child_in_ui(abort_btn, t);      // abortButton@120
    if (is_meditation) {                         // isMeditation@140 gate
        t.handled = local ? 1 : 0;               // complete never reached
        return t;
    }
    if (!local) local = child_in_ui(complete_btn, t);  // completeButton@124
    t.handled = local ? 1 : 0;
    return t;
}

PanelTrace sleepprogressui_start_touch(bool is_meditation,
                                       const ChildReply* abort_btn,
                                       const ChildReply* complete_btn) {
    PanelTrace t;
    bool local = child_start(abort_btn, t);
    if (is_meditation) {
        t.handled = local ? 1 : 0;
        return t;
    }
    if (!local) local = child_start(complete_btn, t);
    t.handled = local ? 1 : 0;
    return t;
}

PanelTrace sleepprogressui_move_touch(bool is_meditation,
                                      const ChildReply* abort_btn,
                                      const ChildReply* complete_btn) {
    (void)abort_btn;
    (void)complete_btn;
    PanelTrace t;
    t.calls.push_back("moveTouch:");   // abortButton@120 (always)
    if (!is_meditation) {
        t.calls.push_back("moveTouch:");  // completeButton@124
    }
    return t;
}

PanelTrace sleepprogressui_end_touch(bool is_meditation,
                                     const ChildReply* abort_btn,
                                     const ChildReply* complete_btn) {
    (void)abort_btn;
    (void)complete_btn;
    PanelTrace t;
    t.calls.push_back("endTouch:");    // abortButton@120 (always)
    if (!is_meditation) {
        t.calls.push_back("endTouch:");   // completeButton@124
    }
    return t;
}

// --- the AddFuelUI panel --------------------------------------------------

constexpr const char* kEnumSel = "countByEnumeratingWithState:objects:count:";

bool addfuelui_touch_is_in_view_at_all(Point p, const PanelFrame& f) {
    const float x = p.x - f.window_x - f.offset_x;
    const float y = p.y - f.window_y - f.offset_y;
    return x > -120.0f && x < 120.0f && y > 0.0f && y < 108.0f;
}

PanelTrace addfuelui_touch_is_in_ui(const ChildReply* const* items,
                                    int count) {
    PanelTrace t;
    t.calls.push_back("import(memset)");   // the enumeration state prologue
    t.calls.push_back(kEnumSel);
    for (int i = 0; i < count; ++i) {
        if (child_in_ui(items[i], t)) {   // break on the first true
            t.handled = 1;
            return t;
        }
    }
    t.calls.push_back(kEnumSel);          // the exhausted request
    t.handled = 0;
    return t;
}

PanelTrace addfuelui_start_touch(const ChildReply* const* items,
                                 int count) {
    PanelTrace t;
    t.calls.push_back("import(memset)");   // the enumeration state prologue
    t.calls.push_back(kEnumSel);
    for (int i = 0; i < count; ++i) {
        if (child_start(items[i], t)) {   // break on the first true
            t.handled = 1;
            return t;
        }
    }
    t.calls.push_back(kEnumSel);
    t.handled = 0;
    return t;
}

PanelTrace addfuelui_move_touch(const ChildReply* const* items, int count) {
    (void)items;
    PanelTrace t;
    t.calls.push_back("import(memset)");   // the enumeration state prologue
    t.calls.push_back(kEnumSel);
    for (int i = 0; i < count; ++i) {
        t.calls.push_back("moveTouch:");  // every element
    }
    t.calls.push_back(kEnumSel);
    return t;
}

PanelTrace addfuelui_end_touch(const ChildReply* const* items, int count) {
    (void)items;
    PanelTrace t;
    t.calls.push_back("import(memset)");   // the enumeration state prologue
    t.calls.push_back(kEnumSel);
    for (int i = 0; i < count; ++i) {
        t.calls.push_back("endTouch:");   // every element
    }
    t.calls.push_back(kEnumSel);
    return t;
}

// --- the PaintMixUI panel -------------------------------------------------

bool paintmixui_touch_is_in_view_at_all(Point p, const PanelFrame& f) {
    const float x = p.x - f.window_x - f.offset_x;
    const float y = p.y - f.window_y - f.offset_y;
    return x > -130.0f && x < 130.0f && y > 0.0f && y < 262.0f;
}

PanelTrace paintmixui_touch_is_in_ui(int level, const ChildReply* sb0,
                                     const ChildReply* sb1,
                                     const ChildReply* sb2,
                                     const ChildReply* slider,
                                     const ChildReply* craft) {
    PanelTrace t;
    bool local = child_in_ui(sb0, t);        // scrollingButtons[0]
    t.calls.push_back("level");              // the first workbench probe
    if (level > 0) {
        if (!local) local = child_in_ui(sb1, t);   // scrollingButtons[1]
        t.calls.push_back("level");          // the second probe
        if (level > 1) {
            if (!local) local = child_in_ui(sb2, t);  // [2]
        }
    }
    if (!local) local = child_in_ui(slider, t);    // countSlider@128
    if (!local) local = child_in_ui(craft, t);     // craftButton@120
    t.handled = local ? 1 : 0;
    return t;
}

PanelTrace paintmixui_start_touch(int level, const ChildReply* sb0,
                                  const ChildReply* sb1,
                                  const ChildReply* sb2,
                                  const ChildReply* slider,
                                  const ChildReply* craft) {
    PanelTrace t;
    bool local = child_start(sb0, t);
    t.calls.push_back("level");
    if (level > 0) {
        if (!local) local = child_start(sb1, t);
        t.calls.push_back("level");
        if (level > 1) {
            if (!local) local = child_start(sb2, t);
        }
    }
    if (!local) local = child_start(slider, t);
    if (!local) local = child_start(craft, t);
    t.handled = local ? 1 : 0;
    return t;
}

PanelTrace paintmixui_move_touch(int level, const ChildReply* sb0,
                                 const ChildReply* sb1,
                                 const ChildReply* sb2,
                                 const ChildReply* slider,
                                 const ChildReply* craft) {
    (void)sb0;
    (void)sb1;
    (void)sb2;
    (void)slider;
    (void)craft;
    PanelTrace t;
    t.calls.push_back("moveTouch:");   // scrollingButtons[0]
    t.calls.push_back("level");
    if (level > 0) {
        t.calls.push_back("moveTouch:");   // scrollingButtons[1]
        t.calls.push_back("level");
        if (level > 1) {
            t.calls.push_back("moveTouch:");   // scrollingButtons[2]
        }
    }
    t.calls.push_back("moveTouch:");   // countSlider@128
    t.calls.push_back("moveTouch:");   // craftButton@120
    return t;
}

PanelTrace paintmixui_end_touch(int level, const ChildReply* sb0,
                                const ChildReply* sb1,
                                const ChildReply* sb2,
                                const ChildReply* slider,
                                const ChildReply* craft) {
    (void)sb0;
    (void)sb1;
    (void)sb2;
    (void)slider;
    (void)craft;
    PanelTrace t;
    t.calls.push_back("endTouch:");    // scrollingButtons[0]
    t.calls.push_back("level");
    if (level > 0) {
        t.calls.push_back("endTouch:");    // scrollingButtons[1]
        t.calls.push_back("level");
        if (level > 1) {
            t.calls.push_back("endTouch:");    // scrollingButtons[2]
        }
    }
    t.calls.push_back("endTouch:");    // countSlider@128
    t.calls.push_back("endTouch:");    // craftButton@120
    return t;
}

// --- the PauseUI panel (the inUI/press/move/end batch) --------------------

PanelTrace pauseui_touch_is_in_ui(bool disabled,
                                  const ChildReply* options_ui) {
    PanelTrace t;
    if (disabled) {                    // the gate: zero calls, 0
        t.handled = 0;
        return t;
    }
    if (options_ui != nullptr) {       // optionsUI@8 non-nil: its reply
        const bool r = child_in_ui(options_ui, t);
        t.handled = r ? 1 : 0;
        return t;
    }
    t.handled = 0;                     // the dead-rect fallthrough
    return t;
}

PanelTrace pauseui_start_touch(bool disabled, const ChildReply* options_ui,
                               const ChildReply* share_ui,
                               const ChildReply* const* buttons) {
    (void)buttons;
    PanelTrace t;
    if (disabled) {
        t.handled = 0;
        return t;
    }
    if (options_ui != nullptr) {
        t.calls.push_back("startTouch:tapCount:");   // optionsUI@8
        t.handled = options_ui->handles ? 1 : 0;
        return t;
    }
    if (share_ui != nullptr) {
        t.calls.push_back("startTouch:tapCount:");   // shareUI@12
        t.handled = share_ui->handles ? 1 : 0;
        return t;
    }
    for (int i = 0; i < 7; ++i) {
        t.calls.push_back("startTouch:");   // resume..shareButton
    }
    t.handled = 0;                     // the constant local (dead replies)
    return t;
}

PanelTrace pauseui_move_touch(bool disabled, const ChildReply* options_ui,
                              const ChildReply* share_ui,
                              const ChildReply* const* buttons) {
    (void)buttons;
    PanelTrace t;
    if (disabled) return t;
    if (options_ui != nullptr) {
        t.calls.push_back("moveTouch:");   // optionsUI@8
        return t;
    }
    if (share_ui != nullptr) {
        t.calls.push_back("moveTouch:");   // shareUI@12
        return t;
    }
    for (int i = 0; i < 7; ++i) {
        t.calls.push_back("moveTouch:");   // resume..shareButton
    }
    return t;
}

PanelTrace pauseui_end_touch(bool disabled, const ChildReply* options_ui,
                             const ChildReply* share_ui,
                             const ChildReply* const* buttons) {
    (void)buttons;
    PanelTrace t;
    if (disabled) return t;
    if (options_ui != nullptr) {
        t.calls.push_back("endTouch:");    // optionsUI@8
        return t;
    }
    if (share_ui != nullptr) {
        t.calls.push_back("endTouch:");    // shareUI@12
        return t;
    }
    for (int i = 0; i < 7; ++i) {
        t.calls.push_back("endTouch:");    // resume..shareButton
    }
    return t;
}

// --- the ShareUI panel (the press/move/end batch) -------------------------

PanelTrace shareui_start_touch(const ChildReply* const* buttons) {
    (void)buttons;
    PanelTrace t;
    for (int i = 0; i < 7; ++i) {
        t.calls.push_back("startTouch:");  // OK..forumsButton
    }
    t.handled = 0;                         // the constant local (dead replies)
    return t;
}

PanelTrace shareui_move_touch(const ChildReply* const* buttons) {
    (void)buttons;
    PanelTrace t;
    for (int i = 0; i < 7; ++i) {
        t.calls.push_back("moveTouch:");   // OK..forumsButton
    }
    return t;
}

PanelTrace shareui_end_touch(const ChildReply* const* buttons) {
    (void)buttons;
    PanelTrace t;
    for (int i = 0; i < 7; ++i) {
        t.calls.push_back("endTouch:");    // OK..forumsButton
    }
    return t;
}

// --- the OptionsUI panel (the press/move/end batch) -----------------------

PanelTrace optionsui_start_touch(const ChildReply* mpw,
                                 const ChildReply* snd,
                                 const ChildReply* ctl,
                                 const ChildReply* const* buttons) {
    (void)buttons;
    PanelTrace t;
    if (mpw != nullptr) {
        t.calls.push_back("startTouch:tapCount:");   // mpw@136
        t.handled = mpw->handles ? 1 : 0;
        return t;
    }
    if (snd != nullptr) {
        t.calls.push_back("startTouch:tapCount:");   // soundOptionsUI@140
        t.handled = snd->handles ? 1 : 0;
        return t;
    }
    if (ctl != nullptr) {
        t.calls.push_back("startTouch:tapCount:");   // controlOptionsUI@144
        t.handled = ctl->handles ? 1 : 0;
        return t;
    }
    for (int i = 0; i < 6; ++i) {
        t.calls.push_back("startTouch:");   // OK..controlOptionsButton
    }
    t.handled = 0;                          // the constant local (dead replies)
    return t;
}

PanelTrace optionsui_move_touch(const ChildReply* mpw,
                                const ChildReply* snd,
                                const ChildReply* ctl,
                                const ChildReply* const* buttons) {
    (void)buttons;
    PanelTrace t;
    if (mpw != nullptr) {
        t.calls.push_back("moveTouch:");    // mpw@136
        return t;
    }
    if (snd != nullptr) {
        t.calls.push_back("moveTouch:");    // soundOptionsUI@140
        return t;
    }
    if (ctl != nullptr) {
        t.calls.push_back("moveTouch:");    // controlOptionsUI@144
        return t;
    }
    for (int i = 0; i < 6; ++i) {
        t.calls.push_back("moveTouch:");    // OK..controlOptionsButton
    }
    return t;
}

PanelTrace optionsui_end_touch(const ChildReply* mpw,
                               const ChildReply* snd,
                               const ChildReply* ctl,
                               const ChildReply* const* buttons) {
    (void)buttons;
    PanelTrace t;
    if (mpw != nullptr) {
        t.calls.push_back("endTouch:");     // mpw@136
        return t;
    }
    if (snd != nullptr) {
        t.calls.push_back("endTouch:");     // soundOptionsUI@140
        return t;
    }
    if (ctl != nullptr) {
        t.calls.push_back("endTouch:");     // controlOptionsUI@144
        return t;
    }
    for (int i = 0; i < 6; ++i) {
        t.calls.push_back("endTouch:");     // OK..controlOptionsButton
    }
    return t;
}

// --- the MainMenuUI panel (the press batch) -------------------------------

PanelTrace mainmenuui_start_touch(bool connecting,
                                  const ChildReply* tc_ui,
                                  const ChildReply* add_credit,
                                  const ChildReply* mm_options,
                                  bool loading,
                                  int selection,
                                  const ChildReply* load_world,
                                  const ChildReply* create_world,
                                  const ChildReply* join_world,
                                  const ChildReply* time_crystal,
                                  const ChildReply* more_games,
                                  const ChildReply* settings) {
    PanelTrace t;
    if (connecting) {                        // attemptingToConnectToWorld@468
        t.handled = 0;
        return t;
    }
    if (tc_ui != nullptr) {                  // tcUI@444
        t.calls.push_back("startTouch:tapCount:");
        t.handled = tc_ui->handles ? 1 : 0;
        return t;
    }
    if (add_credit != nullptr) {             // addCreditUI@476
        t.calls.push_back("startTouch:tapCount:");
        t.handled = add_credit->handles ? 1 : 0;
        return t;
    }
    if (mm_options != nullptr) {             // mainMenuOptionsUI@48
        t.calls.push_back("startTouch:tapCount:");
        t.handled = mm_options->handles ? 1 : 0;
        return t;
    }
    if (loading) {                           // loading@408
        t.handled = 0;
        return t;
    }
    bool local = false;
    if (selection == 3) {                    // loadWorldUI@456
        if (!local) local = child_start(load_world, t);
    } else if (selection == 1) {             // createWorldUI@460
        if (!local) local = child_start(create_world, t);
    } else if (selection == 2) {             // joinWorldUI@464
        if (!local) local = child_start(join_world, t);
    }
    if (!local) local = child_start(time_crystal, t);   // @420
    if (!local) local = child_start(more_games, t);     // @432
    if (!local) local = child_start(settings, t);       // @440
    t.handled = local ? 1 : 0;
    return t;
}

}  // namespace blockheads::ui
