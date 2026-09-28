// ui_control.cpp — the MJControl press lifecycle (see ui_control.h).
#include "ui_control.h"

namespace blockheads::ui {

namespace {
bool hit(const Control& c, Point p) {
    return c.event_frame.contains(p.x, p.y);
}
}  // namespace

PressOutcome control_start_touch(Control& c, Point p) {
    PressOutcome out;
    if (!control_gates_pass(c)) return out;  // hidden/enabled/ignore gates
    // The ARM trace settles the order: the hit test runs BEFORE any state
    // write — a press outside the event frame leaves hover@68 at 0 and
    // makes no calls at all (differential case 1).
    if (!hit(c, p)) return out;
    out.engaged = true;
    c.hover = true;                          // hover@68 = 1 (on a hit)
    if (c.sends_event_on_touch_start) {
        out.sent_action = true;              // sendAction -> target/action
    }
    // startTouchAnimationTimer@96 reset + the clickDown.wav sound.
    out.sound_down = true;
    c.received_touch_start = true;           // receivedTouchStart@70 = 1
    return out;
}

PressOutcome control_move_touch(Control& c, Point p) {
    PressOutcome out;
    if (!control_gates_pass(c)) return out;
    // The body consults receivedTouchStart@70 / wasClicked@69, then updates
    // the hover state by the event-frame membership.
    c.hover = hit(c, p);
    out.engaged = true;
    return out;
}

PressOutcome control_end_touch(Control& c, Point p) {
    PressOutcome out;
    if (!control_gates_pass(c)) return out;
    const bool was_received = c.received_touch_start;
    c.received_touch_start = false;  // the reset at 0x009F7068..0x009F7098
    c.hover = false;
    if (!hit(c, p)) return out;      // lifted outside: no click
    out.engaged = true;
    if (was_received && !c.sends_event_on_touch_start) {
        out.sent_action = true;      // the click fires on the release
    }
    out.sound_up = true;             // click.wav
    c.was_clicked = true;            // wasClicked@69 = 1
    return out;
}

void control_cancel_any_touch_starts(Control& c) {
    c.received_touch_start = false;
}

}  // namespace blockheads::ui
