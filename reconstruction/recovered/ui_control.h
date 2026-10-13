// ui_control.h — MJControl, the widget layer's control base, modelled from
// disasm_mjcontrol_all.txt (0x009F6198..0x009F7470):
//
//   ivars: target@60, action@64, hover@68, wasClicked@69,
//          receivedTouchStart@70, enabled@71, sendsEventOnTouchStart@72,
//          eventFrame@80, startTouchAnimationTimer@96 (a double timer);
//
//   touchIsInUI:  gates (hidden@4 from MJView, enabled@71, ignoreEvents@56),
//                 then the eventFrame@80 test (helper 0x9F66F0) and the
//                 edge chain (0x9F744C/0x9F74A8/0x9F7504/0x9F7560);
//   startTouch:   gates -> hover@68 = 1 -> eventFrame test ->
//                 if sendsEventOnTouchStart@72: sendAction ->
//                 startTouchAnimationTimer@96 + the clickDown.wav sound ->
//                 receivedTouchStart@70 = 1;
//   moveTouch:    gates -> receivedTouchStart@70 / wasClicked@69 consulted ->
//                 eventFrame test -> hover@68 updated (0 = the drag-off);
//   endTouch:     gates -> receivedTouchStart@70 / hover reset -> eventFrame
//                 test -> if NOT sendsEventOnTouchStart@72: sendAction ->
//                 the click.wav sound -> wasClicked@69 = 1;
//   sendAction:   [target@60 performSelector:action@64 withObject:...]
//                 (0x9F6E9C + the accessor pair);
//   cancelAnyTouchStarts: receivedTouchStart@70 = 0.
#pragma once

#include "ui_touch_router.h"

namespace blockheads::ui {

struct Control {
    Rect event_frame;  // eventFrame@80 (setFrame: keeps it in sync)
    bool hidden = false;          // MJView.hidden@4
    bool enabled = true;          // MJControl.enabled@71
    bool ignore_events = false;   // MJView.ignoreEvents@56
    bool sends_event_on_touch_start = false;  // @72
    // state (all MJControl)
    bool hover = false;                // @68
    bool was_clicked = false;          // @69
    bool received_touch_start = false; // @70
};

struct PressOutcome {
    bool engaged = false;   // the gates passed and the event frame matched
    bool sent_action = false;
    bool sound_down = false;  // clickDown.wav
    bool sound_up = false;    // click.wav
};

// The gates shared by all four methods.
inline bool control_gates_pass(const Control& c) {
    return !c.hidden && c.enabled && !c.ignore_events;
}

PressOutcome control_start_touch(Control& c, Point p);
PressOutcome control_move_touch(Control& c, Point p);
PressOutcome control_end_touch(Control& c, Point p);
void control_cancel_any_touch_starts(Control& c);

}  // namespace blockheads::ui
