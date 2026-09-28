// test_ui_control.cpp — pins the MJControl press lifecycle decoded from
// disasm_mjcontrol_all.txt:
//   - the gates (hidden@4 / enabled@71 / ignoreEvents@56) stop every method;
//   - startTouch: hover@68 = 1, the eventFrame@80 test, the
//     sendsEventOnTouchStart@72 send, the clickDown sound,
//     receivedTouchStart@70 = 1;
//   - endTouch: the received/hover resets, the event-frame test (a lift
//     outside fires nothing), the send only when the start did not send,
//     the click sound, wasClicked@69 = 1;
//   - moveTouch: the hover@68 membership update;
//   - cancelAnyTouchStarts: receivedTouchStart@70 = 0.
#include "ui_control.h"

#include <cassert>
#include <cstdio>

using namespace blockheads::ui;

int main() {
    const Point inside{50, 50};
    const Point outside{500, 500};

    // The default button: sends on release.
    {
        Control c;
        c.event_frame = {0, 0, 100, 100};
        const auto s = control_start_touch(c, inside);
        assert(s.engaged && !s.sent_action && s.sound_down);
        assert(c.hover && c.received_touch_start);
        const auto e = control_end_touch(c, inside);
        assert(e.engaged && e.sent_action && e.sound_up);
        assert(c.was_clicked && !c.received_touch_start && !c.hover);
    }
    // The sendsEventOnTouchStart@72 button: fires at the start, not at the end.
    {
        Control c;
        c.event_frame = {0, 0, 100, 100};
        c.sends_event_on_touch_start = true;
        const auto s = control_start_touch(c, inside);
        assert(s.sent_action);
        const auto e = control_end_touch(c, inside);
        assert(e.engaged && !e.sent_action);  // clickDown already fired it
    }
    // A lift outside the event frame: engaged at the start, no click at the end.
    {
        Control c;
        c.event_frame = {0, 0, 100, 100};
        (void)control_start_touch(c, inside);
        const auto e = control_end_touch(c, outside);
        assert(!e.engaged && !e.sent_action && !e.sound_up);
        assert(!c.was_clicked);
    }
    // The gates stop everything (disabled / hidden / ignoreEvents).
    {
        Control c;
        c.event_frame = {0, 0, 100, 100};
        c.enabled = false;
        const auto s = control_start_touch(c, inside);
        assert(!s.engaged && !s.sound_down && !c.received_touch_start);
        c.enabled = true;
        c.hidden = true;
        assert(!control_end_touch(c, inside).engaged);
        c.hidden = false;
        c.ignore_events = true;
        assert(!control_move_touch(c, inside).engaged);
    }
    // moveTouch updates the hover membership.
    {
        Control c;
        c.event_frame = {0, 0, 100, 100};
        (void)control_start_touch(c, inside);
        (void)control_move_touch(c, outside);
        assert(!c.hover);
        (void)control_move_touch(c, inside);
        assert(c.hover);
    }
    // cancelAnyTouchStarts clears the received flag; a later end without a
    // fresh start fires no action.
    {
        Control c;
        c.event_frame = {0, 0, 100, 100};
        (void)control_start_touch(c, inside);
        control_cancel_any_touch_starts(c);
        assert(!c.received_touch_start);
        const auto e = control_end_touch(c, inside);
        assert(e.engaged && !e.sent_action);
    }

    std::printf("ui_control: PASS (gates, send-on-start/end, lift-outside)\n");
    return 0;
}
