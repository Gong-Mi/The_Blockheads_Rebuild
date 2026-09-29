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

// --- the CraftUI panel (the first subclass overrides) --------------------
// CraftUI (0x00B80EB4..0x00B817A4, disasm_craftui_touch.txt /
// disasm_craftui_starttouch.txt). The panel-local frame is
//   local = point - windowInfo(+8/+0xc) - translationOffset(@212/@216)
// (translationOffset is the pair of floats at 212/216). The touch methods
// delegate to three widget children: scrollingButtons@148, craftButton@208,
// countSlider@164.
struct PanelFrame {
    float window_x = 0.0f;  // windowInfo[+8]
    float window_y = 0.0f;  // windowInfo[+0xc]
    float offset_x = 0.0f;  // translationOffset.x (@212)
    float offset_y = 0.0f;  // translationOffset.y (@216)
};

// What a widget child answers to the one-argument touch forms (the
// differential fixture pins these, like every Receiver reply).
struct ChildReply {
    bool in_ui = false;    // [child touchIsInUI:] -> 1
    bool handles = false;  // [child startTouch:] -> 1
};

// CraftUI -touchIsInViewAtAll: (95w) — the panel's own-rect test: 260 x 302
// with EXCLUSIVE edges, x in (-130, 130), y in (0, 302), in the local frame.
bool craftui_touch_is_in_view_at_all(Point p, const PanelFrame& f);

// The delegation artifact: the selector sequence the ARM records plus the
// BOOL the touch methods return (the void ones leave handled at 0).
struct PanelTrace {
    std::vector<const char*> calls;
    int handled = 0;
};

// CraftUI -touchIsInUI: (134w) — the children's touchIsInUI: in the decoded
// order (scrollingButtons, craftButton, countSlider), first nonzero wins.
// The listing has NO own-rect term here: the rect lives in
// touchIsInViewAtAll: alone. (This corrects the earlier INPUT_FRONT note.)
PanelTrace craftui_touch_is_in_ui(const ChildReply* sb, const ChildReply* cb,
                                  const ChildReply* cs);

// CraftUI -startTouch:tapCount: (137w) — the children's startTouch: in the
// same order, first nonzero wins; no own-rect gate either.
PanelTrace craftui_start_touch(const ChildReply* sb, const ChildReply* cb,
                               const ChildReply* cs);

// CraftUI -moveTouch: (103w) / -endTouch: (103w) — ALL THREE children, in
// the OTHER order the listing attests (craftButton, countSlider,
// scrollingButtons); void, and the point they receive is the local one.
PanelTrace craftui_move_touch(const ChildReply* sb, const ChildReply* cb,
                              const ChildReply* cs);
PanelTrace craftui_end_touch(const ChildReply* sb, const ChildReply* cb,
                             const ChildReply* cs);

// --- the DPad panel (the rotated hit test) -------------------------------
// DPad -touchIsInViewAtAll: (0x0070567C..0x007058F8, 232w) with its rotation
// helper (0x0070591C, inside the method's span): the local point is rebased
// through the window fields, rotated by the constant angle (0xBF490FDB,
// movw/movt = -pi/4; sinf/cosf), then tested against the +-80 square, all
// edges exclusive. windowInfo[+8]/[+0xc] are the window origin;
// [+0x10]/[+0x14]/[+0x1c] feed the dpad's own offsets; rightSide@160 selects
// the mirrored layout. DPad -touchIsInUI: (24w) is the pure forward to
// touchIsInViewAtAll:.
struct DPadFrame {
    float window_x = 0.0f;    // windowInfo[+8]
    float window_y = 0.0f;    // windowInfo[+0xc]
    float w10 = 0.0f;         // windowInfo[+0x10]
    float w14 = 0.0f;         // windowInfo[+0x14]
    float w1c = 0.0f;         // windowInfo[+0x1c]
    bool right_side = false;  // rightSide@160
};

bool dpad_touch_is_in_view_at_all(Point p, const DPadFrame& f);

// The forward: the reply of [self touchIsInViewAtAll:point] (sxtb'd).
bool dpad_touch_is_in_ui(bool in_view_at_all);

// --- the BlockheadUI panel (the third subclass) --------------------------
// BlockheadUI -touchIsInViewAtAll: (0x006FD188..0x006FD2F8, 99w): the
// own-rect test — local = point - windowInfo(+8/+0xc) - translationOffset
// (the float pair at 184/188), x in (-120, 120), y in (-144, 142), every
// edge exclusive.
struct BlockheadFrame {
    float window_x = 0.0f;  // windowInfo[+8]
    float window_y = 0.0f;  // windowInfo[+0xc]
    float offset_x = 0.0f;  // translationOffset[0] (@184)
    float offset_y = 0.0f;  // translationOffset[1] (@188)
};

bool blockheadui_touch_is_in_view_at_all(Point p, const BlockheadFrame& f);

// BlockheadUI -touchIsInUI: (0x006FD314..0x006FD69C, 226w): the children's
// OR in the decoded order — getWorkbenchButton@80, nameEditButton@96, then
// sleepButton@84, meditateButton@88 — EXCEPT that a set
// stopButtonDisplayed@76 routes to stopButton@92 and RETURNS right after it
// (sleepButton/meditateButton are never tried in that regime).
struct BlockheadChildren {
    const ChildReply* workbench = nullptr;  // getWorkbenchButton @80
    const ChildReply* name_edit = nullptr;  // nameEditButton @96
    const ChildReply* stop = nullptr;       // stopButton @92
    const ChildReply* sleep = nullptr;      // sleepButton @84
    const ChildReply* meditate = nullptr;   // meditateButton @88
    bool stop_displayed = false;            // stopButtonDisplayed@76
};

PanelTrace blockheadui_touch_is_in_ui(const BlockheadChildren& c, Point p);

// BlockheadUI -startTouch:tapCount: (0x006FD69C..0x006FDA2C, 228w): the
// SAME chain as touchIsInUI: but with the one-argument startTouch: — the
// children's handles replies, first nonzero wins, the stopButtonDisplayed
// gate ending the chain at stopButton.
PanelTrace blockheadui_start_touch(const BlockheadChildren& c, Point p);

// BlockheadUI -moveTouch: (159w) / -endTouch: (159w): ALL children in the
// same order, no short-circuit, and the same gate early-exit (with the gate
// set the chain ends at stopButton); void.
PanelTrace blockheadui_move_touch(const BlockheadChildren& c, Point p);
PanelTrace blockheadui_end_touch(const BlockheadChildren& c, Point p);

// --- the constant-verdict panels (decoded) --------------------------------
// These panels' rect / in-UI bodies rebase the point into dead locals (the
// windowInfo(+8/+0xc) reads happen; the results are discarded) and return
// the class's literal (`movw lr, #N; sxtb r0, lr`) — no receiver is ever
// messaged and nothing is written. Arm-attested per class:
//   MapUI      rect 0 / inUI 0 (its press returns 0; move/end are 7w stubs)
//   OptionsUI  rect 1 / inUI 0
//   ShareUI    rect 1 / inUI 0
//   PauseUI    rect 1 (its in-UI is 79w and not yet decoded)
//   MainMenuUI rect 1 / inUI 1
constexpr bool kMapUiRect = false;
constexpr bool kMapUiInUi = false;
constexpr int kMapUiPress = 0;
constexpr bool kOptionsUiRect = true;
constexpr bool kOptionsUiInUi = false;
constexpr bool kShareUiRect = true;
constexpr bool kShareUiInUi = false;
constexpr bool kPauseUiRect = true;
constexpr bool kMainMenuUiRect = true;
constexpr bool kMainMenuUiInUi = true;

// --- the WorkbenchProgressBarUI panel -------------------------------------
// rect (95w): the same four-compare shape as CraftUI with its own numbers —
// local = point - windowInfo(+8/+0xc) - translationOffset(@120/@124);
// x in (-120, 120), y in (0, 102), every edge exclusive. Everything else is
// constant: touchIsInUI: returns 0 (59w, the rebase is dead), the press
// returns 0 (61w), moveTouch:/endTouch: are empty void bodies (56w each) —
// no receiver is ever messaged.
bool wbpbarui_touch_is_in_view_at_all(Point p, const PanelFrame& f);
constexpr bool kWorkbenchProgressBarInUi = false;
constexpr int kWorkbenchProgressBarPress = 0;

// --- the CameraUI panel ---------------------------------------------------
// rect (32w): constant 1 (dead rebase, windowInfo@96). touchIsInUI: (78w)
// and startTouch:tapCount: (99w) are the two-child OR in the order
// cancelButton@104, takePhotoButton@108 (short-circuit; the press uses the
// one-argument startTouch:); moveTouch:/endTouch: (66w each) message BOTH
// children.
constexpr bool kCameraUiRect = true;
PanelTrace cameraui_touch_is_in_ui(const ChildReply* cancel,
                                   const ChildReply* photo);
PanelTrace cameraui_start_touch(const ChildReply* cancel,
                                const ChildReply* photo);
PanelTrace cameraui_move_touch(const ChildReply* cancel,
                               const ChildReply* photo);
PanelTrace cameraui_end_touch(const ChildReply* cancel,
                              const ChildReply* photo);

// --- the PetUI panel ------------------------------------------------------
// rect (98w): local = point - windowInfo(+8/+0xc) - translationOffset(@136);
// x in (-120, 120), y in (-16, 114), all edges exclusive. The four chains
// message the SINGLE child nameEditButton@52: touchIsInUI: (91w) and the
// press (93w) return its reply, moveTouch:/endTouch: (68w each) are void.
bool petui_touch_is_in_view_at_all(Point p, const PanelFrame& f);
PanelTrace petui_touch_is_in_ui(const ChildReply* name_edit);
PanelTrace petui_start_touch(const ChildReply* name_edit);
PanelTrace petui_move_touch(const ChildReply* name_edit);
PanelTrace petui_end_touch(const ChildReply* name_edit);

// --- the WearUI panel -----------------------------------------------------
// rect (118w): local = point - windowInfo(+8/+0xc) - translationOffset
// (@152); the x compares run in DOUBLE against +-w/2 (frameSize.w, an
// embedded float pair at @28/@32), y in (0, h - 16) in f32 — all edges
// exclusive. The chains message the SINGLE child wearButton@60:
// touchIsInUI: (69w) / the press (93w) return its reply, move/end (68w)
// each are void.
bool wearui_touch_is_in_view_at_all(Point p, const PanelFrame& f,
                                    float w, float h);
PanelTrace wearui_touch_is_in_ui(const ChildReply* wear_button);
PanelTrace wearui_start_touch(const ChildReply* wear_button);
PanelTrace wearui_move_touch(const ChildReply* wear_button);
PanelTrace wearui_end_touch(const ChildReply* wear_button);

// --- the RegenerateUI panel -----------------------------------------------
// rect (95w): local = point - windowInfo(+8/+0xc) - translationOffset
// (@128); x in (-120, 120), y in (0, 184), all edges exclusive.
// touchIsInUI: (122w) / startTouch:tapCount: (127w) are the two-child OR
// in the order dieButton@120, completeButton@124 (short-circuit, the press
// uses the one-arg startTouch:); moveTouch:/endTouch: (87w each) message
// BOTH children.
bool regenerateui_touch_is_in_view_at_all(Point p, const PanelFrame& f);
PanelTrace regenerateui_touch_is_in_ui(const ChildReply* die,
                                       const ChildReply* complete);
PanelTrace regenerateui_start_touch(const ChildReply* die,
                                    const ChildReply* complete);
PanelTrace regenerateui_move_touch(const ChildReply* die,
                                   const ChildReply* complete);
PanelTrace regenerateui_end_touch(const ChildReply* die,
                                  const ChildReply* complete);

}  // namespace blockheads::ui
