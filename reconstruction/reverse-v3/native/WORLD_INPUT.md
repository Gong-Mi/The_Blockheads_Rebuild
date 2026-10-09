# World input router (E104)

The World-side input entry points: the 6150-word tap router (census-grade), the
pinch/pan translation trio, the five touch forwarders into the UI manager and
the six gesture/rotation gates that delegate to the active blockhead. 17
bodies, 7282 verified instruction words, from the pinned original
libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically
from the pinned r2 recipe and the recover tool re-verifies every word, cell and
branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| wi_00 | World -[tap:] | 0x005ac3a0 | 6150 | 82 | 13 | 26 | 6 | 353 | 363 |
| wi_01 | World -[startPinchOrPan] | 0x00552e28 | 38 | 0 | 0 | 3 | 0 | 0 | 0 |
| wi_02 | World -[updateTranslationDueToPinchOrPan:] | 0x00552ec0 | 196 | 1 | 0 | 5 | 0 | 14 | 2 |
| wi_03 | World -[setTranslation:] | 0x005531d0 | 309 | 2 | 0 | 5 | 1 | 18 | 8 |
| wi_04 | World -[translation] | 0x005536a4 | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| wi_05 | World -[touchIsInUI:] | 0x005b30c8 | 60 | 2 | 1 | 1 | 0 | 2 | 4 |
| wi_06 | World -[moveTouch:index:] | 0x005b3278 | 36 | 1 | 0 | 1 | 0 | 1 | 0 |
| wi_07 | World -[doEndTouch:wasCancelled:index:] | 0x005b3308 | 41 | 1 | 0 | 1 | 0 | 1 | 0 |
| wi_08 | World -[cancelTouch:index:] | 0x005b33ac | 33 | 1 | 0 | 0 | 0 | 1 | 0 |
| wi_09 | World -[endTouch:index:] | 0x005b3430 | 33 | 1 | 0 | 0 | 0 | 1 | 0 |
| wi_10 | World -[swipeGesture] | 0x005b34b4 | 35 | 2 | 1 | 1 | 0 | 2 | 0 |
| wi_11 | World -[requiresSwipeEvents] | 0x005bf968 | 36 | 2 | 1 | 1 | 0 | 2 | 0 |
| wi_12 | World -[allowsPanning] | 0x005bf9f8 | 89 | 3 | 1 | 1 | 0 | 4 | 2 |
| wi_13 | World -[allowsRotation] | 0x005bf880 | 58 | 2 | 1 | 2 | 0 | 2 | 1 |
| wi_14 | World -[requiresDirectionalSwipes] | 0x005bfb5c | 46 | 3 | 1 | 1 | 0 | 3 | 0 |
| wi_15 | World -[directionalSwipe:] | 0x005bfc14 | 39 | 3 | 0 | 1 | 0 | 3 | 0 |
| wi_16 | World -[unmodifiedGroundLevelForX:] | 0x005b3540 | 65 | 1 | 1 | 2 | 0 | 2 | 2 |

## The tap router (wi_00, census-grade)

`tap:` is the world-side touch router and the largest body of this batch
(6150w). Read at census level, not instruction by instruction: 353 call
rows carrying objc_msgSend x99 + register blx x44, the geometry helpers
makeIntpair x36 and tileAtWorldPositionLoaded x21, the interpolation pair
linearInterpolate x32 / reverseLinearInterpolate x16, Vector2 ctor x17,
tileIsSolid x17, tileIsPaintable x12, GLKMathUnproject x2 (the
screen-to-world unprojection of the tap point) and tileIsHalfDepth x2. Float
constants: 0x3f800000 (1.0f) and 0xbf000000 (-0.5f); immediates 0xa/0x4b/
0x43f/0x142. The per-branch interaction dispatch inside the body is recorded
at histogram level only - this is a census boundary, not a per-instruction
walkthrough.

## The pinch/pan translation trio

startPinchOrPan (38w) snapshots the translation state in one pass: the
8-byte Vector2 fields behind the ivar slots ffffcc20/cc24/cc28
(accurateTranslation / lastPinchPanTranslation / touchStartTranslation).
updateTranslationDueToPinchOrPan: (196w) applies the delta: the windowInfo
scale (vldr [r0,0xc]) multiplied by pinchScale, Vector2 arithmetic, a clamp
against the window bound (vcvt.f32.s32 + vcmpe with ble guards), constants
0x400 (1024) and 0x3ccdcccd, then setTranslation: via objc_msgSend at
0x553194. setTranslation: (309w) wraps both components with __wrap_fmodf
over worldWidthMacro, recomputes roundedTranslation and pushes
[MJSoundManager instance] setListenerPosition:zoom: (0x5535f4/0x553650).
translation (18w) is the bare 8-byte ivar getter.

## The touch forwarders

touchIsInUI: (60w) returns 1 while panBlockingUIDisplayed (0x5b3118) and
otherwise forwards touchIsInUI: to the uiManager; moveTouch:index: (36w)
and doEndTouch:wasCancelled:index: (41w) forward straight through;
cancelTouch:index: (33w) and endTouch:index: (33w) are the two
wasCancelled=1/0 wrappers of doEndTouch:wasCancelled:index:.

## The gesture gates

swipeGesture (35w) and requiresSwipeEvents (36w) delegate to the active
blockhead; allowsPanning (89w) returns 0 while takingPhoto or when the
blockhead denies panning; allowsRotation (58w) reads requiresMotionEvents
plus the dpadControl flag; requiresDirectionalSwipes (46w) reads
isCasting / fishingRod; directionalSwipe: (39w) forwards the swipe to the
blockhead/fishingRod pair. unmodifiedGroundLevelForX: (65w) is the loader
fallback: worldTileLoader (ffffcd14) path at 0x5b35cc, else the
clientTileLoader path at 0x5b361c.

## Boundaries

- wi_00 `tap:` is census-grade (call histogram + constants + structure); the
  branch-level interaction dispatch inside it is not claimed instruction by
  instruction.
- wi_08 `cancelTouch:index:` listing is trimmed at the next IMP (the exidx
  entry over-covers into the neighbour); the header keeps the extracted
  ARM.exidx end.
- The uiManager / blockhead message contracts are asserted only at the
  selector level (forwarding calls); their implementations live in other
  classes and are outside this batch.
