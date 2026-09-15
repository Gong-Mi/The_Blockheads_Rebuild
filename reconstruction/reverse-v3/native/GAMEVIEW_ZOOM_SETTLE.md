# Post-cap zoom settling: original GameView.update

Pinned original libApplication.so SHA-256:
733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7.
Region 0x00926acc..0x00927ed8 (exclusive) contains 1283 checked words and
30 callsites. All are included in gameview_zoom_settle.json. Full update remains
2460 words / 80 calls; its locally reviewed selector routes now number 49.
These counts are NOT whole-method semantics or original-runtime verification.

## Entry gates and exceptional named branch

0x926acc reads isZoomingCameraOut(offset357). True performs
`scale + ((double(dt) * double(0)) * scale)`, stores scale, then jumps to
0x927ed4. The original double at0x926b88 is zero. Do not invent a zoom speed,
clear this flag, send a notification, or execute the later factor writeback.
Even a mathematically unchanged field write is represented by writeScale.

Otherwise pinching(offset173) skips to0x927ed0. If not pinching, call
world.takingPhoto at0x926c20; true skips the rest. Only then is pinchZooming
(offset184) checked; true also skips. hasPinchVelocity is NOT an entry gate.
Snapshot input takingPhoto does not execute this getter or model its mutation.

## Ordered finite-input selection tree

All literals below are preserved as exact bits/hex floats in JSON and C++.
`D(F(x))` means widen the float-rounded literal; bare decimals are doubles.

- scale < D(F(.99999)):
  - scale < D(F(.6)): ease HalfDown only if scale > .501.
  - otherwise: ease OneUp only if scale < .999.
  - ALWAYS notifyScaleChanged at0x926fa0, even in either inactive low band.
- otherwise, only if scale > D(F(1.00001)):
  - scale < 1.25: OneDown only if scale > 1.001.
  - else scale < 1.75: OneHalfUp if scale < 1.499;
    OneHalfDown if scale > 1.501; neither at/in the closed gap.
  - else scale < 2.5: TwoUp if scale < D(F(1.9999));
    TwoDown if scale > D(F(2.0001)).
  - else scale < D(F(2.9999)): ThreeUp.
  - else scale < 5: ThreeDown only if scale > D(F(3.0001)).
  - else scale < D(F(7.9999)): EightUp.
  - else: compare against the previously computed float maxScale at fp-0xa4,
    widen and store only if greater. No notification/persistence in this branch.
- Other inactive high bands do not notify and do not write scale.

VFP bits at0x926fe0,0x9271a0,0x927558 encode 1.25,1.75,2.5, not the printed
1,1,2. This is not a nearest-integer rounding algorithm or a universal clamp.
An easing/snap path can exceed the earlier cap; it does not fall through to
another numerical branch in the same frame.

## Common arithmetic, distinct thresholds and effects

Every active easing path separately computes:
`delta = scale-target` (double), `step = float(dt*10)`,
`factor = 1-double(step)`, `product = delta*factor`, `sum = target+product`,
then adds/subtracts double literal0x3f847ae140000000 (=D(F(.01))).
The result stays DOUBLE; no premature float cast. No dt/factor clamp.
On the strict snap comparison it writes the target, obtains standardUserDefaults,
and sends setFloat:forKey: with the then-reloaded float scale and CFString
pinchScale (payload and length checked). The notify follows, when selected.

| Path | Target | Bias | Snap test against exact literal | Defaults getter | Defaults setter | Notify |
|---|---:|---|---|---|---|---|
| HalfDown | 0.5 | subtract | newScale < 0x1.fffd600000000p-2 | 0x00926dcc | 0x00926dfc | 0x00926fa0 |
| OneUp | 1.0 | add | newScale > 0x1.0000100000000p+0 | 0x00926f3c | 0x00926f6c | 0x00926fa0 |
| OneDown | 1.0 | subtract | newScale < 0x1.0000000000000p+0 | 0x0092712c | 0x0092715c | 0x00927188 |
| OneHalfUp | 1.5 | add | newScale > 0x1.7fbe760000000p+0 | 0x009272ec | 0x0092731c | 0x00927348 |
| OneHalfDown | 1.5 | subtract | newScale < 0x1.80418a0000000p+0 | 0x009274dc | 0x0092750c | 0x00927538 |
| TwoUp | 2.0 | add | newScale > 0x1.ffbe760000000p+0 | 0x009276b4 | 0x009276e4 | 0x00927710 |
| TwoDown | 2.0 | subtract | newScale < 0x1.0020c40000000p+1 | 0x00927850 | 0x00927880 | 0x009278ac |
| ThreeUp | 3.0 | add | newScale > 0x1.7fdf3c0000000p+1 | 0x009279ec | 0x00927a1c | 0x00927a48 |
| ThreeDown | 3.0 | subtract | newScale < 0x1.8020c40000000p+1 | 0x00927bb8 | 0x00927be8 | 0x00927c14 |
| EightUp | 8.0 | add | newScale > 0x1.ffef9e0000000p+2 | 0x00927d78 | 0x00927da8 | 0x00927dd4 |

## Final factor writeback (0x927e50..0x927ec8)

On every path reaching0x927e50, if hasPinchVelocity(offset172) is true,
`pinchStartScale = float(double(lastPinchFactor) * pinchScale)`.
Source and destination are offset168 and160; the scale is double offset152.
This runs even in eligible inactive scale bands. The earlier cameraOut,
pinching, takingPhoto and pinchZooming bypasses do not reach it.

## Compilable source and limits

reconstruction/recovered/zoom_settle.{h,cpp} implements all ten easing paths,
entry gates, high cap, notification/persistence requests and factor writeback.
Numerical RED observed on the initial missing easing result. O0/O2 pass with
contraction off; finite normal arithmetic and finite intermediates are the
supported domain (not NaN/FTZ/exception-flag parity). Tests cover all ten normal
and snapped paths, strict threshold equality/adjacent doubles, mixed precision,
low-band notifications, bypass order, factor writeback and non-universal cap.
OneUp needs two input ULPs to cross a snap threshold: one ULP rounds back after
addition across an exponent boundary; that case is explicitly tested.

This remains a snapshot/effect helper, NOT an executable Objective-C callback.
The original reloads scale after standardUserDefaults and reads hasPinchVelocity,
lastPinchFactor and scale after pinchScaleChanged. Returned snapshot effects
assume those external calls do not mutate the supplied values. Real callbacks,
settings writes, cross-helper frame ordering and gameplay integration are not
verified here. Merely wiring these helpers together would not prove parity.

## Reproduce

```sh
export PYTHONDONTWRITEBYTECODE=1
python3 tools/recover_gameview_zoom_settle.py \
  "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" \
  --output "$TMPDIR/gameview-zoom-settle.json"
cmp "$TMPDIR/gameview-zoom-settle.json" reconstruction/reverse-v3/native/gameview_zoom_settle.json
python3 tools/test_zoom_settle_evidence.py
for opt in 0 2; do
  c++ -std=c++17 -O${opt} -Wall -Wextra -Werror -ffp-contract=off \
    -Ireconstruction/recovered tools/test_zoom_settle.cpp \
    reconstruction/recovered/zoom_settle.cpp -o "$TMPDIR/test_zoom_settle"
  "$TMPDIR/test_zoom_settle"
done
```

CI executes the checked-in evidence contracts and C++ tests, NOT the original ELF.
Next: remaining entry-time and horizontal-query routes, entry-time compilable
source, then full callback reload/effect order before frame integration.
