# Recovered view module → Android game adapter boundary

Baseline: `90efb6316139840795178ca51b0efffcf3cceb9d` plus the uncommitted complete GameView method batch. This is a source inspection, not original-runtime or device evidence.

## Existing replacement path is not the recovered path

`app/src/main/cpp/game_engine.cpp`:

- `handlePanNative` directly changes renderer target coordinates using `0.02f * camZoom` (lines 240–243).
- `handleZoomNative` directly divides `camZoom`, clamps it to `[0.1,15]` (265–271).
- `onDrawFrameNative` invokes replacement AI/crafting/entities; crafting and entities receive `0.05f * timeSpeed` (318–351). This is not the original distinct `dt` / `accurateDT` contract.

The recovered entry `updateGameView(GameViewState&, FrameRuntime&, float, float)` instead executes World queries/setters/update, time accounting and projection notifications in recovered order. Its `FrameWorld` / `FrameDefaults` are real call boundaries, but current test implementations are fixtures, not recovered production World or platform defaults.

Linking the static archive into the APK without executing the entry and supplying verified dependencies would not advance game integration. Feeding existing camera values into similarly named fields would introduce an unproved coordinate conversion.

## Integration prerequisites and acceptance

1. Six complete World getters and the complete local `setTranslation:` body are recovered in the method library (see `WORLD_VIEW_CONTRACTS.md` and `WORLD_TRANSLATION.md`). The setter shares accurateTranslation/width state with the getters, preserves wrapping and quantization, and requires imported math and sound-dispatch interfaces. `TranslationSoundBridge` now executes the recovered singleton/listener local methods (see `SOUND_MANAGER.md`); alloc/init, imported math and OpenAL remain mandatory external interfaces. A production FrameWorld adapter remains missing. Keep `World.update` explicitly pending until its body/dependencies are recovered. Never use an empty override to call the adapter complete.
2. Recover GameView input-state producers and window lanes. The method map currently indexes, but does not thereby recover:
   - `pinchGesture:velocity:state:center:numberOfTouches:` — `0x0092d1c4`.
   - `pinchZoomToScale:` — `0x00940f24`.
   - primary start/move/end/cancel — `0x0092be2c`, `0x0092c148`, `0x0092c3f4`, `0x0092c638`.
   - secondary start/move/end/cancel — `0x0092c89c`, `0x0092cba8`, `0x0092cdd8`, `0x0092cfa0`.
   - `init` — `0x0091c780`; inspect initialization/window construction before assigning width/height or pixel/world units to the four `windowInfo` lanes.
3. Preserve one state owner and documented borrowed-object lifetimes. Run the recovered method and callbacks on the same serialized frame owner; do not introduce unsynchronized input writes into its callback-mutable state.
4. Recover platform defaults get/set behavior and the actual frame time producer. Verify distinct original frame time arguments, not a fixed timestep substitution.
5. Follow projectionMatrix/cameraZ consumers through original pre-render/render calls before wiring the matrix into replacement GLES. Matrix tests establish arithmetic/storage, not coordinate or shader compatibility.
6. Build an adapter test that invokes the production adapter entry, records all World calls and proves input→state→update→projection consumer linkage. Keep original-runtime differential and Android device behavior as separate gates.

## Work order

Complete GameView method batch → World direct dependencies → input/window producers and World update → production frame adapter → controlled original/runtime/device comparison.

No changes to the current APK frame/input path are made by this document. Existing prototype behavior remains isolated until the conversion contracts are proved.
