# World view direct dependencies: six complete methods

Original ELF SHA256: `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

## Function-level coverage

| Method | IMP | Original field offset | Recovered body |
|---|---|---|---|
| translation | 0x005536a4 | accurateTranslation 0x270 | two raw 32-bit words to stret result |
| isSimulating | 0x0056783c | 0xc44 | signed-byte load, not bool normalization |
| takingPhoto | 0x005c4030 | uiManager 0xf0 | execute `[uiManager cameraUI]`, return object != nil |
| worldWidthMacro | 0x005d9824 | 0xc | int32 load followed by dmb ish |
| translatingToGoal | 0x005d9be8 | 0x280 | signed-byte load |
| loadComplete | 0x005d9c68 | 0x8c | signed-byte load |

The six complete bodies contain 97 instructions, plus separately verified literal pools. `recover_world_view_contracts.py` checks the original hash, fixed instruction words, PIC calculations, relocation types, ivar symbols and offset contents. It independently traces the takingPhoto call target, selector and receiver; it does not infer a photo flag from the method name.

Compiled source: `reconstruction/recovered/world_view_contracts.{h,cpp}` in `blockheads_recovered_view`. `WorldViewContractsState` is typed logical storage, NOT the original Objective-C memory layout. UI objects are borrowed. There is no ready-made FrameWorld subclass and no game-loop adapter.

The width getter uses a relaxed atomic load followed by a seq_cst fence to preserve a post-load full barrier in this portable model. This is not a proof of original ObjC memory-model/ABI equivalence. Other fields require serialized ownership; no concurrent mutation contract is invented. Signed-byte getters retain the full -128..127 result range; a later FrameWorld bool adapter must explicitly implement the caller's nonzero test.

## Setter follow-up and remaining dependencies

`setTranslation:` at `0x005531d0` is not a plain assignment. The pinned body contains arithmetic/branches, additional vector writes and outgoing calls. Its entire region through `0x005536a4` is retained in disassembly with hash `a587b51ed92d57877723438e5518d8a149f84c1df11468b61b0b8a380279a9e1`, and the complete local setter is now implemented in `world_translation.cpp`; see `WORLD_TRANSLATION.md` for wrap/quantization/outgoing effects and the imported-math/dynamic-sound boundaries. No setter stub was added.

`World.update:accurateDT:pinchScale:dragInProgress:` and input/window construction also remain pending. Six getters do not make World or the game complete.

## Verification and reproduction

The new behavior test was first run against a temporary no-op implementation outside the repository and failed at `translation raw lane copy`. The real source then passed O0/O2. Tests cover raw lane patterns including signed zero and NaN payloads on the tested host, all signed-byte values, int32 width extremes, nil UI, nil/non-nil camera objects, real callback side effects and repeated dispatch rather than cached photo state. These are local reconstructed-code tests, not original ARM runtime differential tests or a cross-platform floating-point ABI guarantee.

```sh
export PYTHONDONTWRITEBYTECODE=1
python3 tools/recover_world_view_contracts.py \
  --elf "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" --check
for opt in 0 2; do
  build="$HOME/blockheads-work/recovered-view-O${opt}"
  cmake -S reconstruction/recovered -B "$build" \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS_RELEASE="-O${opt} -DNDEBUG"
  cmake --build "$build" --parallel 2
  ctest --test-dir "$build" --output-on-failure
 done
```

The ELF extractor requires pyelftools and capstone. CI runs the compiled dependency test without requiring the copyrighted original ELF. Source/fixture CI, hash-pinned original evidence, and future device acceptance are separate layers.
