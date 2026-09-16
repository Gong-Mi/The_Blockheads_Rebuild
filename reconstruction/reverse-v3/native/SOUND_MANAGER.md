# MJSoundManager singleton and listener complete local methods

Original ELF SHA256: `733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`.

## Function map

| Method | Code interval (exclusive end) | Source |
|---|---|---|
| +instance | 0x00b88858..0x00b88924 | soundManagerInstance |
| -setListenerPosition:zoom: | 0x00b89e98..0x00b89f60 | SoundManager::setListenerPositionZoom |
| -listenerPos | 0x00b89f68..0x00b89fa8 | SoundManager::listenerPos |

`recover_sound_manager.py` checks the complete pinned ELF, instruction decoding, PIC/relocation chains, actual selectors/classref, AL PLT import, Vector2 identity helper and float immediate opcodes. JSON records all 117 instructions / five calls / one branch and per-region hashes; the disassembly includes the separate literal pools. These are static evidence, not original execution.

## Original semantics

The singleton tests the plain global slot at 0x01065e94. If nil, it sends `alloc` to the fixed MJSoundManager class, then `initWithMasterVolume:` with float 1.0 to the allocation result. It overwrites the slot with the initializer return (including nil or substitute) and reloads it for return. A non-nil slot bypasses both calls. No once guard, retain, lock or atomic publication is present in this bounded body. Repeated nil results retry initialization. A callback writing the shared slot does not cancel the final store. Nil-message suppression is modeled explicitly; object allocation/init exceptions and ObjC dispatch machinery are not implemented here.

The listener copies the two raw input words to `OBJC_IVAR_$_MJSoundManager.listenerPos` at offset 0x50 before calling anything external. Two calls to Vector2::operator float* at 0x004bdaac are identity helpers (entire 20-byte body verified). Its x/y float lanes become r1/r2; zoom arrives by value at caller stack[0] (callee fp+8), and the exact VFP opcode encodes 20.0f. One f32 multiplication supplies z in r3. r0 is 0x1004 (AL_POSITION); PLT 0x001c443c resolves to imported alListener3f. No clamp, invert, division or world wrapping occurs in this method. There are no writes after AL returns.

The getter copies both raw words into the stret result. This is not an arithmetic reconstruction of the vector.

## Compilable integration and boundaries

`reconstruction/recovered/sound_manager.{h,cpp}` is part of blockheads_recovered_view. `TranslationSoundBridge` implements the previously exposed WorldTranslationRuntime interface and executes the real recovered World setter -> singleton -> listener path. Tests invoke all three production modules together, not merely a mocked listener effect.

`SoundSingletonState` must be shared by all bridges of one logical game. State and borrowed runtime objects require serialized ownership and valid lifetimes. It is not an ARM object-memory overlay or concurrency compatibility layer; the original unsynchronized publication is not replaced by an invented thread-safe contract.

Still mandatory external boundaries:

- MJSoundManager allocation and `initWithMasterVolume:` at 0x00b87ac0: its full audio/context/resource/platform body is not recovered in this batch. The singleton local method calls the supplied runtime; tests supply fixtures. Nil/substitute results are not replaced by a fake successful manager.
- Imported alListener3f and OpenAL context/device lifetime: the interface records the real call contract, but no device/audio output is claimed.
- Imported __wrap_fmodf remains explicit in TranslationSoundBridge through SoundMathRuntime.
- Original FPSCR flags, DN/FZ/rounding, exceptional-value bit parity, arbitrary dynamic ObjC overrides and original/runtime differential are not verified.

## Validation

Behavioral RED: before production implementation, an assignment/slot-read-only test double compiled with O2+DNDEBUG aborts at the first singleton initialization assertion. CI repeats that rejection. Tests undefine NDEBUG before headers.

GREEN: O0/O2 + DNDEBUG + -Wall -Wextra -Werror + -fno-fast-math -ffp-contract=off, compiled from current source and executed. Fixtures cover cached lookup, fixed initialization volume, nil allocation/init, retry, substituted return, callback slot mutation, listener float arithmetic, signed-zero/raw NaN lane copy, no post-AL overwrite, and actual World translation-to-listener chaining. These fixtures are not an original-libm/audio oracle. Integrated O0/O2 CTest each passes 5/5; O1 UBSan trap passes 5/5. Three separately compiled mutations outside the repository (wrong z formula, missing AL call, ignoring substituted init return) each abort at behavioral assertions.

Reproduce from repository root:

```sh
python tools/recover_sound_manager.py --elf "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" --check
for opt in 0 2; do
  cmake -S reconstruction/recovered -B "build/sound-methods-O$opt" -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS_RELEASE="-O$opt -DNDEBUG"
  cmake --build "build/sound-methods-O$opt" --parallel 2
  ctest --test-dir "build/sound-methods-O$opt" --output-on-failure
 done
```

The method manifest records 12 implemented methods total, original-runtime behavior-verified remains zero. Android frame-loop/input/window/World.update integration remains pending. CI status is recorded on canonical PR #1 after exact-head verification; device/audio acceptance NOT RUN.
