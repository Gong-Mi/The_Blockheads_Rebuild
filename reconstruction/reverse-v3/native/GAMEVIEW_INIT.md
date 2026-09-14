# GameView -[init] static dispatch map

Original ELF: `libApplication.so`, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`
(pinned by `trace_objc_dispatch.ELFMemory`). IMP `0x0091c780`, next ARM.exidx
function start `0x0091d9cc`, 1171 instruction words, PIC base `0x0105faf4`.

`tools/recover_gameview_init.py` simulates one pass over the bounded body:
registers track int addresses, `('sel',ptr,slot)`, `('cfstr',slot)`,
`('clsref',...)`, `('ivarslot',...)`, GOT imports; fp-relative (and
sp-converted) stack words are modelled so spilled selectors survive calls.
Every word of the checked-in `disasm_gameview_init.txt` listing is re-verified
against the pinned ELF (byte order, exact coverage). Anything the model cannot
prove — cross-branch state loss, `mov pc, ...` style routes, selectors routed
through unmodelled load chains — is exported `kind: unresolved`. No site is
filled by guessing, ordering heuristics or selector-set inference.

This is a static call/selector map, NOT runtime execution order, NOT receiver
object identity. A `recv=prev-msg-result` entry means r0 holds the previous
dispatch's return in the model; nil-receiver behaviour and actual objects are
not measured.

## Selector-resolved sites (27 of 60 blx; 21 provably via objc_msgSend/Super2)

`target` below is the dispatch register's proven value; `lr`/`ip`-routed sites
whose GOT provenance the model loses keep selector evidence but stay
target-unresolved in JSON.

| call | selector | receiver (static model) |
|---|---|---|
| 0x0091c7d4 | `init` | objc_msgSendSuper2 (super-init) |
| 0x0091c884 | `alloc` | `OBJC_CLASS_$_CloudInterface` |
| 0x0091c894 | `init` | prev-msg-result |
| 0x0091c8c8 | `alloc` | `OBJC_CLASS_$_DatabaseEnvironment` |
| 0x0091c9d0 | `objectAtIndex:` | prev-msg-result (NSSearchPathForDirectoriesInDomains result) |
| 0x0091c9f4 | `stringWithFormat:` | classref slot 0x00e8aaa8 (class pointer relocates at load) |
| 0x0091ca20 | `initWithPath:maxDatabases:maxMapSizeInMB:` | prev-msg-result |
| 0x0091ca54 | `alloc` | `OBJC_CLASS_$_Database` |
| 0x0091ca7c | `initWithEnvironment:name:` | prev-msg-result |
| 0x0091cc14 | `instance` | `OBJC_CLASS_$_MJSoundManager` |
| 0x0091cc34 | `instance` | `OBJC_CLASS_$_TradeMissionManager` |
| 0x0091cc60 | `standardUserDefaults` | NSUserDefaults classref |
| 0x0091cc74 | `boolForKey:` | prev-msg-result |
| 0x0091ccb0 | `standardUserDefaults` | NSUserDefaults classref |
| 0x0091ccc4 | `floatForKey:` | prev-msg-result |
| 0x0091cf80 | `objectAtIndex:` | unresolved target reg (r3 spilled path) |
| 0x0091d058 | `defaultQueue` | `OBJC_CLASS_$_SKPaymentQueue` |
| 0x0091d078 | `addTransactionObserver:` | prev-msg-result |
| 0x0091d098 | `instance` | `OBJC_CLASS_$_CrystalManager` |
| 0x0091d0a8 | `loadFromSave` | prev-msg-result |
| 0x0091d0cc | `release` | prev-msg-result |
| 0x0091d1a8 | `standardUserDefaults` | NSUserDefaults classref |
| 0x0091d460 | `instance` | `OBJC_CLASS_$_CrystalManager` |
| 0x0091d760 | `instance` | `OBJC_CLASS_$_CrystalManager` |
| 0x0091d7d0 | `instance` | `OBJC_CLASS_$_CrystalManager` |
| 0x0091d82c | `displayInterstitialForTag:` | prev-msg-result |
| 0x0091d8bc | `reconnectWithAuthenticationDelegate:` | prev-msg-result |

## Direct calls (8)

`0x0091c8f4`/`0x0091cd84` → `NSSearchPathForDirectoriesInDomains`,
`0x0091cae8` → `NSLog`, `0x0091caf0` → `__wrap_exit` (paired with the
`Error. Unable to open app database.` cfstring), `0x0091cb24` → `time`,
and two intra-library calls (`0x0091d9cc`, `0x0091eca4`, `0x00920354` —
local helpers, bodies outside this method's bounds). PLT resolution decodes
the ARM `add ip,pc; add ip,ip; ldr pc,[ip,#x]!` stub triple and maps the GOT
slot's `R_ARM_JUMP_SLOT` symbol.

## CFStrings referenced (12)

`%@/game/`, `main`, `7acfe93afc08c%d65ae2c54ecaf07f`,
`7acfe93afc08%dc65ae2c54ecaf07f`, `Hax`, `%@/game_db/`,
`Error. Unable to open app database.`, `hdTexturesDisabled`, `pinchScale`,
`hasBoughtIAP`, `totalTCBuyCount`, `totalGamePlayTimePassed`.

Two of these are `%d`-formatted MD5 template halves around the literal
`Hax` — an obfuscated key fragment pattern, recorded as found without
interpretation. Together with `initWithPath:maxDatabases:maxMapSizeInMB:`
and `initWithEnvironment:name:`, the game/game_db path assembly and SQLite
environment setup live inside `GameView -[init]`.

## Structural conclusions (evidence-bounded)

1. `-[init]` is not a GL setup routine: it constructs `CloudInterface`,
   `DatabaseEnvironment`, `Database`, touches `MJSoundManager`,
   `TradeMissionManager`, `CrystalManager` singletons, registers StoreKit
   transaction observation and account reconnect.
2. Defaults keys `hdTexturesDisabled`/`pinchScale`/`hasBoughtIAP`/
   `totalTCBuyCount`/`totalGamePlayTimePassed` are all read in the
   constructor via `standardUserDefaults` + `boolForKey:`/`floatForKey:`.
3. The failure branch is `NSLog("Error. Unable to open app database.")`
   followed by `__wrap_exit` — a database-open failure terminates the
   process; there is no recovery message path inside this body.
4. No `OBJC_IVAR_$_GameView.*` store routes were resolved by the model
   (ivar_stores=0): field initialisation is either super-init side effect or
   routed through patterns the model conservatively refuses to pair.
   This is a coverage gap, NOT evidence of absence.

## Remaining unresolved sites

38 blx targets unresolved: selector-receiver pairs beyond model reach
(spill/reload around `time()`, ad-framework and account callbacks whose
dispatch registers arrive through instruction classes the model invalidates).
`gameview_init.json` lists each with `kind: unresolved`.

### CFG replay cross-check (2026-09-14)

`tools/crosscheck_gameview_init_cfg.py` re-derives selector facts with a
worklist + all-path join (loop headers keep only values equal on every
incoming path), independent of the linear pass's layout-order assumption.
Result: 9 of 27 selector sites re-proven, ZERO conflicts, ZERO additions
(machine copy: `gameview_init_cfg_crosscheck.json`).

Two honest conclusions:
1. Those 9 sites now have layout-order-free evidence (strongest tier in this
   file). The join pass cannot beat the linear model for the rest: the
   remaining sites' selectors are preloaded before loop headers and consumed
   inside, so all-path intersection removes them by construction — a
   precision limit of the join, not a contradiction of the linear pass.
2. The cross-check tool hard-refuses to emit on any future pass disagreement,
   so the table above cannot silently drift from CFG-verifiable ground.
   Re-check (needs original ELF):

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/crosscheck_gameview_init_cfg.py \
  "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" \
  --json reconstruction/reverse-v3/native/gameview_init_cfg_crosscheck.json
```

## Reproduce (local acceptance layer, requires original ELF)

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/recover_gameview_init.py \
  "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" --check
```

CI runs the dependency-free contract instead:
`tools/test_gameview_init_evidence.py`.

## Adapter boundary (replacement side)

The rebuild currently maps: game/game_db path assembly + Database open →
`GameActivity.initNative(storageDir)` + `game_world.cpp` persistence +
`original_save_format` (world_db layout from reverse-v3 save work);
defaults keys → `settings_manager`; singleton registration and StoreKit/ads
→ out of scope for the offline replacement (documented, not simulated).
Movement/input wiring is tracked in `GAMEVIEW_INPUT.md`.
