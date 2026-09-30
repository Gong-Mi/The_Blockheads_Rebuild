# GameView construction and preUpdate forwarding

This is a reviewed static source boundary, not runtime object-identity proof.
Original ELF is SHA-256 pinned by ELFMemory. `recover_gameview_construction.py`
verifies all 111 words of loadGameView and 32 words of GameView.preUpdate:,
then resolves class/ivar symbols and selector literals.

## Construction

EvolutionViewController.loadGameView IMP 0x00780604:

- Classref 0x00e8a644 contains module-relative OBJC_CLASS_$_GameView at 0x00e91520.
- 0x007806bc alloc; 0x007806cc init, with prior return value used as receiver.
- 0x007806e0 stores init's returned object to controller.gameView (offset 32).
- 0x00780704 sends gameView.setViewController(self).
- 0x00780718 gets self.view; 0x0078073c sends returnedView.setGameView(gameView).
- 0x0078076c gets self.view again; 0x0078078c sends gameView.setGlView(returnedView).

Explanatory pseudocode:

```text
self.gameView = [[GameView alloc] init]
self.gameView.setViewController(self)
self.view.setGameView(self.gameView)
self.gameView.setGlView(self.view)
```

This is strong construction evidence for the GameView implementation family.
Objective-C init may substitute an object and dispatch may be swizzled; neither
runtime dynamic class nor actual identity of two `view` results has been measured.

## Complete small forwarding body

GameView.preUpdate: IMP 0x0093ebd4, end 0x0093ec54:

- 0x0093ebfc..0x0093ec1c: read GameView.world ivar, offset 24.
- incoming float in r2 -> s0 -> stack(sp+4) -> s0 -> r3 -> r2.
- 0x0093ec38: objc_msgSend(world, preUpdate:, original dt bits).
- No arithmetic, clamp, branch gate or local state update in this body.
- There is no explicit world != nil guard; ordinary Objective-C nil dispatch applies.

This connects the outer drawFrame preUpdate argument to the world receiver;
it does not yet recover World.preUpdate: implementation or world construction.

## Four callback inventory (NOT equivalent progress)

| method | IMP | refs | status |
|---|---|---:|---|
| initOpenGL | 0x009216d0 | 29 | references extracted, body not semantically recovered |
| preUpdate: | 0x0093ebd4 | 1 | bounded forwarding body reviewed above |
| update:accurateDT: | 0x009259c0 | 14 | references extracted, branch/dataflow pending |
| render: | 0x009290b0 | 78 | references extracted, branch/dataflow pending |

These counts include selector and CFString records and are not call counts.
The render reference set includes incrementalLoad/startSimulatingIfNeeded,
world creation, UI and save/connection metadata. It is not safe to assume this
method is a pure GPU draw operation, nor to turn sorted references into execution
order. The other three full disassemblies were extracted locally for discovery;
only reviewed construction and preUpdate disassembly slices are committed here.

## Reproduce

```sh
export PYTHONDONTWRITEBYTECODE=1
ELF="$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so"
python3 tools/recover_gameview_construction.py "$ELF" --output "$TMPDIR/gameview-construction.json"
```

Raw refs can be regenerated with extract_objc_references.py using class
`^GameView$` and selector `^(initOpenGL|preUpdate:|update:accurateDT:|render:)$`.
The ledger is now refs=24 / cfg-evidence=21; these reflect explicit evidence
owners, not semantic completion counts. No replacement runtime code changed.
