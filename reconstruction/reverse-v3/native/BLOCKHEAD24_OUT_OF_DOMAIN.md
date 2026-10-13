# Type 24 Blockhead — out of the dynamic-record domain (evidence note)

Status: **exempt, with proof**. Type 24 is the last row of the 64-row
dynamic-object type table that carries no recovered record loader, and this
note records why a loader does not exist for it — the type is not loaded
from the dynamic-record domain at all.

## The three proofs

1. **Blockhead has no 4-arg record init.** The class's 261 methods in
   `libApplication_objc_methods.tsv` contain NO implementation of
   `initWithWorld:dynamicWorld:saveDict:cache:` (the selector the dynamic
   loader dispatches). Every dynamic-record type recovered through the
   family modules reaches that selector (directly or inherited, as with
   FreightCar 43 / HandCar 41 / PassengerCar 44); Blockhead's own method
   table contains no such implementation — its initializers are the
   runtime/gameplay constructors (`initWithWorld:...atPosition:...` family),
   not a save-record reader.

2. **Blockheads live in `dynamicWorld.blockheads`, not in dynamic
   records.** `NPC_SAVEDICT.md` records the enumeration:
   `dynamicWorld.blockheads` — the world's blockhead list, referenced BY
   INDEX from other records (`currentBlockheadIndex`, `tamedClientID`,
   `savedBlockheadIndex` in the NPC/TrainCar chains, all captured by the
   recovered loaders). The save's main-domain store is `worldv2`
   (`STATIC_SAVE_CONTRACT.md`), whose blockhead state is persisted under
   the world's own keys — a runtime-entity domain, not the per-record
   `dynamicObjects` array the registry constructs.

3. **The type-table entry is a dispatch slot, not a loader address.** The
   matrix row `{type_id: 24, class_name: Blockhead, jump_target: 0x00b59f18}`
   records the id→class jump-table target. 0x00b59f18 is not a Blockhead
   method (the nearest method at/below it in the same image is a JetPackUI
   `.cxx_construct` at 0x00b5960c); the slot exists so the type table stays
   dense, not because a record loader hangs off it.

## Consequence for the registry

Registering a factory for 24 would be a fabricated loader: there is no
record shape it would read (no keys to decode, no selector to inherit).
The honest coverage line is therefore:

- **63/64 types load through recovered chains** (every type with a
  standard/derivable record init).
- **24 Blockhead is exempt as out-of-domain**, with the proofs above, and
  is never counted as "recovered" by the run fixture (`test_client_snapshot_run.py`'s
  fixture builds one record per in-domain type; no type-24 record exists
  and none is synthesized).

The blockhead-facing state that records DO carry (blockhead indices,
tame counts, ownership) is already decoded inside the NPC/TrainCar/chest
modules — so nothing observable from the dynamic domain is left unread.
