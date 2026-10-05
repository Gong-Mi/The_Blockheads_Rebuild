# The DynamicObject flag cluster (offsets 48..52): who reads and who sets them

## The cluster

Five adjacent **one-byte** flags, which is why every accessor in this family shares the `ldrsb` body:

| flag | offset | cell |
|---|---:|---|
| `needsRemoved` | 48 | `0xf33e44` |
| `updateNeedsToBeSent` | 49 | `0xf33e48` |
| `creationDataNeedsToBeSent` | 50 | `0xf33e4c` |
| `unreliableUpdateNeedsToBeSent` | 51 | `0xf33e50` |
| `isNet` | 52 | `0xf33e40` |

`needsRemoved` gates the update loop; the other four are network-dirty bits.

## Site census, after fixing the classifier

| flag | cell | sites | read | write | unclassified |
|---|---|---:|---:|---:|---:|
| `isNet` | 0xf33e40 | 6 | 5 | 0 | 1 |
| `needsRemoved` | 0xf33e44 | 14 | 4 | 1 | 9 |
| `updateNeedsToBeSent` | 0xf33e48 | 29 | 4 | 22 | 3 |
| `creationDataNeedsToBeSent` | 0xf33e4c | 1 | 0 | 1 | 0 |
| `unreliableUpdateNeedsToBeSent` | 0xf33e50 | 1 | 0 | 1 | 0 |

`updateNeedsToBeSent`'s writers are exactly where a dirty bit belongs:

- `strb r3, [r0, r1] (fused: offset register is the index)` at 0x5ebc04 in TradingPost -[contentsDidChange]
- `strb r3, [r0, r1] (fused: offset register is the index)` at 0x5f28dc in TradingPost -[paint:]
- `strb lr, [r0]` at 0x5f63a4 in InteractionObject -[startInteractionWithBlockhead:]
- `strb r3, [r0, r1] (fused: offset register is the index)` at 0x6011ac in Sign -[paint:]
- `strb r3, [r0, r1] (fused: offset register is the index)` at 0x627ac0 in FreeBlock -[initWithWorld:dynamicWorld:saveDict:cache:]
- `strb r3, [r0, r1] (fused: offset register is the index)` at 0x6cc184 in Stairs -[updateConfiguration]
- `strb r3, [r0, r1] (fused: offset register is the index)` at 0x6d03c0 in Stairs -[paint:]
- `strb r3, [r0, r1] (fused: offset register is the index)` at 0x768fe8 in Door -[checkAndUpdateBlockedStatus]
- `strb r3, [r0, r1] (fused: offset register is the index)` at 0x77a5c0 in Rail -[updateRailConfiguration]
- `strb r3, [r0, r1] (fused: offset register is the index)` at 0x77b768 in Rail -[remoteUpdate:]
- `strb ip, [r0, r1] (fused: offset register is the index)` at 0x7ad82c in DropBear -[update:accurateDT:isSimulation:]
- `strb r3, [r0, r1] (fused: offset register is the index)` at 0x8195e8 in KelpPlant -[tileHarvested:removeBlockhead:correctToolMultiplier:]

and that is the finding: **the network-sync trigger is a one-byte flag set by every "something changed"
path** - contents changed, painted, reconfigured, a door's blocked status recomputed, an object
constructed from a save dict. It is one flag, set from many places, read by the update loop.

`isNet` keeps **0** writers through this channel, so how an object becomes "networked" uses another
mechanism - a constructor store, a memset of the block, or a form still unclassified - and that is an
open question rather than a negative result.

## The correction that produced these numbers

The first version of this artifact reported **1** classified write and **24** unclassified sites for
`updateNeedsToBeSent`, and I wrote, correctly at the time, that "one writer" would be a conclusion drawn
from a tool gap rather than from the binary. It was: the classifier required an explicit
`add rF, rObj, rO` before the access, while the compiler folds that add into the access itself, emitting
`strb r3, [r0, r1]` with the cell's content in `r1` and no add anywhere. Recognising the fused form moved
**4898 of the 7193 sites** from unclassified into read/write overall (writes
197 -> 464).

So the earlier sentence stays in the record as the thing that kept this from being believed wrong - and
the honest summary is that the flag census was wrong, not the binary.

## What did NOT change

`World.fastForward` still resolves to exactly **one** site and it is still a **read** under the fixed
classifier. The same correction that flips the flag census leaves the world-clock conclusion intact,
which is the kind of independence worth having: a tool fix that flatters every prior claim would be
suspect.
