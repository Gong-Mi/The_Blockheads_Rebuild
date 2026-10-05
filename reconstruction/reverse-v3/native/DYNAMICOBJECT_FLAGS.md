# The DynamicObject flag cluster (offsets 48..52) and who touches it

## The cluster

Five adjacent **one-byte** flags, which is why every accessor in this family has the same `ldrsb` body:

| flag | offset | cell |
|---|---:|---|
| `needsRemoved` | 48 | `0xf33e44` |
| `updateNeedsToBeSent` | 49 | `0xf33e48` |
| `creationDataNeedsToBeSent` | 50 | `0xf33e4c` |
| `unreliableUpdateNeedsToBeSent` | 51 | `0xf33e50` |
| `isNet` | 52 | `0xf33e40` |

`needsRemoved` gates the update loop, and the other four are network-dirty bits - the shape says so: an
object marks itself "needs to be sent" through adjacent bytes.

## Site census

| flag | cell | sites | read | write | unclassified |
|---|---|---:|---:|---:|---:|
| `isNet` | 0xf33e40 | 6 | 2 | 0 | 4 |
| `needsRemoved` | 0xf33e44 | 14 | 4 | 0 | 10 |
| `updateNeedsToBeSent` | 0xf33e48 | 29 | 4 | 1 | 24 |
| `creationDataNeedsToBeSent` | 0xf33e4c | 1 | 0 | 0 | 1 |
| `unreliableUpdateNeedsToBeSent` | 0xf33e50 | 1 | 0 | 0 | 1 |

## What is actually learned

The **reads** are semantically coherent, which is the useful part: `needsRemoved` is read by
`NPC -[checkCurrentPositionForFood]`, `Scorpion -[blockheadUnloaded:]`, `Dodo -[blockheadUnloaded:]` and
`Boat -[updatePosition:]` - the "is this object gone" question asked from the places that need it, and
`isNet` is read from `NPC`, `FireObject -[update:accurateDT:isSimulation:]` and `Blockhead`. That is a
networked-object model showing up in the expected places.

Exactly one site is classified as a write: `strb lr,[r0]` at `0x5f63a4` in
`InteractionObject -[startInteractionWithBlockhead:]`, setting `updateNeedsToBeSent`.

## Do NOT read the write counts as a writer census

This is the part that would mislead a reader in a hurry, so it is stated here rather than left in the
artifact: **24 of `updateNeedsToBeSent`'s 29 sites are labelled `pointer-or-unknown`**, because the
classifier inspects only the instruction after the address computation and these sites use
`strb rX,[rY,rZ]` store forms it does not recognise. The population of store-shaped sites across
`Torch -[worldChanged:]`, `TradingPost -[contentsDidChange]`, `Sign -[paint:]`, `Stairs
-[updateConfiguration]`, `Rail -[remoteUpdate:]`, `Chest -[paint:]`, `Bed -[paint:]`, `Ladder
-[paint:]` is exactly where a dirty bit belongs, but "one writer" would be a conclusion drawn from a
tool gap, not from the binary.

Also carried over from the existing evidence: the flag getters sit in a run of **adjacent** functions
(`0x83d1xx`), so prologue attribution packs several of their own self-reads under
`DynamicObject -[uniqueID]`. The cell identity is reliable; the method name is not - the same limit
recorded for the shared one-line getters, now hitting a second family.
