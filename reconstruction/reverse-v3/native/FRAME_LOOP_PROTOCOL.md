# The frame-loop protocol, and what tracing its members produced

Two things, kept apart because they have different grades.

## 1. Census (static, exact)

`update:accurateDT:isSimulation:` is implemented by **52 classes** in this binary, and all of them use the
identical signature `v20@0:4f8f12c16` - one uniform protocol, not a set of lookalikes:

| `Tree` | `0x004c57b0` |
| `VinePlant` | `0x004f7cf0` |
| `GemTree` | `0x005298e0` |
| `TradingPost` | `0x005ebe98` |
| `InteractionObject` | `0x005f5de4` |
| `Sign` | `0x005fca18` |
| `FreeBlock` | `0x0062bfe8` |
| `NPC` | `0x006468d0` |
| `FireObject` | `0x00675d30` |
| `Stairs` | `0x006cdccc` |
| `ElevatorMotor` | `0x007017a0` |
| `ClownFish` | `0x00797300` |
| `DropBear` | `0x007ab240` |
| `Shark` | `0x007d6470` |
| `CoffeeTree` | `0x007e0c8c` |
| `LimeTree` | `0x0080bc80` |
| `SurfaceBlock` | `0x00812fb4` |
| `KelpPlant` | `0x00816e34` |
| `PassengerCar` | `0x0081c6f8` |
| `Column` | `0x00835b60` |
| `DynamicObject` | `0x0083ac20` |
| `FishingRod` | `0x0083e870` |
| `GatherBlock` | `0x00869988` |
| `Scorpion` | `0x008a45f0` |
| `DynamicWorld` | `0x008cbf40` |
| `Plant` | `0x00956ef8` |
| `Yak` | `0x0095dcfc` |
| `Boat` | `0x0096de60` |
| `TulipPlant` | `0x009a1d20` |
| `AppleTree` | `0x009bf5f0` |
| `TrainCar` | `0x00a3c488` |
| `FreightCar` | `0x00a41860` |
| `HandCar` | `0x00a4ff08` |
| `NormalPlant` | `0x00a675a0` |
| `Dodo` | `0x00a781c8` |
| `OrangeTree` | `0x00a98648` |
| `CoconutTree` | `0x00a9aa30` |
| `Mirror` | `0x00aa0330` |
| `DonkeyLike` | `0x00ab2130` |
| `Workbench` | `0x00aeea18` |
| `CactusTree` | `0x00b54c60` |
| `PineTree` | `0x00b66fa8` |
| `Blockhead` | `0x00bb9238` |
| `Chest` | `0x00cbc4f0` |
| `CherryTree` | `0x00d0fdb4` |
| `SteamTrain` | `0x00d1bab8` |
| `Bed` | `0x00d41aa0` |
| `MangoTree` | `0x00d4d314` |
| `Egg` | `0x00d4f0c0` |
| `CaveTroll` | `0x00d56460` |
| `SnowSurfaceBlock` | `0x00d8e530` |
| `MapleTree` | `0x00db8078` |

That is the simulation's participant list: every object type that takes a frame step. It is derived
from the method table by the contract test, so gaining or losing a participant is a test failure rather
than a silent edit.

## 2. Traces (executed with a fabricated receiver - and mostly empty)

| target | sends | unresolved | VFP skipped | call-outs | instructions | first-cycle selectors |
|---|---:|---:|---:|---:|---:|---|
| `DynamicWorld:simulate:` | 0 | 0 | 38 | 8 | 249 | - |
| `DynamicWorld:update:accurateDT:` | 0 | 0 | 8 | 1 | 34 | - |
| `World:incrementalLoad` | 0 | 0 | 0 | 21 | 445 | - |
| `World:update:accurateDT:pinchScale:dragInProgress:` | 1 | 0 | 230 | 38 | 1527 | `setTranslation:` |

Read the zeros honestly: **a trace with 0 sends means this run never REACHED a send** - the receiver's
fields are all zero, so the body took the empty path, or the sends sit behind a stubbed call. It does
not mean the method sends nothing.

The one that did reach a send is the useful one:
`World:update:accurateDT:pinchScale:dragInProgress:` sends **`setTranslation:` from 0x573548** while
skipping **230 VFP instructions** - float-heavy geometry that ends by handing a translation to the
object, consistent with `translation` being a `Vector2` at offset 624 that this project already
executes and verifies. Two independent lines meeting on the same field.
Cross-reference: that trace is receiver-conditional. Under a different fabrication of the same
receiver the same method sends nothing - see `TRACE_RECEIVER_SENSITIVITY.md`, which is why the
claim here is scoped to "in this run" rather than to the original.


`World:incrementalLoad`, `DynamicWorld:simulate:` and `DynamicWorld:update:accurateDT:` produced no
sends here; their call-out sites are in the artifact, and any claim about their structure needs a better
receiver than a zeroed page - that is the next problem, not a result.
