# World lifecycle and cloud/prices IO (E106)

The World lifecycle and IO line: the constructor (census-grade), the global-prices connection quartet, the cloud flags, the old-block decommission pass and the DB bulk pair. 13 bodies, 3266 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| wl_00 | World -[initWithWindowInfo:cache:delegate:saveID:name:client:server:multiplayerWorldData:serverHostData:saveDelay:worldWidthMacro:customRules:expertMode:] | 0x00563604 | 1428 | 26 | 18 | 34 | 14 | 66 | 36 |
| wl_01 | World -[setWindowInfo:] | 0x005b59f8 | 87 | 1 | 1 | 3 | 0 | 1 | 0 |
| wl_02 | World -[connectionDidFinishLoading:] | 0x005ccc88 | 540 | 16 | 5 | 7 | 3 | 23 | 18 |
| wl_03 | World -[connection:didFailWithError:] | 0x005cc994 | 189 | 3 | 3 | 4 | 0 | 10 | 4 |
| wl_04 | World -[connection:didReceiveData:] | 0x005cc864 | 76 | 1 | 1 | 4 | 0 | 2 | 4 |
| wl_05 | World -[connection:didReceiveResponse:] | 0x005cc73c | 74 | 1 | 1 | 4 | 0 | 2 | 4 |
| wl_06 | World -[isCloudGame] | 0x005d0d2c | 74 | 1 | 1 | 2 | 0 | 2 | 5 |
| wl_07 | World -[cloudTopupSucceeded:] | 0x005d3158 | 60 | 2 | 1 | 3 | 0 | 2 | 0 |
| wl_08 | World -[decommissionOldBlocks] | 0x005c6ef8 | 627 | 1 | 0 | 3 | 1 | 12 | 29 |
| wl_09 | World -[incrementalLoadCount] | 0x005d9ca4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| wl_10 | World -[startBulkDatabaseUpdate] | 0x005d8d3c | 26 | 1 | 1 | 1 | 0 | 1 | 0 |
| wl_11 | World -[finishBulkDatabaseUpdate] | 0x005d8da4 | 45 | 2 | 1 | 2 | 0 | 2 | 0 |
| wl_12 | World -[appDatabase] | 0x005d97c0 | 25 | 1 | 1 | 0 | 0 | 1 | 0 |

## The World constructor (wl_00, census-grade)

`initWithWindowInfo:cache:delegate:saveID:name:client:server:multiplayerWorldData:
serverHostData:saveDelay:worldWidthMacro:customRules:expertMode:` (1428w) is the
world constructor: 26 selector cells across 14 classes. Load-bearing wiring:
NSUserDefaults round-trip for saveDelay (0x40) and the bool flags; the server
password via **SFHFKeychainUtils getPasswordForUsername:andServiceName:error:**;
the singleton setWorld:/setWorldWidthMacro: wiring for TipManager,
ParticleEmitter and MJSoundManager; the **saveQueue NSOperationQueue**
(setMaxConcurrentOperationCount:, 0x14 concurrent slots); interfaceOrientation
from UIApplication statusBarOrientation; CMMotionManager +
startObservingMotionEvents (the motion/dpad seeds) and the welcome-message
custom-rules call (viewServerWelcomeMessage:customRules:allowEdit:). The
__stack_chk_guard / __stack_chk_fail pair pins the stack-protector build.

## The global-prices connection quartet

`connectionDidFinishLoading:` (540w) completes the **global trade-prices
fetch**: NSJSONSerialization JSONObjectWithData:options:error: parses the
payload, the dictionary merges into **globalPrices** (fast enumeration x2),
persists through NSUserDefaults setDouble:forKey:, schedules an
`addOperationWithBlock:` on the saveQueue (the _NSConcreteStackBlock literal)
and notifies tradePortalUI (updatedPricesReceived) + updateTradePricesIfNeeded.
The other three callbacks feed it: `connection:didReceiveData:` (appendData:
into getPricesRecieveData / sendPricesRecieveData), `connection:didReceive
Response:` (setLength: reset) and `connection:didFailWithError:` (NSLog x2 +
buffer release).

## Decommission, cloud flags and DB bulk ops

`decommissionOldBlocks` (627w) walks the macroTiles through WorldHelper
`checkIfMacroTileCanBeDecommissioned:world:minAge:blockToSavePhyscialBlock:`
(original spelling; minAge immediate 0x1e = 30), collecting blocks in a
std::unordered_set<PhysicalBlock> (insert x2 + erase paths) with __wrap_free
x3 and an _Unwind_Resume tail. `isCloudGame` folds client/server + isCloudMatch
into one boolean; `cloudTopupSucceeded:` refreshes the store UI and re-arms the
credit timer (0x1e). The DB bulk pair opens/closes the databaseEnvironment
transaction (startBulkTransaction / finishBulkTransaction +
portalChestManager saveAnyPendingDataToDisk); appDatabase and
incrementalLoadCount are the small forwarders/getters.

## Boundaries

- wl_00 is census-grade (call histogram + selector/ivar/class tables +
  constants); the per-branch logic inside it is not claimed instruction by
  instruction.
- wl_05 connection:didReceiveResponse: listing is trimmed at the next IMP (the
  exidx entry over-covers into the neighbour); the header keeps the extracted
  ARM.exidx end.
- The SFHFKeychainUtils / NSOperationQueue / WorldHelper contracts are asserted
  at the selector level (forwarding calls); their implementations live in other
  classes and are outside this batch.
