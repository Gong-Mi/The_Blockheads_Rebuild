# World trade prices and IAP line (E108)

The World trade line: the prices-refresh engine, the pow-curve price math with the unsent-transaction queues, the server relay and the crystal/double-time store flow. 10 bodies, 2219 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| wt_00 | World -[updateTradePricesIfNeeded] | 0x005cbc30 | 707 | 19 | 8 | 6 | 11 | 34 | 19 |
| wt_01 | World -[updatePriceForItemBoughtOrSoldOfTypeKey:soldCount:] | 0x005cd6a8 | 453 | 10 | 2 | 5 | 2 | 18 | 9 |
| wt_02 | World -[transactionDataRecieved:fromClient:] | 0x005ce260 | 430 | 13 | 2 | 3 | 3 | 20 | 10 |
| wt_03 | World -[crystalsPurchased] | 0x005c44a0 | 198 | 6 | 1 | 2 | 0 | 10 | 9 |
| wt_04 | World -[worldPriceOffsetsRecievedFromServer:] | 0x005ceb18 | 165 | 4 | 1 | 1 | 0 | 8 | 7 |
| wt_05 | World -[purchaseDoubleTime] | 0x005c4228 | 158 | 6 | 3 | 2 | 2 | 7 | 1 |
| wt_06 | World -[IAPForWorldTopupSucceeeded:transactionID:] | 0x005d32ac | 39 | 2 | 1 | 1 | 0 | 2 | 0 |
| wt_07 | World -[doubleTimePurchaseTapped] | 0x005c2858 | 35 | 2 | 1 | 0 | 0 | 2 | 0 |
| wt_08 | World -[worldPriceMultipliers] | 0x005da150 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| wt_09 | World -[globalPrices] | 0x005da10c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |

## The prices-refresh engine (wt_00) and the fetch loop

`updateTradePricesIfNeeded` (707w) closes the E106 loop: it loads the bundled
price plist (NSPropertyListSerialization propertyListWithData:... over the main
bundle resource path), reads the last-update stamp from NSUserDefaults
(doubleForKey: vs NSDate timeIntervalSinceReferenceDate, constants 0xe / 0x3c
= 60), and when stale + connected + client builds the NSMutableURLRequest
(requestWithURL:cachePolicy:timeoutInterval:) over URLWithString: and kicks
`getPricesConnection` — the connection whose
`connectionDidFinishLoading:` (E106) parses this very response. The fetched
prices land in globalPrices; the per-world offsets arrive separately via
`worldPriceOffsetsRecievedFromServer:` (165w, gzipInflate + enumeration into
worldPriceMultipliers).

## The price math and the transaction queues (wt_01 / wt_02)

`updatePriceForItemBoughtOrSoldOfTypeKey:soldCount:` (453w) recomputes a price
multiplier with a pow() curve over soldCount and writes it back through
numberWithDouble:/numberWithFloat:; the persist runs as an
addOperationWithBlock: on the saveQueue, and the transaction is queued in
unsentGlobalTradeTransactions / unsentMultiplayerTradeTransactions.
`transactionDataRecieved:fromClient:` (430w) is the server-side intake of the
same records: pow()-scaled multipliers, saveQueue persist, then gzipDeflate +
sendNetworkData:toPeers:reliable: to relay the transactions to the other
clients (helper 0x55468c).

## Crystal purchases, double-time IAP and the getters

`crystalsPurchased` (198w) refreshes craftUI and calls
checkIfCanWarpInSecondBlockheadAfterItemAdded:dataB: over the blockheads — the
second-blockhead warp gate that E105's warp-in flow consumes.
`purchaseDoubleTime` (158w) stores store credentials through
SFHFKeychainUtils storeUsername:andPassword:forServiceName:updateExisting:
error: (the same keychain class as the E106 constructor), nudges
sendHeartbeatData and marks doubleTimeUnlocked; `doubleTimePurchaseTapped`
(35w) and `IAPForWorldTopupSucceeeded:transactionID:` (39w, original triple-e
spelling) are the store button/ack pair. worldPriceMultipliers (17w) and
globalPrices (17w) are the bare getters.

## Boundaries

- All ten bodies fully read (max 707w); no census members.
- The NSURLConnection / NSPropertyListSerialization / SFHFKeychainUtils
  contracts are asserted at the selector level; the store/pricing server side
  is outside this batch.
- The pow() curve's lane constants live in the artifact cells (pools
  0x5cd708/0x5cd710/0x5cd718), not re-derived here.
