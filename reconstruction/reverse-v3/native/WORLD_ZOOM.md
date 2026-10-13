# World camera/zoom/motion line (E107)

The World camera line: the net-blockhead zoom request chain, the zoom-to-workbench open flow and the motion-to-camera calibration pipeline. 9 bodies, 2503 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| wz_00 | World -[zoomToActiveNetBlockheadForPlayer:] | 0x005c4c28 | 627 | 21 | 3 | 5 | 4 | 33 | 25 |
| wz_01 | World -[getBlockheadZoomPosForClient:requesterClient:cycleIndex:] | 0x005c55f4 | 390 | 11 | 1 | 2 | 1 | 23 | 19 |
| wz_02 | World -[zoomToPortalAtPosition:] | 0x005c8e98 | 313 | 11 | 1 | 2 | 0 | 18 | 5 |
| wz_03 | World -[remoteZoomRequestReturnedWithSuccess:point:] | 0x005c5c0c | 53 | 1 | 0 | 1 | 0 | 1 | 2 |
| wz_04 | World -[activeBlockheadPos] | 0x005c60ac | 74 | 2 | 1 | 2 | 0 | 3 | 5 |
| wz_05 | World -[acceleration:] | 0x005be998 | 583 | 5 | 1 | 10 | 1 | 34 | 19 |
| wz_06 | World -[motionUpdatePingAccelerometer] | 0x005bf528 | 132 | 3 | 1 | 1 | 0 | 9 | 6 |
| wz_07 | World -[motionUpdatePingDeviceMotion] | 0x005bf738 | 82 | 3 | 1 | 1 | 0 | 5 | 2 |
| wz_08 | World -[endCalibration] | 0x005be378 | 249 | 0 | 0 | 4 | 0 | 17 | 2 |

## The net-blockhead zoom chain (wz_00 / wz_01 / wz_03)

`zoomToActiveNetBlockheadForPlayer:` (627w) is a client/server pair: the client
half builds a dictionaryWithObject:forKey: (numberWithInt: cycle count) and
sends it with `sendDataToServer:reliable:` after appendData:/dataWithBytes:
length: packing; the server half enumerates allBlockheadsIncludingNet, matches
clientID, checks visibility through `tileIsLitForClient:atPos:tile:` and zooms
with `zoomToPos:pinchZoom:`. Guards: clientZoomRequestSent +
zoomPlayerCycleCounts (the cycle counter wraps via __umodsi3). The constants
0x10/0x20/0x1b bound the packet and cycle logic and the tail calls helper
0x55468c. `getBlockheadZoomPosForClient:requesterClient:cycleIndex:` (390w) is
the server-side picker: same enumeration/filter, then cycleIndex % count
(__umodsi3) picks the target and makeIntpair + tileAtWorldPositionLoaded build
the pos. `remoteZoomRequestReturnedWithSuccess:point:` (53w) is the client
response handler (zoomToPos:pinchZoom: on success). `activeBlockheadPos` (74w)
is the camera anchor with the startPortalPos fallback.

## The zoom-to-workbench open flow (wz_02)

`zoomToPortalAtPosition:` (313w) looks up workbenchAtPos:, zooms
(zoomToPos:pinchZoom:) and then runs the UI half: setDisplayed:,
addBlockheadUI, setWorkbench:blockhead:craftableItemObject:,
numberOfCraftableItems, setSelectedIndex: and craftUI, gated by isCloudGame.

## The motion-to-camera pipeline (wz_05 - wz_08)

`acceleration:` (583w) is the merge point: interfaceOrientation comes from
UIApplication statusBarOrientation, the requiresMotionEvents gate filters
consumers, and the acceleration vector is smoothed into
longTermAveragedAcceleration, transformed by calibrationMatrix
(Vector::multiplyMatrix) and turned into moveUpDownFraction /
moveLeftRightFraction through Vector::normal/normalize + clamp_float (Vector
ops x30). The two pings feed it: motionUpdatePingAccelerometer (132w, reads
motionManager accelerometerData, 0x18-byte struct) and
motionUpdatePingDeviceMotion (82w, motionManager gravity). `endCalibration`
(249w) builds the calibration basis: Vector::cross (cross_Vector_) +
Vector::normal from longTermAveragedAcceleration, stores calibrationMatrix and
sets hasCalibrated.

## Boundaries

- All nine bodies are read in full or near-full (max 627w); no census-grade
  members in this batch.
- The motionManager / UIApplication / NSURLConnection-adjacent contracts are
  asserted at the selector level (forwarding calls); their implementations
  live in the system frameworks and are outside this batch.
- The calibration math is described at the operation level (cross/normal/
  multiplyMatrix); individual lane constants are recorded in the artifact
  cells, not re-derived here.
