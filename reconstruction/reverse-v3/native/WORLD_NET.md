# World class — E103: the net/admin core

The World net/admin core: the admin summary, the heartbeat family, the
welcome-back builder, the unique-ID grant and the remote quartet.
**21 bodies, 8016 verified words**, from the pinned original
`libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_worldnet.py` (hash-gated; `--check` reproduces
the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/world_net.json`.

## Load-bearing findings

- **The unique-ID grant**: `uniqueIDReturnedFromServer:` = 1416w with objc
  x25 + sel x37 + **0xc350 (50000)** - the per-object ID assignment with
  the **50000-object ceiling**.
- **The welcome-back builder**: `welcomeBackMessageForInfoDict:` = 2312w
  with **fast enumeration x5** + memset x5 (what changed while away).
- **The client sentinel**: clientConnected: touches the **0x7fffffff
  (INT_MAX)** cell (initial/unbounded ID state).
- **The kick code**: clientDisconnected:wasKick: carries **0x3e7 (999)**.
- **The heartbeat family**: heartbeatData (0x17=23 type code) / sendHeartbeat
  (pure packing) / heartbeatDataRecieved:fromPeer: (br x21 peer dispatch).
- **The remote quartet**: remoteCreate / remoteUpdate /
  remoteCreationDataUpdate / remoteRemove forObjectsOfType: - four 209-258w
  dispatchers of identical shape (pure message packing, no external calls).
- **The admin summary**: summaryNetDataForAdmin: = 1000w of objc dict
  packing + the 0x55468c helper.
- **The interest resolver**: peersInterestedInMacroIndex: (which peers
  watch this macro tile).

## Boundaries (honest)

- uncl 31/34: three cells (0xffed2e68 x2, the 0x7fffffff sentinel).
- The iCloud family (worldInfoForiCloudSave/fileWriteFailed:) is present
  but the iCloud backend itself is out of scope.

**World line status after E100-E103**: 83/322 bodies.
