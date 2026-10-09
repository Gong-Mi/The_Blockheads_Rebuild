# NPC core (E117)

The NPC class opens: the name-tag renderer, the net-state receive and tick giants (census-grade), the tame/economy loop, the riding and ownership checks and the creation wire format. 30 bodies, 11055 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| np_00 | NPC -[setBreed:] | 0x006513e4 | 18 | 0 | 0 | 1 | 0 | 0 | 0 |
| np_01 | NPC -[drawName:modelViewMatrix:pinchScale:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:] | 0x0064bf30 | 1832 | 20 | 7 | 15 | 3 | 67 | 42 |
| np_02 | NPC -[remoteCreationDataUpdate:] | 0x00647cf8 | 1432 | 35 | 4 | 13 | 2 | 63 | 91 |
| np_03 | NPC -[update:accurateDT:isSimulation:] | 0x006468d0 | 1261 | 19 | 2 | 29 | 0 | 37 | 55 |
| np_04 | NPC -[getSaveDict] | 0x00645aac | 803 | 9 | 18 | 17 | 2 | 37 | 14 |
| np_05 | NPC -[feedByBlockhead:] | 0x0064b398 | 695 | 19 | 2 | 13 | 2 | 27 | 25 |
| np_06 | NPC -[updatePosition:] | 0x00650b10 | 513 | 4 | 1 | 7 | 1 | 24 | 29 |
| np_07 | NPC -[checkCurrentPositionForFood] | 0x00650218 | 469 | 13 | 1 | 6 | 0 | 20 | 21 |
| np_08 | NPC -[npcCreationNetDataForClient:] | 0x00644e94 | 464 | 3 | 1 | 19 | 0 | 5 | 27 |
| np_09 | NPC -[successfulTame] | 0x0064ad80 | 390 | 5 | 2 | 3 | 2 | 22 | 6 |
| np_10 | NPC -[hitWithForce:blockhead:] | 0x00649894 | 355 | 15 | 2 | 9 | 2 | 15 | 10 |
| np_11 | NPC -[initWithWorld:dynamicWorld:atPosition:cache:saveDict:isAdult:wasPlaced:placedByClient:] | 0x00644718 | 259 | 9 | 2 | 4 | 1 | 10 | 10 |
| np_12 | NPC -[blockheadsLoaded] | 0x0064fd60 | 216 | 9 | 1 | 4 | 0 | 9 | 6 |
| np_13 | NPC -[setFreeByBlockhead:] | 0x0064f124 | 200 | 6 | 1 | 8 | 0 | 8 | 3 |
| np_14 | NPC -[generateNewName] | 0x0064a9f8 | 192 | 6 | 2 | 4 | 0 | 9 | 6 |
| np_15 | NPC -[addRider:] | 0x0064f6c8 | 182 | 8 | 1 | 5 | 0 | 8 | 3 |
| np_16 | NPC -[belongsToPlayerWithBlockhead:] | 0x0064e8d8 | 163 | 3 | 2 | 3 | 0 | 5 | 7 |
| np_17 | NPC -[captureByBlockhead:withItemType:] | 0x0064f444 | 161 | 6 | 1 | 6 | 0 | 6 | 4 |
| np_18 | NPC -[removeRider:] | 0x0064f9a0 | 148 | 5 | 1 | 5 | 0 | 5 | 3 |
| np_19 | NPC -[belongsToLocalPlayer] | 0x0064eb64 | 142 | 3 | 2 | 4 | 0 | 4 | 8 |
| np_20 | NPC -[appendNPCCreationDataToData:] | 0x0064567c | 136 | 5 | 2 | 1 | 3 | 5 | 3 |
| np_21 | NPC -[blockheadUnloaded:] | 0x00649fec | 135 | 2 | 1 | 5 | 0 | 2 | 4 |
| np_22 | NPC -[changeName:] | 0x0064e604 | 134 | 5 | 1 | 5 | 0 | 7 | 2 |
| np_23 | NPC -[die:] | 0x00649670 | 132 | 5 | 1 | 6 | 0 | 5 | 2 |
| np_24 | NPC -[mateWithNPC:] | 0x0064ef20 | 129 | 3 | 1 | 6 | 0 | 4 | 4 |
| np_25 | NPC -[initWithWorld:dynamicWorld:cache:netData:] | 0x00644ca0 | 125 | 2 | 2 | 5 | 1 | 2 | 2 |
| np_26 | NPC -[canBeFedByBlockhead:] | 0x0064a2f0 | 107 | 2 | 1 | 3 | 0 | 2 | 5 |
| np_27 | NPC -[dealloc] | 0x00646738 | 102 | 0 | 0 | 0 | 0 | 5 | 0 |
| np_28 | NPC -[setAdultCreationStartValues] | 0x0064448c | 87 | 1 | 1 | 3 | 0 | 5 | 0 |
| np_29 | NPC -[creationNetDataForClient:] | 0x0064589c | 73 | 3 | 1 | 0 | 1 | 4 | 2 |

## The NPC core (E117)

The NPC class opens with its operational core - 30 bodies, the interaction
family that the Donkey/DonkeyLike/Yak line (E96-E98) always had underneath it:

- **The three census giants**: drawName:modelViewMatrix:... (1832w) - the
  floating name-tag renderer (MJTextView + BitmapFont + drawShaderQuadNoTexture
  x2 + glUniform4f x2, name color by isClient/localNetID, the
  inspectingBlockhead variant); remoteCreationDataUpdate: (1432w) - the
  net-state receive dispatching the full interaction family; update:accurateDT:
  isSimulation: (1261w) - the tick with the environment reads
  (day-night/weather/season/temperature) driving the death and cooldown logic.
- **The tame/economy loop**: feedByBlockhead: (695w) with the
  **tameCountRequirementForNPCType(NPCType)** threshold and per-client tame
  counts (0x1fa4/0xa8c), successfulTame (390w - generateNewName + MJSoundManager
  playAtPosition + hearts particles), canBeFedByBlockhead: (107w, 0x1518).
- **Ownership and riding**: belongsToPlayerWithBlockhead:/
  belongsToLocalPlayer (163w/142w), addRider:/removeRider: (182w/148w),
  blockheadsLoaded (216w reconnect-by-index), setFreeByBlockhead: (200w),
  captureByBlockhead:withItemType: (161w - spawns the captured item via
  createFreeBlockAtPosition:...).
- **Combat and life cycle**: hitWithForce:blockhead: (355w), die: (132w),
  dealloc (102w), the placement ctor (259w), the net ctor (125w, 0x48-byte
  record), npcCreationNetDataForClient: (464w) + appendNPCCreationDataToData:
  (136w) + creationNetDataForClient: (73w) - the creation wire format.
- **Movement**: updatePosition: (513w - door/trapdoor/gate interactions on the
  move: tileContainsDoor x4 / tileContainsTrapDoor x2 / tileContainsGate x2)
  and checkCurrentPositionForFood (469w - chest looting at the position).
- The shared helper **0x6445d8** recurs across np_03/09/11/24/28 - and
  generateNewName (192w) is the client-side name picker (getNamesArray +
  __modsi3).

## Boundaries

- np_01/np_02/np_03 are census-grade (histogram + tables + constants); the
  other 27 read in full.
- The NSPropertyListSerialization / MJTextView / ParticleEmitter contracts are
  asserted at the selector level.
- np_28 listing is trimmed at the next IMP; header keeps the extracted end.
