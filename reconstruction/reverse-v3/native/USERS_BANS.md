# DynamicWorld users/bans/session smalls — E33

The users/bans/session smalls: the mute/ban propagators, the ban query, the
player-list broadcast, the owner-name resolver, the client-control check, the
pickup reply, the blockhead lookup and the debug chest loader.
**9 bodies, 1013 verified words**, from the pinned original `libApplication.so`
(1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_users.py` (hash-gated; `--check` reproduces the
artifact byte for byte). Artifact: `reconstruction/reverse-v3/native/users_bans.json`.

| body | imp | words | content |
|---|---|---:|---|
| isControllingBlockheadsForClientPlayer: | 0x008fdbf0 | 175 | client-control check |
| blockheadWithUniqueID: | 0x008f7000 | 139 | blockhead lookup |
| userBanChanged:isBanned: | 0x009025e4 | 138 | ban propagator |
| remotePickupRequestReply: | 0x008f722c | 127 | pickup reply applier |
| playersChanged | 0x009028c8 | 126 | player-list broadcast |
| userMuteChanged: | 0x009023f4 | 124 | mute propagator |
| loadDebugChestAtPos:chest: | 0x009067e0 | 110 | debug chest loader |
| playerIsBannedWithID: | 0x0090280c | 47 | ban query |
| getOwnerNameForObjectOwnerID: | 0x00902ac0 | 27 | owner-name resolver |

## Load-bearing findings

- **Client registry family**: the mute/ban propagators both walk the **ffffe54c
  member's +0x270 client slice** (per-node ffe237a8 / ffe237ac with the sxtb'd
  flag) and take the **ffffe51c registry lookup**; `playerIsBannedWithID:`
  resolves through ffe237b0; `getOwnerNameForObjectOwnerID:` chains the
  ffffe51c slot into ffe237b8 — the client/player registry quartet.
- **playersChanged** enumerates the ffffe4f4 netBlockheads with the ffe237b4
  per-player notice.
- **blockheadWithUniqueID:** enumerates the **ffffe4f8 blockheads collection**
  and compares `[bh uniqueID]` via the **eor/orr 64-bit equality** — the
  canonical uniqueID lookup.
- **isControllingBlockheadsForClientPlayer:** fast path through the ffffe5ac
  dict (ffe233d4) then the **ffffe4f0** local-client collection enumeration with
  the ffe233a4/ffe23444 clientID match.
- **remotePickupRequestReply:** parses 16-byte units with a **VLA stack
  alloc** (`lsr r1, r0, 3; bfc r0, 0, 3; sub r0, r1, r0; mov sp, r0`) and
  applies via ffe236dc/ffe236e4 — the 16-byte IDs match E28's
  clientPickupRequest:count:clientID:blockheadRequesterUniqueID:.
- **loadDebugChestAtPos:chest:** the full registration writer (ffffe550 12-byte
  segment + ffffe554 worldIndex map + the ffe232a0 flag-1) — the same shape as
  E26's interaction placer and E30's adder family.

## Boundaries (honest)

- All dispatch cells pinned by cell; the +0x270 slice identity is inference
  from the client-registry calls (pinned by offset, not name); the VLA alloc is
  read from the stack arithmetic; all 14 uncl cells resolve as PIC base
  anchors (clean). Note: `setPaused:` was attempted for this batch but is
  already covered by E27 (BREED_NPC) and was replaced by loadDebugChestAtPos:.
