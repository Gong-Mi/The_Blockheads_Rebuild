# Action (E154)

The multiplayer player-row button lands: the touch cycle, the button dispatch, the moderation actions and the player-state refresh. 36 bodies, 4048 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). Every listing regenerates byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| npb_00 | NetPlayerButton -[banButtonTapped] | 0x00788798 | 32 | 1 | 1 | 2 | 0 | 1 | 0 |
| npb_01 | NetPlayerButton -[buttonAction:] | 0x00788188 | 204 | 7 | 1 | 6 | 1 | 7 | 4 |
| npb_02 | NetPlayerButton -[cloudMode] | 0x00788cf4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_03 | NetPlayerButton -[connected] | 0x00788af4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_04 | NetPlayerButton -[dealloc] | 0x007853f4 | 105 | 2 | 2 | 5 | 1 | 6 | 0 |
| npb_05 | NetPlayerButton -[endTouch:] | 0x00787fb0 | 118 | 3 | 1 | 1 | 1 | 4 | 3 |
| npb_06 | NetPlayerButton -[initWithFrame:cache:windowInfo:alignment:world:worldUI:] | 0x00784e1c | 355 | 11 | 10 | 11 | 4 | 13 | 2 |
| npb_07 | NetPlayerButton -[isAdmin] | 0x00788bf4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_08 | NetPlayerButton -[isMod] | 0x00788c74 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_09 | NetPlayerButton -[isOwner] | 0x00788b74 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_10 | NetPlayerButton -[kickButtonTapped] | 0x00788818 | 32 | 1 | 1 | 2 | 0 | 1 | 0 |
| npb_11 | NetPlayerButton -[local] | 0x007889f4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_12 | NetPlayerButton -[moveTouch:] | 0x00787df4 | 111 | 3 | 1 | 1 | 1 | 4 | 2 |
| npb_13 | NetPlayerButton -[muteButtonTapped] | 0x00788630 | 90 | 2 | 1 | 5 | 0 | 2 | 0 |
| npb_14 | NetPlayerButton -[muted] | 0x00788d74 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_15 | NetPlayerButton -[playerID] | 0x0078896c | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_16 | NetPlayerButton -[playerName] | 0x007889b0 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_17 | NetPlayerButton -[playerUIIsVisible] | 0x00788918 | 21 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_18 | NetPlayerButton -[renderFrame:projectionMatrix:] | 0x00785864 | 498 | 4 | 1 | 7 | 2 | 7 | 7 |
| npb_19 | NetPlayerButton -[renderUI:projectionMatrix:] | 0x0078602c | 155 | 1 | 0 | 1 | 0 | 1 | 0 |
| npb_20 | NetPlayerButton -[reportButtonTapped] | 0x00788898 | 32 | 1 | 1 | 2 | 0 | 1 | 0 |
| npb_21 | NetPlayerButton -[setCloudMode:] | 0x00788d30 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_22 | NetPlayerButton -[setConnected:] | 0x00788b30 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_23 | NetPlayerButton -[setFrame:] | 0x00786298 | 152 | 2 | 1 | 5 | 1 | 5 | 0 |
| npb_24 | NetPlayerButton -[setFrame:windowInfo:alignment:] | 0x00785598 | 179 | 2 | 1 | 6 | 1 | 5 | 0 |
| npb_25 | NetPlayerButton -[setIsAdmin:] | 0x00788c30 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_26 | NetPlayerButton -[setIsMod:] | 0x00788cb0 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_27 | NetPlayerButton -[setIsOwner:] | 0x00788bb0 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_28 | NetPlayerButton -[setLocal:] | 0x00788a30 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_29 | NetPlayerButton -[setMuted:] | 0x00788db0 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_30 | NetPlayerButton -[setTextChatEnabled:] | 0x00788ab0 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_31 | NetPlayerButton -[startTouch:] | 0x00787d04 | 60 | 1 | 0 | 1 | 1 | 2 | 2 |
| npb_32 | NetPlayerButton -[textChatEnabled] | 0x00788a74 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| npb_33 | NetPlayerButton -[textToggleButtonTapped] | 0x007884b8 | 94 | 3 | 2 | 2 | 1 | 3 | 0 |
| npb_34 | NetPlayerButton -[touchIsInUI:] | 0x00787c14 | 60 | 1 | 0 | 1 | 1 | 2 | 2 |
| npb_35 | NetPlayerButton -[updatedPlayerIfNeeded:] | 0x007864f8 | 1460 | 26 | 19 | 21 | 3 | 62 | 50 |

## Findings (E156)

NetPlayerButton — the per-player row button of the multiplayer player list (owned by WorldUI). 36 bodies / 4048 words decoded from the pinned original `libApplication.so` (armeabi-v7a, sha256 `733d8210...c30b94c7`). IMP span `0x00784e1c` `-[initWithFrame:cache:windowInfo:alignment:world:worldUI:]` .. `0x00788db0` `-[setMuted:]`; the class is an MJButton subclass (class_metadata super = MJButton), instance_size 328, 18 ivars at 276..324. Listings regenerate byte-identically from the pinned r2 recipe; every literal-pool cell, selector, import, ivar and class reference was cross-checked against the GNU listings and re-resolved (file offset == vaddr) against the ELF.

| body | method | words | br | calls | grade |
|---|---|---|---|---|---|
| npb_00 | `NetPlayerButton -[banButtonTapped]` | 32 | 0 | 1 | read |
| npb_01 | `NetPlayerButton -[buttonAction:]` | 204 | 4 | 7 | read |
| npb_02 | `NetPlayerButton -[cloudMode]` | 15 | 0 | 0 | read |
| npb_03 | `NetPlayerButton -[connected]` | 15 | 0 | 0 | read |
| npb_04 | `NetPlayerButton -[dealloc]` | 105 | 0 | 6 | read |
| npb_05 | `NetPlayerButton -[endTouch:]` | 118 | 3 | 4 | read |
| npb_06 | `NetPlayerButton -[initWithFrame:cache:windowInfo:alignment:world:worldUI:]` | 355 | 2 | 13 | read |
| npb_07 | `NetPlayerButton -[isAdmin]` | 15 | 0 | 0 | read |
| npb_08 | `NetPlayerButton -[isMod]` | 15 | 0 | 0 | read |
| npb_09 | `NetPlayerButton -[isOwner]` | 15 | 0 | 0 | read |
| npb_10 | `NetPlayerButton -[kickButtonTapped]` | 32 | 0 | 1 | read |
| npb_11 | `NetPlayerButton -[local]` | 15 | 0 | 0 | read |
| npb_12 | `NetPlayerButton -[moveTouch:]` | 111 | 2 | 4 | read |
| npb_13 | `NetPlayerButton -[muteButtonTapped]` | 90 | 0 | 2 | read |
| npb_14 | `NetPlayerButton -[muted]` | 15 | 0 | 0 | read |
| npb_15 | `NetPlayerButton -[playerID]` | 17 | 0 | 0 | read |
| npb_16 | `NetPlayerButton -[playerName]` | 17 | 0 | 0 | read |
| npb_17 | `NetPlayerButton -[playerUIIsVisible]` | 21 | 0 | 0 | read |
| npb_18 | `NetPlayerButton -[renderFrame:projectionMatrix:]` | 498 | 7 | 7 | read |
| npb_19 | `NetPlayerButton -[renderUI:projectionMatrix:]` | 155 | 0 | 1 | read |
| npb_20 | `NetPlayerButton -[reportButtonTapped]` | 32 | 0 | 1 | read |
| npb_21 | `NetPlayerButton -[setCloudMode:]` | 17 | 0 | 0 | read |
| npb_22 | `NetPlayerButton -[setConnected:]` | 17 | 0 | 0 | read |
| npb_23 | `NetPlayerButton -[setFrame:]` | 152 | 0 | 5 | read |
| npb_24 | `NetPlayerButton -[setFrame:windowInfo:alignment:]` | 179 | 0 | 5 | read |
| npb_25 | `NetPlayerButton -[setIsAdmin:]` | 17 | 0 | 0 | read |
| npb_26 | `NetPlayerButton -[setIsMod:]` | 17 | 0 | 0 | read |
| npb_27 | `NetPlayerButton -[setIsOwner:]` | 17 | 0 | 0 | read |
| npb_28 | `NetPlayerButton -[setLocal:]` | 17 | 0 | 0 | read |
| npb_29 | `NetPlayerButton -[setMuted:]` | 17 | 0 | 0 | read |
| npb_30 | `NetPlayerButton -[setTextChatEnabled:]` | 17 | 0 | 0 | read |
| npb_31 | `NetPlayerButton -[startTouch:]` | 60 | 2 | 2 | read |
| npb_32 | `NetPlayerButton -[textChatEnabled]` | 15 | 0 | 0 | read |
| npb_33 | `NetPlayerButton -[textToggleButtonTapped]` | 94 | 0 | 3 | read |
| npb_34 | `NetPlayerButton -[touchIsInUI:]` (TRIMMED) | 60 | 2 | 2 | read |
| npb_35 | `NetPlayerButton -[updatedPlayerIfNeeded:]` | 1460 | 50 | 62 | census |

Call-column totals: 126 call rows across the 36 bodies (73 `blx rN` indirect sends, 35 `bl loc.imp.objc_msgSend`, 8 `bl loc.imp.objc_msgSendSuper2`, 6 `bl 0x7853a8` rect packer, 4 `bl 0x787bc8` colour packer). npb_35 alone carries 62 of them (47 `blx rN` + 9 `bl loc.imp.objc_msgSend` + 4 `bl 0x787bc8` + 2 `bl 0x7853a8`); the other pack4 sites are npb_06, npb_18, npb_23 and npb_24 (1 each). Grades: npb_35 is [census] (full 62-row send census, complete constant-pool and key-string resolution, 50-branch map, block walk); every other body including the 355- and 498-word ones was read line-by-line through the annotated register-tracking digest.

Structure of the class that the 36 bodies expose:

- **Fields (18 ivars, offsets from class_metadata)**: standardShader@276, world@280, worldUI@284, alignment@288, playerUI@292, avatarImage@296, mutedImage@300, hasAvatar@304, local@305, playerID@308, playerName@312, textChatEnabled@316, connected@317, isOwner@318, isAdmin@319, isMod@320, muted@321, cloudMode@324. Every accessor in this batch hits exactly these offsets; scalars use `ldrsb`/`strb` (cloudMode is the only `str`/`int`), object getters carry `dmb ish`, char setters carry `dmb ish` on both sides of the store.
- **Touch cycle**: `touchIsInUI:` (npb_34) and `startTouch:` (npb_31) are delegate wrappers — send to super via objc_msgSendSuper2 and, when super returns 0, re-send the same selector to `self->playerUI`. `moveTouch:` (npb_12) and `endTouch:` (npb_05) additionally drop `self->playerUI` (inline ARC strong-store-to-nil: `objc_msgSend(playerUI, autorelease)` then store 0 into the slot) when the point leaves the sub-UI, then forward `[super moveTouch:/endTouch:]` and `[playerUI moveTouch:/endTouch:]`.
- **buttonAction:** (npb_01) is the row's tap entry (target/action wired at ctor time). It ignores its argument; for non-local rows it first asks `[self->worldUI canZoomCameraToOtherPlayer]` and sends `zoomButtonTappedForButton:self`, then builds the popup exactly once: `playerUI = [[NetPlayerUI alloc] initWithWindowInfo:self->windowInfo netPlayerButton:self cache:self->cache localPlayerIsMod:[self->world isMod] showReportButton:[self->world isCloudGame]]` followed by `[self->world hideChatView]`.
- **Four action callbacks**: banButtonTapped (npb_00) -> `[world banPlayerWithNameFromPlayerButton:self->playerName]`; kickButtonTapped (npb_10) -> `kickPlayerWithNameFromPlayerButton:`; reportButtonTapped (npb_20) -> `reportButtonTappedForPlayer:`; muteButtonTapped (npb_13) -> toggles `muted`, then `[world setPlayerMuted:muted withID:playerID]` + `[playerUI windowInfoChanged:self->windowInfo]`.
- **Chat toggle**: textToggleButtonTapped (npb_33) flips `textChatEnabled@316`, persists `setBool:!textChatEnabled forKey:@"textChatDisabled"` on NSUserDefaults (CFString literal at file offset 0xf90118), then `[self->worldUI textToggleButtonTappedForButton:self]`.
- **Ctor** (npb_06): super `initWithFrame:cache:windowInfo:textureName:@"InventoryButtonBackground.png"`; `cloudMode=0`, `connected=1`, `textChatEnabled = !boolForKey(@"textChatDisabled")`; `standardShader = shaderNamed:@"StandardObject" attributes:[position,texCoord] uniforms:[mvp_matrix,texture]` (literal strings at 0xf90138..0xf90178); `avatarImage = [[MJImageView alloc] initWithFrame:CGRectInset(frame,4,4) cache/ windowInfo/ texture:@"noGCAvatar.png"]`; selected texture `"InventoryButtonBackgroundSelected.png"`; `setTarget:self action:buttonAction:`.
- **Layout** (npb_23 / npb_24): super setFrame, then `MJView.windowInfo@52`/`alignment@288` writes only in the 3-arg form; npb_23 sizes avatarImage/mutedImage to the raw frame, npb_24 to the 4-inset frame; both end with `[playerUI windowInfoChanged:self->windowInfo]` when playerUI exists. Both use helper `0x007853a8` to pack four floats (x,y,w,h) into a local CGRect.
- **Render** (npb_18): super render, bail on `MJView.hidden@4`; `muted` -> lazily build `mutedImage@300` with `"avatarMuted.png"` (0xf90198) and render it; else render `avatarImage@296` (early-out when nil). npb_19 `renderUI:projectionMatrix:` is a bare trampoline to `[self->playerUI renderFrame:pt projectionMatrix:m]`.
- **updatedPlayerIfNeeded:** (npb_35, census): see semantics_netplayerbutton.json for the full block-by-block account. Key facts: per-player dictionary with keys `playerID`(0xf901a8), `local`(0xf901b8), `mod`(0xf901c8), `owner`(0xf901d8), `admin`(0xf901e8), `supermod`(0xf901f8), `mode1`(0xf90208), `mode2`(0xf90218), `photo`(0xf90268), `alias`(0xf90278), `connected`(0xf90288); cloudMode sentinels 0xA8F4 ("mode1") / 0x4D83 ("mode2"); background texture chain InventoryButtonBackground.png (0xf90108) / ...Owner (0xf90228) / ...ModRed (0xf90238) / ...Admin (0xf90248) / ...Mod (0xf90258); avatar rebuilt via UIImage imageWithData: + CPTexture2D initWithUIImage:, fallback `noGCAvatar.png` (0xf90188); connected colours packaged with helper 0x00787bc8 — {1,1,1,1} when connected, {0.1,0.1,0.1,1.0} (0x3dcccccd) for the row and {0.2,0.2,0.2,0.5} (0x3e4ccccd, 0x3f000000) for the avatar when not; a changed-flag gates the final `[playerUI windowInfoChanged:self->windowInfo]`.
- **Detached helpers hit by this batch** (outside the class, documented because they are the only `bl` targets): `0x007853a8` and its byte-identical twin `0x00787bc8` — 19-instruction leaf functions `pack4(float a=r1, float b=r2, float c=r3, float d=[sp], float* out=r0)` (vmov s0..s6 from r3/r2/r1/stack, four vldr/vstr pairs, bx lr) that store r1/r2/r3/stack into out[0..12]; not ObjC methods.

## Boundaries

- **npb_34 is TRIMMED** (roster note): ARM.exidx end is `0x00787df4` but the body is cut at the next ObjC IMP `0x00787d04` `-[startTouch:]`; the recorded window/word count is the listing 0x00787c14..0x00787d04 = 60 words. The range 0x787d04..0x787df4 that the exidx range would have swallowed is exactly npb_31 (startTouch:, also 60 words), so nothing of npb_34 is lost.
- **npb_06 window ends at the exidx bound `0x007853a8`**, which is *below* the next class IMP `-[dealloc]` at `0x007853f4`: the gap 0x7853a8..0x7853f4 is the pack4 float helper described above (called from npb_06, npb_18, npb_23 and npb_24), not a NetPlayerButton method. It has a byte-identical twin at 0x787bc8.
- **npb_35 window ends exactly where the second pack4 helper begins**: the roster bound is `0x00787bc8` — the address of the twin helper (its byte-identical copy at 0x7853a8 is what npb_06/18/23/24 call, while npb_35 calls this copy four times). The window [0x7864f8, 0x787bc8) = 1460 words ends with the method's literal cells (last data word 0x787bc4) and npb_35's own epilogue sits at 0x787b04..0x787b08; the helper code at 0x787bc8..0x787c10 is documented in the notes above but is NOT among the counted 1460 words.
- **cloudMode sentinel values** 0xA8F4 / 0x4D83 are byte-exact in the listing (`movw r0, 0xa8f4` at 0x7867d4/0x786c80, `movw r0, 0x4d83` at 0x786858/0x786d58/0x786e30) but their *meaning* is inferred from the pairing with the `supermod` key's "mode1"/"mode2" strings; the role-to-background matrix (Owner / ModRed on admin+0xA8F4 / Admin / Mod / default, with 0x4D83 forcing the default for admin and mod) is as observed in the branch chain, no UX doc was consulted.
- **R2 vs GNU**: r2 renders the raw literal words as mis-parsed instructions (`invalid`, `addeq ...`) — those words are data (PIC bases, negative import offsets, CFString/ivar/selector slots). All VFP immediates quoted here (4.0 = vmov.f32 #16, 8.0 = #32; 1.0 = 0x3f800000, 0.5 = 0x3f000000, 0.2 = 0x3e4ccccd, 0.1 = 0x3dcccccd) come from the GNU cross-check listings.
- **Strings** were resolved from the CFString literal structs (file offset == vaddr) at 0xf90108..0xf90288; the file-offset and the object address legitimately differ (e.g. literal 0xf90118 = "textChatDisabled").
- `-[buttonAction:]`'s argument is dead in the binary (spilled to fp-0x24, never re-read) and the two `worldUI` sends re-pass `self`; recorded as observed, not as intent.
- dealloc (npb_04) releases playerID, playerUI, avatarImage, mutedImage, playerName in that order and does **not** release standardShader@276, world@280, worldUI@284, matching the asymmetry already logged for sibling UI classes (e.g. TrainStation shaders) — flagged, not reconciled.
- No body in this batch references `hasAvatar` writes other than updatedPlayerIfNeeded: (npb_35); npb_06's ctor leaves it 0, so first refresh forces the avatar rebuild path.

