# CameraUI photo-mode domain — CameraUI, UIManager camera flags, World photo chain

The photo-mode domain: the in-game camera UI (`CameraUI`), the UIManager
camera-flag trio, and the World photo pipeline from `glReadPixels` to the
photo library. 21 bodies, **3024 verified words** total, recovered from the
pinned original `libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`); every
instruction word re-verified, tool refuses to emit on drift
(`tools/recover_camera_ui.py`; JSON: `camera_ui.json`).

## CameraUI (11 bodies)

- **`initWithWorld:windowInfo:cache:`** (`0x009d414c`..`0x009d522c`, 1080w).
  `objc_msgSendSuper2` init; nil guard; stores **World@20 / windowInfo@96 /
  cache@100**; creates the border-line shader via
  `shaderNamed:attributes:uniforms:` (**borderLineShader@24**) and the two
  buttons via `initWithFrame:cache:windowInfo:title:` (**cancelButton@104 /
  takePhotoButton@108**) with `textureNamed:` / `setBackgroundTexture:` /
  `setBackgroundSelectedTexture:`; computes the button geometry via helpers
  **`0x009d522c` / `0x009d5384`** (constant family +/-1000, 125, 120, 40
  bounds); `memcpy` 0x40 bytes; applies the elements; return self.
  `texCoordsForItemType:` (`0x004d6040`) supplies the button artwork.
- **`dealloc`** (64w): releases the view objects (ivars eb78 / eb7c) +
  `objc_msgSendSuper2(super, dealloc)`.
- **`windowInfoChanged:`** (`0x009d54d0`..`0x009d5c24`, 469w): stores the
  new WindowInfo; reads the size floats; recomputes the four button rects
  (helper `0x009d522c` once + `0x009d5384` x4 with constants +/-1000,
  -125, 120, 49, -52, 64, 5, -60); `memcpy` 0x40 bytes from the
  WindowInfo; applies the layout via `objc_msgSend`.
- **`render:translation:pinchScale:`** (`0x009d5c24`..`0x009d6054`, 268w):
  `objc_msgSendSuper2(super, render:...)`; then GL work:
  `glEnableVertexAttribArray(0)` / `(1)`, **`glEnable(GL_BLEND 0xbe2)`**;
  submits two 16-float `_GLKMatrix4` uniform packets (shader objects from
  ivars eb78 / eb7c via the `0xe24990` selector); then
  `glDisableVertexAttribArray` x2 + `glDisable(0xbe2)` restore.
- Touch family (same-selector forwards to the two button objects /
  World): **`touchIsInViewAtAll:`** (32w) = deltas + unconditional YES;
  **`touchIsInUI:`** (78w) = `[cancelButton touchIsInUI:pt] ||
  [takePhotoButton touchIsInUI:pt]`; **`startTouch:tapCount:`** (99w) =
  two-stage `startTouch:` acceptance OR; **`moveTouch:`** / **`endTouch:`**
  (66w each) = delta-pair forwards (2x objc_msgSend); **`cancelButton:`**
  / **`takePhotoButton:`** (26w each) = single forwards to the World
  (`cancelTakePhotoButtonTapped` / `takePhotoButtonTapped`).

## UIManager camera flags (3 bodies)

- **`showCameraUI`** (28w): when the camera-UI field == 0 -> set the active
  flag byte = 1.
- **`dismissCameraUI`** (15w): ldrsb getter of the dismiss flag.
- **`setDismissCameraUI:`** (17w): stores the byte with **`dmb ish`**
  barriers before/after (flagged atomic write).

## World photo chain (7 bodies)

- **`doCameraScreenshot`** (`0x005c3278`..`0x005c3800`, 354w): permission
  gate = `[NoodlePermissionGranter isPermissionGranted:...]`; not granted
  -> `requestPermission:withRationaleMessage:` and return. Granted path:
  photo-state = 2, sub-flag = 1; w/h = floats x scale (`vcvt.s32`);
  `__wrap_malloc(w*h*4)`; **`glReadPixels(0, 0, w, h, GL_RGBA 0x1908,
  GL_UNSIGNED_BYTE 0x1401, buf)`**; `CGDataProviderCreateWithData` +
  `CGColorSpaceCreateDeviceRGB` + **`CGImageCreate`** (8 bpc / 32 bpp /
  w*4 stride) -> `[UIImage imageWithCGImage:]` with `rotate:`; flag == 0
  -> **`UIImageWriteToSavedPhotosAlbum`**
  else the share path; state restore; `CGColorSpaceRelease` +
  `CGDataProviderRelease` + `__wrap_free`.
- **`startUsingCamera`** (59w): **`[pauseUpdates]` + `[UIManager
  showCameraUI]`** + photo-state = 1 + flag byte = 0 — enters photo mode.
- **`takePhotoButtonTapped`** (43w):
  **`[reportAchievementWithIdentifier:]` + `[self doCameraScreenshot]`**
  + request flag byte = 1.
- **`cancelTakePhotoButtonTapped`** (93w) / **`sharePhotoFinished`** (93w):
  structural twins — **`[sendHeartbeatData]` + `[setPaused:]` +
  `[UIManager setDismissCameraUI:]`** + clear the photo-state flag.
- **`takingPhoto`** (33w) = `[self cameraUI] != 0`;
  **`hasJustTakenPhoto`** (15w) = ldrsb of the photo-state byte.

## Anchors

- Cells: CameraUI ivars **windowInfo@96 / orthoMatrix@32 /
  borderLineShader@24 / cache@100 / world@20 / cancelButton@104 /
  takePhotoButton@108**; UIManager **cameraUI@100 / showCameraUITapped@151 /
  dismissCameraUI@147**; **World.hasJustTakenPhoto@3080**; the
  `0xe24994`/`0xe24998`/`0xe2499c`/`0xe249a0`/`0xe249a4`/`0xe249a8`/`0xe24988`/
  `0xe24990` selectors, World photo selectors (`0xe1ebc4`/`0xe1eae0`/
  `0xe1ebd0`/`0xe1e328`/`0xe1e32c`), UIManager flag chains.
- All 100 call sites pinned (30/3/11/9/0/2/2/2/2/1/1/0/0/0/23/2/2/4/1/4/0),
  all 31 branches, 115 instruction anchors.
- Key callees: helpers `0x009d522c` / `0x009d5384`; `texCoordsForItemType:`
  (`0x004d6040`); GL/Quartz: `__wrap_glReadPixels` (`0x001c3fe0`),
  `__wrap_glEnable/Disable` / `...VertexAttribArray`, `CGImageCreate`
  (`0x001c3434`), `CGColorSpaceCreateDeviceRGB` (`0x001c311c`),
  `CGDataProviderCreateWithData` (`0x001c3428`),
  `UIImageWriteToSavedPhotosAlbum` (`0x00256560`), `__wrap_malloc/free`.

## Boundaries

- `World render:cameraZ:projectionMatrix:pinchScale:` (`0x0058c7f8`, the
  30580-word world renderer) is a separate campaign and NOT part of this
  batch; `CameraUI .cxx_construct` (69w) and the UIManager accessor family
  after `setDismissCameraUI:` are out of batch. `cam_move` trimmed to its
  next IMP (exidx over-covered `0x009d65a8`); `ui_setdismiss` trimmed to
  `0x00ade470` (accessor family follows in the same exidx row).
- This closes the CameraUI photo-mode domain of the first-stage six-domain
  inventory.
