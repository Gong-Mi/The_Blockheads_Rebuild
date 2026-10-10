# World class — E102: the renderer

The World renderer: the **29808w** draw giant (92 glVertexAttribPointer, 56
glBindTexture, the depth-mask stack) plus the load/zoom/screenshot family.
**14 bodies, 33840 verified words**, from the pinned original
`libApplication.so` (1.7.6, armeabi-v7a, SHA-256
`733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7`).

Recovered by `tools/recover_worldrender.py` (hash-gated; `--check`
reproduces the artifact byte for byte). Artifact:
`reconstruction/reverse-v3/native/world_render.json`.

## Load-bearing findings

- **The render giant** (`render:cameraZ:projectionMatrix:pinchScale:` =
  **29808w**, sel x101, 1121 calls, 394 branches, 240 ivars — the largest
  World body): **glVertexAttribPointer x92** (the batched-vertex pipeline),
  **glBindTexture x56**, **glActiveTexture x46**, glUniform4f x34,
  glEnableVertexAttribArray x27, glUniform1i x26, glUniformMatrix4fv x24,
  glDisableVertexAttribArray x22, glUseProgram x18, **glDrawElements x16 +
  glDrawArrays x10**, **pushDepthMaskState/popDepthMaskState x12/x11**
  (the depth-state stack), glEnable/glDisable x12/x9, floor x8,
  drawShaderQuad x5, glBlendFunc x5; operator float* x154+x81 (Vector).
- **The GL constant set**: **0xbe2 (GL_BLEND)**, **0xde1 (GL_TEXTURE_2D)**,
  **0x1406 (GL_FLOAT)**, 0x1401 (GL_UNSIGNED_BYTE), 0x1403
  (GL_UNSIGNED_SHORT), **0x84c0/0x84c1/0x84c2 (GL_TEXTURE0-2)**, **0x303
  (GL_ONE_MINUS_SRC_ALPHA)**, 0x800, 0x432 (the 1074 draw range), 0x100,
  plus the float pool 0x3f80/0x3f00/0xcccd and the cell 0xc2000000
  (**-32.0f**).
- **The lazy-load family**: loadDynamicObjectsIfNotAlreadyLoaded /
  loadLightBlockForClientLightBlockIndex / physicalBlockToLoadByClient
  TileLoader / fullyLoadAndUpdateIfNeeded / fullyLoadIfNeededAroundPos
  (the 3x3 macro sweep).
- **The capture family**: doPortalScreenshot + exportCurrentFrame.
- **The zoom family**: zoomUIToOnscreen / scrollToTap / zoomToPoint /
  zoomToPos / markCircumNavigateX / renderingTeaserFrames.

## Boundaries (honest)

- uncl 107/117: ten cells (0xffff1dbc, 0xff54a270, 0xffffc9bc shared by 3
  bodies, 0xffed2e68, and the -32.0f float cell 0xc2000000).
- The render giant's semantics above are **census-level** (call histogram +
  constant pool + structure counts over all 29808 instructions); the full
  instruction-by-instruction walk of a 30k-word body is not claimed.

**World line status after E100-E102**: 62/322 bodies (mutation, simulation,
renderer cores); net/admin + UI families remain.
