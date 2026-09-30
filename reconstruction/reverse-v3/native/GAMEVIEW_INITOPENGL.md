# GameView.initOpenGL reviewed semantics

IMP 0x009216d0, end 0x00921e64. Reproducer verifies 485 instruction/literal
words, covers all 23 register blx sites, and validates CFString payload bytes.
This is a hand-reviewed local static path, not automatic whole-function alias
recovery or dynamic GL/platform acceptance. No replacement code is changed.

## Ordered stages

1. 0x00921720: glClearColor(0,0,0,1).
   0x00921728: glClear(0x4100), color+depth bits.
   0x00921734: glBlendFunc(1,0x303), GL_ONE/GL_ONE_MINUS_SRC_ALPHA.
   No glEnable(GL_BLEND) occurs in this method; this is not the entire GL state.
2. 0x00921874 alloc CPCache, 0x00921884 init; 0x00921898 store self.cache
   (ivar offset 12). Two NSArray arrays are constructed:
   attributes [position, texCoord], uniforms [mvp_matrix, texture].
   0x00921934 cache.shaderNamed("StandardObject", attributes, uniforms);
   0x00921948 store self.basicShader (offset 16).
3. cache.textureNamed("InventoryButtonBackground.png") at 0x00921970,
   texture.name at 0x00921980, glBindTexture(GL_TEXTURE_2D,name) at 0x00921994.
   0x009219a4: glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR).
   Green variant follows at 0x00921a10/20/34/44 with the same setting.
   This method sets MAG_FILTER only, not MIN_FILTER/mipmap/wrap. Texture loader
   defaults or other callers must be checked before making a full sampler claim.
4. Compute a boolean from self.totalGamePlayTimePassed (double, offset 272) < 1.0.
   The compare occurs at 0x00921a98..0x00921ab0; the saved byte is reused later.
5. 0x00921af0 self.initAds (unconditional within this method).
   0x00921b18 self.performSelector(authenticateGameCenter, nil, 3.0 seconds).
   This schedules a later invocation, not synchronous authentication success.
6. If the saved less-than-one flag is true, 0x00921b7c standardUserDefaults,
   0x00921b98 setBool(true, "GPGSShouldSignIn"). No write on the other branch.
7. 0x00921c20 NSUbiquitousKeyValueStore.defaultStore;
   0x00921c30 synchronize; 0x00921c50 MJSoundManager.instance;
   0x00921c68 setLoopMP3s(true). These calls are outside the first-time branch.
8. If the saved flag is false, MJSoundManager.instance (0x00921d40),
   NSBundle.mainBundle/resourcePath (0x00921d60/70), append "GameResources/"
   (0x00921d84), append "mountainKingLoop.mp4" (0x00921d98), then
   soundManager.playMP3IfSafe(path) at 0x00921db8.
   For finite values this is totalGamePlayTimePassed >= 1.0. The filename really
   ends in .mp4 despite the method names containing MP3; do not normalize it.

There are seven direct GL wrapper calls and 23 Objective-C dispatch sites.
The only conditional control branches select the defaults write and music path;
the unconditional jump at 0x00921adc skips an inline zero literal, not a feature
branch. NaN/exception semantics are not folded into finite-input pseudocode.

## Lifecycle implication and boundary

The preceding drawFrame controller guards this entry using openGLInitialized.
This body itself has no idempotence guard and creates/reassigns cache/shader and
schedules platform work. Treating it as a pure reusable EGL-context rebuild hook
would duplicate non-GL side effects unless reconstruction separates them explicitly.
This is an architectural consequence of observed calls, not an observed device bug.
CPCache allocation/shader/texture internals and initAds/authenticateGameCenter
bodies are not recovered by this slice.

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/recover_gameview_initopengl.py \
  "$HOME/blockheads-work/extracted/lib/armeabi-v7a/libApplication.so" \
  --output "$TMPDIR/gameview-initopengl.json"
```

Output is stored as gameview_initopengl_reviewed.json. Next work: GameView.update
and render world-loading/simulation/UI branch topology, with args and receiver
provenance rather than treating their reference sets as an ordered call graph.
