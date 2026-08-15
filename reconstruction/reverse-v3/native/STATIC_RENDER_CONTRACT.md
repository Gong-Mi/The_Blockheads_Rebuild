# Original 1.7.6 renderer and asset contract

This document records static evidence from the original APK and
`libApplication.so`. It does not claim pixel parity for the rebuild.

## Evidence levels

- **A**: directly present in the original APK, shader source, ELF metadata,
  selector table, symbol table, or current rebuild source.
- **B**: reproduced by a controlled run of the original application.
- **C**: conclusion combining multiple A-level observations.
- **D**: proposed implementation direction, not recovered original behavior.

This document contains A/C evidence. Device screenshots of the rebuild are
acceptance evidence for the rebuild, not B-level evidence for the original.

## Asset namespace

[A] The original `assets/GameResources/` tree contains **723 files** totaling
71,108,242 bytes:

- 553 direct children;
- 125 files under `HDTex/`;
- remaining files under `Fonts/`, `UI/`, `instructions/`, and `skins/`;
- 458 PNG, 152 WAV, 46 `.vsh`, and 46 `.fsh` files.

[A] Paths are mixed-case and case-sensitive. Examples include `TileMap.png`,
`TileDestruct.png`, `TileReflect.png`, `ItemNormals.png`, `Items.png`,
`SkyBetter.png`, `Sun.png`, `Moon.png`, and `HDTex/TileMap.png`. There are no
case-fold collisions.

[A] There are 126 repeated-basename groups spanning 252 paths, mostly SD files
and their `HDTex/` counterparts. The namespaces must not be flattened by
basename. Representative pairs are:

| Asset | SD | HD |
|---|---:|---:|
| `Items.png` | 512×256 | 2048×1024 |
| `TileMap.png` | 512×512 | 2048×2048 |
| `TileDestruct.png` | 512×512 | 2048×2048 |
| `TileReflect.png` | 512×512 | 2048×2048 |
| `head_ct.png` | 32×16 | 128×64 |
| `body_ct.png` | 32×16 | 128×64 |
| `arms_ct.png` / `legs_ct.png` | 16×16 | 64×64 |

[A] The rebuild contains byte-identical copies of all 723 resources after
removing the original `GameResources/` prefix. Current runtime calls open
root-relative names such as `TileMap.png`; this is a compatibility layout, not
an exact reproduction of the original APK path namespace.

## Native renderer topology

[A] Objective-C metadata in `libApplication.so` exposes `World`, `Shader`,
`CPTexture2D`, `DrawCube`, `Weather`, `ParticleEmitter`, `GameView`,
`WorldTileLoader`, `DynamicWorld`, `OwnershipAreaRenderer`, and `Blockhead`.

[A] `World` has distinct state for `blockShader`, `blockTransparentShader`,
`staticDrawCubeShader`, `lightsShader`, `dodoEggShader`, sky/star/black-tile
shaders, tile/destruction/light textures, sky/sun/moon textures, item and item
normal textures, block geometry arrays, camera bounds, and time/weather
matrices.

[A] Recovered selectors include:

- `preRenderUpdate:fastSlowDT:cameraZ:projectionMatrix:`
- `preDrawUpdate:cameraMinXWorld:cameraMaxXWorld:cameraMinYWorld:cameraMaxYWorld:`
- `reloadDrawBlock:world:waterAnimationIndex:slowAnimationIndex:mapPixelData:skyPixelData:`
- `drawOpaqueObjects:...`
- `drawFreeBlocks:...`
- `drawInFrontOfBlocksObjects:...`
- `renderCloudWithMatrix:translation:dt:weatherFraction:futureWeatherFraction:timeOfDayFraction:`
- `renderWithMatrix:pinchScale:withDayColor:rainFraction:snowFraction:snowLevel:`
- `renderAndUpdate:...windMovement:`

[C] The original renderer is multi-pass. Opaque blocks, transparent blocks,
free blocks, in-front objects, water, static cubes, dynamic objects, dodo eggs,
light glows, particles, and weather cannot be represented faithfully by one
opaque terrain VBO pass.

## Exact block shader packing

[A] `Block.vsh` consumes four `vec4` attributes: `position`, `texCoord`,
`other`, and `paintColor`.

| Field | Original shader meaning |
|---|---|
| `position.xyz` | world position |
| `position.w` | atlas column |
| `texCoord.xy` | 0–255 coordinate inside one atlas cell |
| `texCoord.z` | artificial-light contribution scalar |
| `texCoord.w / 255` | Y displacement |
| `other.xy / 256` | lightmap UV |
| `other.z` | atlas row |
| `other.w / 255` | gather opacity in `BlockTransparent` |
| `paintColor` | paint RGB and paint alpha |

[A] `Block.fsh` samples a fixed **32×32 atlas** using the half-texel inset:

```text
((((coord / 255) * 0.984375) + 0.0078125) + cell) / 32
```

[A] It samples `texture`, `light_texture`, and `destruct_texture`.
Destruction RG perturbs the normal; destruction alpha controls diffuse and
specular terms. Lightmap RGB supplies artificial light and lightmap alpha
controls observed daylight. Paint alpha changes the final color equation and
must be zero for an unpainted tile.

[A] `BlockTransparent` is a separate shader contract. It forwards
`other.w / 255` as gather opacity, thresholds destruction blue against it, and
produces transparent output. It is not a mode of the opaque fragment shader.

## Other shader families

[A] Original assets and metadata establish these independent contracts:

- `LightQuads`: texture, night fraction, luminosity encoded by paint alpha;
- `StaticDrawCubes`: position, UV, normal, paint, lightmap, diffuse/specular;
- `Item`: normalized UVs over `Items.png` and `ItemNormals.png`;
- Blockhead body, clothing, face, hair, and multi-texture character shaders;
- `SkyBetter`, sun, moon, stars, six-layer HD cloud shaders;
- lightmap-aware rain and point-rendered snow.

The original spelling `artificalLight` is part of the character shader ABI.

## Rebuild conformance ledger

Verified in current source and CI:

- terrain atlas indices use item definitions rather than guessed numeric IDs;
- the terrain VBO is unbound before client-side character arrays;
- a new EGL context recreates renderer-owned GL objects and requeues cached
  chunk meshes for VBO upload;
- the fallback 1×1 light texture has non-mipmapped filters and clamp wrapping;
- gameplay initializes `artificalLight` and `lightPosition`;
- unpainted generated vertices use paint alpha zero;
- shaders pass `glslangValidator` and source contract checks run in CI.

Outstanding evidence-backed gaps:

1. [A] `texCoord.z` and `other.xy` are not populated as a real per-block
   artificial-light/lightmap contract.
2. [A] The fallback light texture is not a real physical-block lightmap.
3. [A/C] Transparent/background/water/object passes remain collapsed or absent.
4. [A] Character drawing uses only the body program and flat six-vertex faces;
   clothing, face, hair, multi-texture composition, and cuboid geometry remain.
5. [A] Runtime always selects SD root assets; HD selection is absent.
6. [A] Shader compile/link/validation diagnostics are incomplete.
7. [A/C] Sky and weather are prototypes rather than recovered original passes.

## Acceptance observations

These are rebuild-device observations, not original-runtime evidence:

- CI run `31873929349` built commit `983078f` successfully.
- APK installation and saved-world loading succeeded on the test device.
- Terrain and UI remain visible after EGL context recreation.
- Setting unpainted paint alpha to zero made brick atlas content materially
  recognizable, but broad terrain remains dark and the character remains only
  partially recognizable.
