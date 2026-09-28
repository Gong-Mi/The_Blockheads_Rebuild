# The shaders — recovered as SOURCE (the render front's best evidence tier)

The 46 vertex/fragment pairs that drive the game's GPU pipeline ship as
plain-text GLSL in the APK's `assets/GameResources/` (`*.vsh` / `*.fsh`),
each carrying the original header:

```
//  Shader.vsh
//  SandLandiPad
//  Created by David Frampton on 8/03/11.
//  Copyright 2011 Jungle Ltd. All rights reserved.
```

They are copied verbatim into `reconstruction/reverse-v3/assets/shaders/`
(all 92 files) — provenance evidence (the author, the project name
"SandLandiPad", the 2011 date) and, more importantly, the **exact GPU
semantics** the disassembly work kept inferring: no decompilation needed for
this layer.

## The UI pipeline (mapped to the classes)

`Shader -initWithShaderVertexFile:fragmentFile:attribute...` (0x007C63AC,
597w) loads these files and compiles them; `MJButton -renderFrame:` uses the
object in `shader@108` with a cached `uniformLocations` array. The button's
shader is literally **`MJButton.vsh` / `MJButton.fsh`**:

```glsl
// MJButton.vsh
attribute vec4 position;
attribute vec4 texCoord;
uniform mat4 mvp_matrix;
varying highp vec4 outTexCoord;
void main() {
    gl_Position = mvp_matrix * vec4(position.xyz, 1.0);
    outTexCoord = texCoord;
}

// MJButton.fsh
uniform sampler2D texture;
uniform highp vec4 color;
varying highp vec4 outTexCoord;
void main() {
    highp vec4 tex = texture2D(texture, outTexCoord.xy);
    gl_FragColor = tex * color;
}
```

So every UI quad = `tex * color` under the mvp transform — exactly what the
MJButton ivar map implied (`View.color@28`, `glyphColor@152`, the per-state
texture selection, the `color`/`texture` uniforms). **`Text.fsh` is the same
formula**; the two title layers differ only in the glyph texture and the
color pushed.

### The class → shader mapping, proven three ways

`MJButton -initWithFrame:cache:windowInfo:textureName:` (0x00D11768) builds
its shader with the literal constants:

```
[shaderNamed:@"MJButton"
 attributes:[NSArray arrayWithObjects:@"position", @"texCoord", nil]
 uniforms:[NSArray arrayWithObjects:@"mvp_matrix", @"texture", @"color", nil]]
```

Three independent records agree exactly:

1. the disassembly's CFString refs — "MJButton", "position", "texCoord",
   "mvp_matrix", "texture", "color" (0x00FADE78..0x00FADEC8);
2. the shader source in `assets/GameResources/MJButton.vsh/fsh` —
   `attribute vec4 position; attribute vec4 texCoord;` /
   `uniform mat4 mvp_matrix; uniform sampler2D texture; uniform vec4 color;`;
3. the class's ivar map — `shader@108` set at the call, with
   `backgroundTexture@112` following via `[cache textureNamed:…]`.

The API used here, `shaderNamed:attributes:uniforms:`, is the seam every
class's render setup goes through, so the rest of the inventory can be
mapped the same way (class init constants ↔ the .vsh/.fsh pair).

## The world pipeline

`Basic.vsh`/`Basic.fsh` carry the world's lit/fogged path (the `cloud`
attribute = the per-vertex shading + fog):

```glsl
// Basic.vsh (main)
gl_Position = mvp_matrix * vec4(position.x, position.y, position.z, 1.0);
outTexCoord = texCoord;
outCloud = cloud;

// Basic.fsh (main)
highp vec4 fog = vec4(outCloud.y, outCloud.y, outCloud.y, 1.0);
highp vec4 tex = texture2D(texture, outTexCoord.xy)
               * vec4(outCloud.y, outCloud.y, outCloud.y, 1.0)
               * vec4(outTexCoord.z, outTexCoord.z, outTexCoord.z, 1.0);
highp vec4 texShaded = mix(vec4(0.0,0.0,0.0,1.0), tex,
                           min((outCloud.y + tex.a), 1.0));
gl_FragColor = mix(texShaded, fog, vec4(outCloud.x, outCloud.x,
                                        outCloud.x, outCloud.x));
```

i.e. per-vertex light in `cloud.y`, fog blend in `cloud.x`, a
texCoord.z brightness factor, and the alpha-aware black mixing.

## The screen effects

`Vignette.fsh` — the edge darkening, an exact cubic falloff:

```glsl
lowp float blackAlpha = length(outTexCoord.xy - vec2(0.5,0.5)) * 1.35;
blackAlpha = blackAlpha * blackAlpha * blackAlpha;
gl_FragColor = vec4(0.0,0.0,0.0,blackAlpha);
```

## The full inventory

ActionSquare, Basic, BlackCube, BlackTile, Block, BlockTransparent,
BlockheadBody, BlockheadClothing, BlockheadFace, BlockheadHair,
BonusParticle, Button, Cloud, CloudHD, ColorPicker, ColorWell, ColoredNPC,
ColoredNoTexture, DodoBreedBody, DrawCube, FreeBlock, InProgressPainting,
Item, LightQuads, MJButton, Painting, Particle, PortalPreview, Rain,
ShadedWorldObject, ShadedWorldObjectMultiTexture, Sky, SkyBetter, Snow,
StandardObject, StandardObjectColored, Star, StaticDrawCubes, Text, Tulip,
Vignette, WorldObject, WorldObjectGather, WorldObjectNewLighting,
dodoEggSingle, dodoEggStatic.

The render front's decode can therefore reference the shader **source** for
every GPU stage, while the remaining work is the CPU side: which quads are
built, with which attributes/uniforms, in which order (the leaf painters'
listsings).

## How to inspect

```
ls reconstruction/reverse-v3/assets/shaders/
# or the live tree:
ls ~/blockheads-work/extracted/assets/GameResources/*.vsh
```
