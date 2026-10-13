# MJButton (E138)

The MJButton widget class lands: button geometry, hit-testing and the button render surface. 50 bodies, 6259 verified instruction words, from the pinned original libApplication.so (1.7.6, armeabi-v7a). All listings regenerate byte-identically from the pinned r2 recipe and the recover tool re-verifies every word, cell and branch against the ELF.

| name | method | imp | words | sel | imp-c | ivar | cls | calls | br |
|---|---|---|---|---|---|---|---|---|---|
| mj_00 | MJButton -[.cxx_construct] | 0x00d17034 | 6 | 0 | 0 | 0 | 0 | 0 | 0 |
| mj_01 | MJButton -[backgroundHighlightedSelectedTexture] | 0x00d16a7c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_02 | MJButton -[backgroundHighlightedTexture] | 0x00d169f4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_03 | MJButton -[backgroundSelectedTexture] | 0x00d1696c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_04 | MJButton -[backgroundTexture] | 0x00d168e4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_05 | MJButton -[createTitleBWithColor:] | 0x00d1611c | 223 | 3 | 0 | 6 | 2 | 4 | 7 |
| mj_06 | MJButton -[createTitleWithColor:] | 0x00d10640 | 223 | 3 | 0 | 6 | 2 | 4 | 7 |
| mj_07 | MJButton -[dealloc] | 0x00d1232c | 148 | 2 | 2 | 7 | 1 | 8 | 0 |
| mj_08 | MJButton -[dontStretch] | 0x00d16e54 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_09 | MJButton -[glyphColor] | 0x00d16ed4 | 24 | 0 | 0 | 1 | 0 | 1 | 0 |
| mj_10 | MJButton -[glyphFrame] | 0x00d16c94 | 24 | 0 | 0 | 1 | 0 | 1 | 0 |
| mj_11 | MJButton -[glyphFrameB] | 0x00d16d74 | 24 | 0 | 0 | 1 | 0 | 1 | 0 |
| mj_12 | MJButton -[glyphTexture] | 0x00d16b04 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_13 | MJButton -[glyphTextureB] | 0x00d16b8c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_14 | MJButton -[hoverSelectedDisabled] | 0x00d16c14 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_15 | MJButton -[initWithFrame:cache:windowInfo:textureName:] | 0x00d11768 | 389 | 6 | 7 | 9 | 2 | 9 | 2 |
| mj_16 | MJButton -[initWithFrame:cache:windowInfo:title:] | 0x00d11d7c | 364 | 5 | 7 | 8 | 2 | 8 | 2 |
| mj_17 | MJButton -[renderFrame:projectionMatrix:] | 0x00d12700 | 2581 | 15 | 2 | 42 | 2 | 68 | 38 |
| mj_18 | MJButton -[setBackgroundHighlightedSelectedTexture:] | 0x00d16ab8 | 19 | 0 | 0 | 1 | 0 | 1 | 0 |
| mj_19 | MJButton -[setBackgroundHighlightedTexture:] | 0x00d16a30 | 19 | 0 | 0 | 1 | 0 | 1 | 0 |
| mj_20 | MJButton -[setBackgroundSelectedTexture:] | 0x00d169a8 | 19 | 0 | 0 | 1 | 0 | 1 | 0 |
| mj_21 | MJButton -[setBackgroundTexture:] | 0x00d16920 | 19 | 0 | 0 | 1 | 0 | 1 | 0 |
| mj_22 | MJButton -[setColor:] | 0x00d1138c | 247 | 4 | 1 | 6 | 1 | 9 | 5 |
| mj_23 | MJButton -[setDontStretch:] | 0x00d16e90 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_24 | MJButton -[setEnabled:] | 0x00d10fc4 | 242 | 4 | 2 | 4 | 1 | 9 | 8 |
| mj_25 | MJButton -[setFrame:] | 0x00d15ae4 | 297 | 1 | 0 | 5 | 1 | 7 | 2 |
| mj_26 | MJButton -[setGlyphColor:] | 0x00d16f34 | 32 | 0 | 0 | 1 | 0 | 1 | 0 |
| mj_27 | MJButton -[setGlyphFrame:] | 0x00d16cf4 | 32 | 0 | 0 | 1 | 0 | 1 | 0 |
| mj_28 | MJButton -[setGlyphFrameB:] | 0x00d16dd4 | 32 | 0 | 0 | 1 | 0 | 1 | 0 |
| mj_29 | MJButton -[setGlyphTexture:] | 0x00d16b40 | 19 | 0 | 0 | 1 | 0 | 1 | 0 |
| mj_30 | MJButton -[setGlyphTexture:minTexX:maxTexX:minTexY:maxTexY:] | 0x00d15784 | 108 | 2 | 1 | 6 | 0 | 2 | 0 |
| mj_31 | MJButton -[setGlyphTextureB:] | 0x00d16bc8 | 19 | 0 | 0 | 1 | 0 | 1 | 0 |
| mj_32 | MJButton -[setGlyphTextureB:minTexX:maxTexX:minTexY:maxTexY:] | 0x00d15934 | 108 | 2 | 1 | 6 | 0 | 2 | 0 |
| mj_33 | MJButton -[setHidden:] | 0x00d12674 | 35 | 1 | 1 | 0 | 1 | 1 | 0 |
| mj_34 | MJButton -[setHighlighted:] | 0x00d15740 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_35 | MJButton -[setHoverSelectedDisabled:] | 0x00d16c50 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_36 | MJButton -[setSelected:] | 0x00d156fc | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_37 | MJButton -[setTapAnimationDisabled:] | 0x00d16ff0 | 17 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_38 | MJButton -[setTextureName:] | 0x00d1257c | 62 | 3 | 1 | 2 | 0 | 3 | 0 |
| mj_39 | MJButton -[setTitle:] | 0x00d10c30 | 214 | 4 | 1 | 4 | 0 | 8 | 10 |
| mj_40 | MJButton -[setTitleAlignment:] | 0x00d10a08 | 119 | 2 | 1 | 4 | 0 | 5 | 4 |
| mj_41 | MJButton -[setTitleAlignmentB:] | 0x00d16748 | 82 | 2 | 1 | 3 | 0 | 3 | 1 |
| mj_42 | MJButton -[setTitleB:color:] | 0x00d16498 | 157 | 4 | 1 | 2 | 0 | 5 | 7 |
| mj_43 | MJButton -[setTitleOffset:] | 0x00d15f88 | 21 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_44 | MJButton -[setTitleOffsetB:] | 0x00d16890 | 21 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_45 | MJButton -[tapAnimationDisabled] | 0x00d16fb4 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_46 | MJButton -[title] | 0x00d10f88 | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_47 | MJButton -[titleB] | 0x00d1670c | 15 | 0 | 0 | 1 | 0 | 0 | 0 |
| mj_48 | MJButton -[titleViewActualDimensions] | 0x00d15fdc | 40 | 1 | 0 | 1 | 0 | 2 | 2 |
| mj_49 | MJButton -[titleViewBActualDimensions] | 0x00d1607c | 40 | 1 | 0 | 1 | 0 | 2 | 2 |

## Findings (E138)

- **The MJButton batch lands**: 50 bodies / 6259 words / 97 branches / 171 call rows of `MJButton` - the whole class at body level (objc method-table order: `.cxx_construct` @0x00d17034 .. `-[titleViewBActualDimensions]` @0x00d1607c; implementation addresses span 0x00d10640..0x00d1704c). 1 body >1000w [census], 2 bodies 301-1000w [census-lite], 47 bodies <=300w fully read. Roster names are collision-free (no overlap with existing native/ listings).

  | body | method | w | br | calls | grade |
  |---|---|---|---|---|---|
  | mj_00 | `MJButton -[.cxx_construct]` | 6 | 0 | 0 | read |
  | mj_01 | `MJButton -[backgroundHighlightedSelectedTexture]` | 15 | 0 | 0 | read |
  | mj_02 | `MJButton -[backgroundHighlightedTexture]` | 15 | 0 | 0 | read |
  | mj_03 | `MJButton -[backgroundSelectedTexture]` | 15 | 0 | 0 | read |
  | mj_04 | `MJButton -[backgroundTexture]` | 15 | 0 | 0 | read |
  | mj_05 | `MJButton -[createTitleBWithColor:]` | 223 | 7 | 4 | read |
  | mj_06 | `MJButton -[createTitleWithColor:]` | 223 | 7 | 4 | read |
  | mj_07 | `MJButton -[dealloc]` | 148 | 0 | 8 | read |
  | mj_08 | `MJButton -[dontStretch]` | 15 | 0 | 0 | read |
  | mj_09 | `MJButton -[glyphColor]` | 24 | 0 | 1 | read |
  | mj_10 | `MJButton -[glyphFrame]` | 24 | 0 | 1 | read |
  | mj_11 | `MJButton -[glyphFrameB]` | 24 | 0 | 1 | read |
  | mj_12 | `MJButton -[glyphTexture]` | 15 | 0 | 0 | read |
  | mj_13 | `MJButton -[glyphTextureB]` | 15 | 0 | 0 | read |
  | mj_14 | `MJButton -[hoverSelectedDisabled]` | 15 | 0 | 0 | read |
  | mj_15 | `MJButton -[initWithFrame:cache:windowInfo:textureName:]` | 389 | 2 | 9 | census-lite |
  | mj_16 | `MJButton -[initWithFrame:cache:windowInfo:title:]` | 364 | 2 | 8 | census-lite |
  | mj_17 | `MJButton -[renderFrame:projectionMatrix:]` | 2581 | 38 | 68 | census |
  | mj_18 | `MJButton -[setBackgroundHighlightedSelectedTexture:]` | 19 | 0 | 1 | read |
  | mj_19 | `MJButton -[setBackgroundHighlightedTexture:]` | 19 | 0 | 1 | read |
  | mj_20 | `MJButton -[setBackgroundSelectedTexture:]` | 19 | 0 | 1 | read |
  | mj_21 | `MJButton -[setBackgroundTexture:]` | 19 | 0 | 1 | read |
  | mj_22 | `MJButton -[setColor:]` | 247 | 5 | 9 | read |
  | mj_23 | `MJButton -[setDontStretch:]` | 17 | 0 | 0 | read |
  | mj_24 | `MJButton -[setEnabled:]` | 242 | 8 | 9 | read |
  | mj_25 | `MJButton -[setFrame:]` | 297 | 2 | 7 | read |
  | mj_26 | `MJButton -[setGlyphColor:]` | 32 | 0 | 1 | read |
  | mj_27 | `MJButton -[setGlyphFrame:]` | 32 | 0 | 1 | read |
  | mj_28 | `MJButton -[setGlyphFrameB:]` | 32 | 0 | 1 | read |
  | mj_29 | `MJButton -[setGlyphTexture:]` | 19 | 0 | 1 | read |
  | mj_30 | `MJButton -[setGlyphTexture:minTexX:maxTexX:minTexY:maxTexY:]` | 108 | 0 | 2 | read |
  | mj_31 | `MJButton -[setGlyphTextureB:]` | 19 | 0 | 1 | read |
  | mj_32 | `MJButton -[setGlyphTextureB:minTexX:maxTexX:minTexY:maxTexY:]` | 108 | 0 | 2 | read |
  | mj_33 | `MJButton -[setHidden:]` | 35 | 0 | 1 | read |
  | mj_34 | `MJButton -[setHighlighted:]` | 17 | 0 | 0 | read |
  | mj_35 | `MJButton -[setHoverSelectedDisabled:]` | 17 | 0 | 0 | read |
  | mj_36 | `MJButton -[setSelected:]` | 17 | 0 | 0 | read |
  | mj_37 | `MJButton -[setTapAnimationDisabled:]` | 17 | 0 | 0 | read |
  | mj_38 | `MJButton -[setTextureName:]` | 62 | 0 | 3 | read |
  | mj_39 | `MJButton -[setTitle:]` | 214 | 10 | 8 | read |
  | mj_40 | `MJButton -[setTitleAlignment:]` | 119 | 4 | 5 | read |
  | mj_41 | `MJButton -[setTitleAlignmentB:]` | 82 | 1 | 3 | read |
  | mj_42 | `MJButton -[setTitleB:color:]` | 157 | 7 | 5 | read |
  | mj_43 | `MJButton -[setTitleOffset:]` | 21 | 0 | 0 | read |
  | mj_44 | `MJButton -[setTitleOffsetB:]` | 21 | 0 | 0 | read |
  | mj_45 | `MJButton -[tapAnimationDisabled]` | 15 | 0 | 0 | read |
  | mj_46 | `MJButton -[title]` | 15 | 0 | 0 | read |
  | mj_47 | `MJButton -[titleB]` | 15 | 0 | 0 | read |
  | mj_48 | `MJButton -[titleViewActualDimensions]` | 40 | 2 | 2 | read |
  | mj_49 | `MJButton -[titleViewBActualDimensions]` | 40 | 2 | 2 | read |

- **The heavy bodies** (>300w), in listing order:

  | body | method | words | branches | calls |
  |---|---|---|---|---|
  | mj_15 | `MJButton -[initWithFrame:cache:windowInfo:textureName:]` | 389 | 2 | 9 |
  | mj_16 | `MJButton -[initWithFrame:cache:windowInfo:title:]` | 364 | 2 | 8 |
  | mj_17 | `MJButton -[renderFrame:projectionMatrix:]` | 2581 | 38 | 68 |

- **Class anatomy (ivar offsets, class_metadata.json authoritative)**: instance_size 273, super MJControl/MJView. Own ivars: title@0x64, titleAlignment@0x68, shader@0x6c, backgroundTexture@0x70, backgroundSelectedTexture@0x74, backgroundHighlightedTexture@0x78, backgroundHighlightedSelectedTexture@0x7c, titleView@0x80, glyphTexture@0x84, glyphFrame@0x88 (CGRect), glyphColor@0x98 (MJColor), isSelected@0xa8 (c), hoverSelectedDisabled@0xa9 (c), isHighlighted@0xaa (c), glyphMinTexX@0xac / glyphMaxTexX@0xb0 / glyphMinTexY@0xb4 / glyphMaxTexY@0xb8 (f), customGlyphTexCoords@0xbc (c), dontStretch@0xbd (c), glyphTextureB@0xc0, glyphFrameB@0xc4 (CGRect), glyphMinTexBX@0xd4 / glyphMaxTexBX@0xd8 / glyphMinTexBY@0xdc / glyphMaxTexBY@0xe0, customGlyphTexCoordsB@0xe4 (c), titleOffset@0xe8 (CGSize), titleB@0xf0, titleAlignmentB@0xf4, titleViewB@0xf8, titleOffsetB@0xfc (CGSize), lastRenderTime@0x108 (double), tapAnimationDisabled@0x110 (c). Inherited: MJView.hidden@4, MJView.frame@8, MJView.color@0x1c, MJView.cache@0x30, MJView.windowInfo@0x34; MJControl.hover@0x44, enabled@0x47, startTouchAnimationTimer@0x60. Every ivar access is the Apportable offset-cell form (ldr cell -> ldr [cell+picbase] -> deref -> add self, plus_offset).
- **The geometry contract**: glyphFrame = frame inset by 4 ({x+4, y+4, w-8, h-8}); glyphFrameB = {x+18, y+18, w-16, h-16} - both recomputed in the ctors and in setFrame: (three sites; one writer helper 0xd109bc). Title views get rect {x + align-offset, y - h/2 + 8.0, w - 4.0, h} on creation (createTitle(WithB)WithColor:) and {x + 0.5*w, y - 0.5*h + 8.0, w, h} on setFrame:. Alignment offsets: titleAlignment 0 -> x+9.0, 1 -> x + 0.5*w, 2 -> x + w-9.0.
- **The color algebra**: enabled=false dims the A-title to color*0.5 (setColor:/setEnabled:/setTitle:); the B-title always renders at color*0.67 (0x3f2b851f, setColor:/setEnabled:) while the alignment setters use plain constants: setTitleAlignment: rebuilds with (1,1,1,1) enabled / (0.5,0.5,0.5,1) disabled, setTitleAlignmentB: with (0.67,0.67,0.67,1). createTitle*WithColor: always uses [BitmapFont standardFont] and an MJTextView initWithFrame:cache:windowInfo:string:horizontalAlignment:font:color: (the same selector the JoinWorldUI batch saw).
- **The render pipeline (mj_17, census)**: loop-free 2581-word renderer; dt from NSDate timeIntervalSinceReferenceDate; countdown startTouchAnimationTimer -= 4.0*max(arg, dt); hidden short-circuits to the super tail; tap animation scale = 1 - 0.125*|timer^2 - 0.5|; background texture state machine isSelected || (hover && !hoverSelectedDisabled) -> selected texture, isHighlighted -> highlighted textures; three quad groups each drawn with glBindTexture + glVertexAttribPointer x2 (GL_FLOAT 0x1406) + glDrawElements x2 (mode 4, 6 indices, GL_UNSIGNED_SHORT 0x1403, shared index buffer @0x00e76c90 word 0x00060000); MVP = mat4 product helper 0xd14f54 then glUniformMatrix4fv; title views rendered through the translate helper 0xd15514 with titleOffset/titleOffsetB; tail = [super renderFrame:projectionMatrix:].
- **Helper catalog pinned by this batch**: 0xd109bc and 0xd10be4 = instruction-identical 4-float writers write4(dst, a, b, c, d) (rect/CGSize/color writers; 19 words each; 6 and 7 caller bodies respectively, 11 in union); 0xd14f54 = 4x4 matrix product over two stacked 16-float operands (368 words; dst[4c] = sum_k A[4k]*B[4c+k]); 0xd15514 = 4x4 matrix with the translation row rewritten from (x, y, z) - dst[12+c] = x*M[c] + y*M[4+c] + z*M[8+c] + M[12+c] (122 words). objc_setProperty_nonatomic carries the four background-texture setters (mj_18-mj_21) and glyphTexture/glyphTextureB (mj_29/mj_31); objc_copyStruct (16, 1, 0) carries the struct getters/setters (mj_09/mj_10/mj_11 and mj_26/mj_27/mj_28).
- **State flags & atomicity**: the plain strb setters are setSelected: (0xa8) and setHighlighted: (0xaa); the dmb ish bracketed byte setters are setDontStretch: (0xbd), setHoverSelectedDisabled: (0xa9), setTapAnimationDisabled: (0x110). setHidden: is a pure super forward; dealloc and renderFrame tail both use objc_msgSendSuper2.
- **The title layer is a three-state rebuild**: setTitle:/setTitleB:color: early-out on identical strings (isEqualToString:), release both the old string and the old view, then lazily recreate through the matching create*WithColor:; the alignment setters rebuild with literal colors; setEnabled:/setColor: rebuild with the current self.color (dimmed by enabled state).

## Boundaries

- Grades: mj_17 is census-level - call histogram, branch skeleton, constant usage, cell map and the phase structure above are pinned, but it was not read instruction by instruction (2581 words, zero loops). mj_15 and mj_16 are census-lite by size but their whole instruction streams were traced in this batch. The remaining 47 bodies (<=300 words each) were fully read; 34 of them sit in instruction-identical sibling groups verified by pointer-normalized diff (mj_01/02/03/04; mj_05/06; mj_08/14; mj_10/11; mj_12/13; mj_18/19/20/21; mj_23/35/37; mj_26/27/28; mj_29/31; mj_30/32; mj_34/36; mj_43/44; mj_46/47; mj_48/49), and mj_45/46 differ only in ldrsb vs ldr.
- mj_36 (setSelected:) is trimmed at the next ObjC IMP 0x00d15740 (shared ARM.exidx suffix 0x00d15784); 17 words as received, and the listing bound is the record.
- The helper interpretation of 0xd14f54 (4x4 product) and 0xd15514 (translation rewrite) is derived from the index arithmetic in their bodies (dot products over stride-4 A elements against contiguous B elements); the rows/columns orientation (which operand is the projection and which the modelview) is recorded at expression level only, not runtime-verified.
- mj_17 stack-block offsets are quoted as [block+0xNNN] where NNN is the offset inside the aligned local buffer (block base = sp-relative via add r3, sp, 0x530); they are internal scratch fields, not ivars, and no names are claimed for them beyond the shape described.
- The r2 listing for offset-cell getters prints the companion cells as "unmapped"/invalid data words (e.g. mj_01 cell 0xd16ab4 = 0x00349068). Those are the PIC-base materialization words (0x00349068 + pc(0xd16a8c) = 0x0105faf4); values were re-checked by direct ELF reads, and the pointer-add route was not claimed from the pool-row text.
- mj_05/mj_06 leave dead stack stores (9 / 2 / 7) in the titleAlignment == 2 arm; no in-body reader consumes them (recorded, not interpreted). Likewise mj_17 dead-stores exist around the animated-quad block; only the computed final values are claimed.
- Static only: no runtime values. GL enum names are given as the literal constants (0x1406 GL_FLOAT, 0x1403 GL_UNSIGNED_SHORT, mode 4 GL_TRIANGLES); UIKit/MJTextView/BitmapFont/Shader internals beyond the call-site level are not claimed. mj_48/mj_49 depend on MJTextView -[actualDimensions] (stret); its result layout is CGSize by the method signature, not by a runtime sample.
- The batch-local prefix mj_ is exclusive; gen_listings reported no collisions and no clash with existing native/ listing names.
