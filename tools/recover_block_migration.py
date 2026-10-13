#!/usr/bin/env python3
"""Hash-gated recovery of the Physical-block format migration batch (E15).

The WorldTileLoader block-version updater - the third body of the block-storage
trilogy (write E14, sync E14, migrate E15):
1 body, 1311 instruction words, from the pinned original libApplication.so
(1.7.6, armeabi-v7a).  Every instruction word is re-verified; tool refuses to
emit on drift.

Verification rules (each one is a claim this file makes about its own evidence):
  * coverage    - the checked-in listing must cover [start, end) exactly once per word,
                  and every word is re-read from the pinned ELF.
  * PIC base    - recomputed from the `add rX, pc, rY` anchor and its pool literal;
                  must equal 0x0105faf4.
  * cells       - selector cells: the slot is base + signed(pool value) and the C string
                  it points at must be the named selector.  Import cells: the slot must be
                  a PLT/GOT slot whose relocation names the import, or - for functions
                  reached through an ABS32 relocation - a relocation whose symbol names
                  it (the route used is recorded per cell).  Ivar cells: the slot
                  holds a pointer to OBJC_IVAR_$_<Class>.<name> in .dynsym plus the
                  offset word.  Class cells: the slot either holds the OBJC_CLASS_$_
                  symbol value (.dynsym) or - for classes imported from the system
                  frameworks - carries an ABS32 relocation whose symbol is the class;
                  both routes are checked, the relocation route is named when used.
  * calls       - the set of bl/blx rows inside the body must equal the spec's set, and
                  every `bl <name>` route's computed target must match ROUTE_TARGETS.
  * branches    - the set of conditional/unconditional b* rows whose destination lands
                  inside the body must equal the spec's set.  Rows outside the body are
                  literal-pool words that mask as branches; they are recorded in
                  `disjoint_branch_rows` instead of being silently dropped.
  * anchors     - the listed instruction texts must match the listing byte for byte.

Machine-generated spec tables + hand-written semantics; see
reconstruction/reverse-v3/native/BLOCK_MIGRATION.md for the prose and boundaries.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

sys.path.insert(0, str(Path(__file__).resolve().parent))
from trace_objc_dispatch import ELFMemory
from recover_drawframe_slices import verify_disassembly

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ROOT / 'reconstruction/reverse-v3/native'
EXPECTED_SHA = '733d821027d69de329d0ba171df2e6013d612edf5a4d327badd001acc30b94c7'
EXPECTED_BASE = 0x0105FAF4

ROUTE_TARGETS = {
    'bl loc.imp.objc_msgSend': 0x001c281c,
    'bl sym.imp.__aeabi_idiv': 0x001c3728,
    'bl sym.makeIntpair_int__int_': 0x004b49fc,
}

SPECS = [
    dict(
        name='wtl_updatephysicalblocktol',
        method='WorldTileLoader -[updatePhysicalBlockToLatestVersion:]',
        types='v12@0:4^{PhysicalBlock=ii^{Tile}cCdII[32*][32C]}8',
        start=8802480,
        end=8807724,
        disasm='disasm_worldtileloader_updatephysicalblocktolatestversion_.txt',
        base_add=8802500,
        base_literal=8806364,
        boundary='ARM.exidx end 0x0086652c (listing bound); next ObjC IMP 0x0086652c WorldTileLoader -[unarchiveLightBlocksForClient:]',
        selectors={
                 0x865fe0: (15213624, 'getRockAndDirtHeightforX:rockHeight:dirtHeight:'),
                 0x865ff8: (15213480, 'worldWidthMacro'),
                 0x86623c: (15213480, 'worldWidthMacro'),
                 0x866248: (15213576, 'isCaveForX:y:faultOffset:'),
                 0x86624c: (15213572, 'faultOffsetForX:y:'),
                 0x866258: (15213600, 'getX:Y:octaves:'),
                 0x8664bc: (15213624, 'getRockAndDirtHeightforX:rockHeight:dirtHeight:'),
                 0x8664c4: (15213572, 'faultOffsetForX:y:'),
                 0x8664d0: (15213480, 'worldWidthMacro'),
                 0x8664d8: (15213600, 'getX:Y:octaves:'),
                 0x866514: (15213596, 'isBeachForPos:height:'),
                 0x866524: (15213676, 'dynamicWorld'),
                 0x866528: (15213788, 'createTreasureChestOrTrollAtTile:atPos:loadTroll:loadTreasure:'),
        },
        imports={
                 0x866244: (17151904, 'objc_msgSend'),
                 0x8664cc: (17151904, 'objc_msgSend'),
        },
        ivars={
                 0x865ff0: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x866238: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x86625c: (17161628, 'OBJC_IVAR_$_WorldTileLoader.flintDensityNoiseFunction', 36),
                 0x866454: (17161544, 'OBJC_IVAR_$_WorldTileLoader.yHeightDivider', 244),
                 0x8664b8: (17161612, 'OBJC_IVAR_$_WorldTileLoader.bestStartPosition', 76),
                 0x8664d4: (17161548, 'OBJC_IVAR_$_WorldTileLoader.world', 4),
                 0x8664dc: (17161628, 'OBJC_IVAR_$_WorldTileLoader.flintDensityNoiseFunction', 36),
                 0x8664e0: (17161624, 'OBJC_IVAR_$_WorldTileLoader.tinDensityNoiseFunction', 40),
                 0x8664e4: (17161568, 'OBJC_IVAR_$_WorldTileLoader.rockHeights', 96),
                 0x866510: (17161564, 'OBJC_IVAR_$_WorldTileLoader.dirtHeights', 92),
        },
        classes={},
        instructions=[(8802480, 'push {r4, r5, r6, r7, r8, sl, fp, lr}'), (8802520, 'ldrb r0, [r0, 0xd]'), (8802532, 'bge 0x86568c'), (8802644, 'bl loc.imp.objc_msgSend'), (8802832, 'bl sym.imp.__aeabi_idiv'), (8803056, 'beq 0x865670'), (8803356, 'bne 0x865664'), (8803784, 'strb r2, [r1, r0, lsl 6]'), (8803932, 'bl loc.imp.objc_msgSend'), (8803992, 'bge 0x865bbc'), (8804608, 'bl loc.imp.objc_msgSend'), (8805320, 'bge 0x866474'), (8805676, 'bl loc.imp.objc_msgSend'), (8807720, 'invalid')],
        calls=[(8802644, 'bl loc.imp.objc_msgSend'), (8802808, 'bl loc.imp.objc_msgSend'), (8802832, 'bl sym.imp.__aeabi_idiv'), (8802908, 'bl loc.imp.objc_msgSend'), (8803012, 'bl loc.imp.objc_msgSend'), (8803036, 'bl sym.imp.__aeabi_idiv'), (8803300, 'blx ip'), (8803344, 'blx lr'), (8803644, 'blx r4'), (8803828, 'bl loc.imp.objc_msgSend'), (8803876, 'bl sym.makeIntpair_int__int_'), (8803932, 'bl loc.imp.objc_msgSend'), (8804164, 'bl loc.imp.objc_msgSend'), (8804564, 'bl sym.makeIntpair_int__int_'), (8804608, 'bl loc.imp.objc_msgSend'), (8804832, 'blx r4'), (8804940, 'blx r3'), (8805024, 'blx r2'), (8805196, 'blx lr'), (8805492, 'bl loc.imp.objc_msgSend'), (8805676, 'bl loc.imp.objc_msgSend'), (8805880, 'blx r6'), (8805984, 'blx r3'), (8806124, 'blx r2'), (8806288, 'blx lr'), (8806636, 'blx lr'), (8806876, 'blx lr'), (8807144, 'blx lr'), (8807384, 'blx lr')],
        branches=[(8802532, 'bge', 8803980), (8802556, 'bge', 8803976), (8802700, 'blt', 8803956), (8802712, 'bge', 8803956), (8802724, 'ble', 8803952), (8802736, 'beq', 8803952), (8802844, 'beq', 8803952), (8802932, 'beq', 8803952), (8803056, 'beq', 8803952), (8803120, 'beq', 8803128), (8803124, 'b', 8803960), (8803168, 'bne', 8803948), (8803188, 'ble', 8803944), (8803356, 'bne', 8803940), (8803700, 'ble', 8803936), (8803720, 'bpl', 8803936), (8803936, 'b', 8803940), (8803940, 'b', 8803944), (8803944, 'b', 8803948), (8803948, 'b', 8803952), (8803952, 'b', 8803956), (8803956, 'b', 8803960), (8803972, 'b', 8802548), (8803976, 'b', 8803980), (8803992, 'bge', 8805308), (8804016, 'bge', 8805304), (8804088, 'beq', 8805284), (8804244, 'bge', 8804292), (8804256, 'b', 8804300), (8804336, 'bge', 8804360), (8804368, 'beq', 8805280), (8804504, 'bge', 8804520), (8804516, 'b', 8804528), (8804620, 'beq', 8805260), (8804664, 'bne', 8805256), (8804948, 'bge', 8804964), (8804960, 'b', 8805032), (8805228, 'ble', 8805252), (8805252, 'b', 8805256), (8805256, 'b', 8805260), (8805260, 'b', 8805264), (8805276, 'b', 8804316), (8805280, 'b', 8805284), (8805284, 'b', 8805288), (8805300, 'b', 8804008), (8805304, 'b', 8805308), (8805320, 'bge', 8807540), (8805344, 'bge', 8807536), (8805416, 'beq', 8807516), (8805552, 'bge', 8805576), (8805584, 'beq', 8807512), (8805716, 'bne', 8807488), (8805732, 'bne', 8807488), (8805992, 'bge', 8806064), (8806004, 'b', 8806132), (8806316, 'ble', 8807484), (8806348, 'bge', 8806400), (8806360, 'b', 8806408), (8806676, 'ble', 8806700), (8806696, 'bmi', 8806748), (8806724, 'bpl', 8807008), (8806744, 'ble', 8807008), (8806908, 'ble', 8806964), (8806928, 'bpl', 8806964), (8806964, 'b', 8807480), (8807184, 'ble', 8807208), (8807204, 'bmi', 8807256), (8807232, 'bpl', 8807476), (8807252, 'ble', 8807476), (8807416, 'ble', 8807472), (8807436, 'bpl', 8807472), (8807472, 'b', 8807476), (8807476, 'b', 8807480), (8807480, 'b', 8807484), (8807484, 'b', 8807488), (8807488, 'b', 8807492), (8807504, 'b', 8805532), (8807512, 'b', 8807516), (8807516, 'b', 8807520), (8807532, 'b', 8805336), (8807536, 'b', 8807540)],
        semantics=("updatePhysicalBlockToLatestVersion: is the WorldTileLoader physical-block format-migration routine: handed one ^{PhysicalBlock} record it upgrades the record's 32x32 in-memory tile image in up to three cumulative passes selected by the record's version byte, and returns without ever writing that byte back. The prologue pushes {r4,r5,r6,r7,r8,sl,fp,lr} at 0x008650b0 and reserves 0x298 at 0x008650bc; the PIC base comes from the pool word at 0x00865fdc (add r3,pc,r3 at 0x008650c4) and is kept at [fp,-0x130]; self goes to [fp,-0x30] (0x008650c8), the never-re-read _cmd to [fp,-0x34] (0x008650cc) and the record argument to [fp,-0x38] (0x008650d0). The first thing it reads is the version byte (ldrb r0,[r0,0xd] at 0x008650d8, cmp 3 at 0x008650dc); the bge at 0x008650e4 skips the first pass and lands at 0x0086568c where the same byte is re-read (0x0086568c-0x00865690) and gate two runs (cmp 5, bge 0x00865bbc at 0x00865698), and gate three re-reads it at 0x00865bc0 (cmp 7) whose bge at 0x00865bc8 jumps straight to the epilogue at 0x00866474 (sub sp,fp,0x28; vpop {d8,d9}; pop {r4,r5,r6,r7,r8,sl,fp,pc}). The passes are therefore cumulative: byte <3 runs A then B then C in one call, 3..4 runs B and C, 5..6 runs C only, >=7 does nothing; the whole listing contains no store to offset 13 of the record, so nothing in this body bumps the version. Pass A (byte<3) is a single loop over tile columns i (counter [fp,-0x3c], zeroed at 0x008650e8; head 0x008650f4 cmp 0x20, bge 0x008650fc exiting at 0x00865688; increment 0x00865678-0x00865684). Per column it forms index = physicalBlock->[0]*32 + i (ldr 0x00865108, add r1,r2,r1,lsl 5 0x00865110), calls [self getRockAndDirtHeightforX:index rockHeight:&(fp-0x44) dirtHeight:(stack, &(fp-0x48) staged at 0x00865134)] (bl objc_msgSend 0x00865154, selector from cell 0x00865fe0), subtracts physicalBlock->[4]*32 from both returned heights (0x00865160-0x00865180) into local rock/dirt at [fp,-0x4c]/[fp,-0x50], and runs a guard chain: continue only when 0 <= local rock < 0x20 (blt 0x0086518c, bge 0x00865198), global rockHeight > 0x1f0 (ble 0x008651a4), index != 0 (beq 0x008651b0), index != (W*32)/4 (bl 0x008651f8 = [self->world worldWidthMacro], __aeabi_idiv 0x00865210, beq 0x0086521c), index != (W*32)/4*2 (0x00865260-0x00865268, beq 0x00865274) and index != (W*32)/4*3 (idiv 0x008652dc, mul 0x008652e4, beq 0x008652f0), W being re-asked each time (0x008651f8, 0x0086525c, 0x008652c4). It then addresses the tile at tiles(physicalBlock+8) + (local rock*32+i)*64 (0x00865314-0x00865320) and bails unless byte3 == 0 (ldrb 0x00865324, beq 0x00865330) and byte0 == 8 (ldrb 0x0086534c, bne 0x00865360) and local dirt - local rock > 2 (0x00865364-0x00865374); it evaluates the inner call [self faultOffsetForX:index y:rockHeight-1] (blx ip 0x008653e4, selector cell 0x0086624c) and the outer [self isCaveForX:index y:rockHeight-1 faultOffset:fault] (blx lr 0x00865410, cell 0x00866248, fault returned at 0x008653f4 and stacked at 0x00865408) and skips when the result is nonzero (bne 0x0086541c). The last test is a flint-density band: [self->flintDensityNoiseFunction getX:(((float)index+1453.0f)/32.0f/self->yHeightDivider)*1.4230f Y:(((float)rockHeight+1247.0f)/32.0f/self->yHeightDivider)*1.4536f octaves:5] (ivar cells 0x0086625c and 0x00866454, float pools 0x008657a4-0x008657c0, blx r4 = objc_msgSend 0x0086553c), with 0.55 synthesised as 0.85-0.3 at 0x00865568; the fixup runs only for 0.55 < noise < 0.85 (ble 0x00865574, bpl 0x00865588) and rewrites the tile in place: byte2 = 1 (strb 0x008655a0), byte1 = 1 (strb 0x008655b4), byte0 = 2 (strb 0x008655c8), after which it registers a dynamic object: [self->world dynamicWorld] (bl 0x008655f4, world ivar via 0x008664d4/0x00866520, selector cell 0x00866524), makeIntpair(&(fp-0x80), index, rockHeight) (bl 0x00865624), then [dynamicWorld createTreasureChestOrTrollAtTile:&tile atPos:(index,rockHeight) loadTroll:0 loadTreasure:1] (bl 0x0086565c, selector cell 0x00866528; receiver is the dynamicWorld result, the pair words are read back at 0x00865638/0x0086563c and 0/1 are stacked at 0x00865648-0x00865654). Every pass-A skip funnels through the chain 0x00865660-0x00865678 back to the increment. Pass B (byte<5) loops columns j = [fp,-0x84] 0..31 (head 0x008656a8, bge 0x008656b0 to 0x00865bb8): per column idx = physicalBlock->[0]*32 + j, skipped when idx equals self->bestStartPosition (cell 0x008664b8, offset 76; ldr 0x008656ec, beq 0x008656f8), it recomputes fresh heights via [self getRockAndDirtHeightforX:idx ...] (bl 0x00865744) minus physicalBlock->[4]*32 and walks k from max(local rock, 0) (0x00865788-0x008657d8) while k < local dirt and k < 0x20 (head 0x008657dc, exit beq 0x00865810 to 0x00865ba0), per k reading self->rockHeights[idx] (cell 0x008664e4, offset 96, ldr 0x0086585c) and self->dirtHeights[idx] (cell 0x00866510, offset 92, ldr 0x00865880) and passing their maximum as the height (selection 0x00865898-0x008658b0); it requires [self isBeachForPos:(idx, k+physicalBlock->[4]*32) height:max] to be true (makeIntpair 0x008658d4, bl 0x00865900, beq 0x0086590c skips when false) and tile byte0 at tiles+((k*32)+j)*64 to equal 8 (ldrb 0x0086592c, bne 0x00865938). It then samples flint noise with X = (idx/(32*W))*0.0625 and Y = ((((k+physicalBlock->[4]*32) - 5*rockHeights[idx])/32)/max(W,512))*4*6.0, octaves 3 (double 5.0 at 0x00865a14, max(W,512) selection 0x00865a50-0x00865aa4, 0.0625 pool 0x00865e80, 6.0 staged at 0x00865ac8, blx lr 0x00865b4c), and when noise > 0.4 (ble 0x00865b6c) writes 0x3a into tile byte0 (strb 0x00865b78) and byte1 (strb 0x00865b80); its skips funnel 0x00865b84-0x00865b90 to the k increment and 0x00865ba0-0x00865ba8 to the column increment. Pass C (byte<7) loops columns m = [fp,-0xe0] 0..31 (head 0x00865bd8, exit bge 0x00865be0 to 0x00866470 and the epilogue): idx = physicalBlock->[0]*32 + m, skipped when idx == self->bestStartPosition (beq 0x00865c28), fresh rock via bl 0x00865c74; inner loop k = 0 while k < min(local rock, 0x20) (head 0x00865c9c, exit beq 0x00865cd0 to 0x00866458); per k with idx1 = k + physicalBlock->[4]*32 and tile index (k*32)+m it first calls [self faultOffsetForX:idx y:idx1] (bl 0x00865d2c, selector cell 0x008664c4), requires tile byte0 == 1 (ldrb 0x00865d4c, bne 0x00865d54) and byte3 == 0 (ldrb 0x00865d5c, bne 0x00865d64), then computes C_nx = ((idx+5673)/32)/W*4 (5673.0f pool 0x00865fec, [world worldWidthMacro] blx 0x00865df8) and C_ny = ((idx1+6343-fault)/32)/max(W,512)*4 (6343 via movw 0x00865d8c, clamp 0x00865e68-0x00865e74 re-issuing the width call at 0x00865eec, blx 0x00865e60). It samples noise2 = [flint getX:C_nx*0.112 Y:C_ny*0.084 octaves:2] (double pools 0x00865e90/0x00865e88, blx 0x00865f90) and requires noise2 > 0 (ble 0x00865fac), then C_ty = (1 - max(idx1,400)/self->rockHeights[idx]) * 0.004f (400 via movw 0x00865fb0, max 0x00865fc8/0x00866000-0x00866008, rockHeights re-read 0x00866074, 0.004f pool 0x00866254, stored 0x00866090) and noise3 = [self->tinDensityNoiseFunction getX:C_nx*0.012+0.212 Y:C_ny+0.47 octaves:2] (tin cell 0x008664e0, double pools 0x00865ea8/0x00865ea0/0x00865e98, blx 0x008660ec). A mirrored band test follows: noise3 <= 0.299-C_ty goes to 0x0086612c (ble 0x00866114), noise3 < 0.3 drops into the first write path at 0x0086615c (bmi 0x00866128), noise3 >= -0.299+C_ty or <= -0.3 go to the second region at 0x00866260 (bpl 0x00866144, ble 0x00866158), and the remainder (-0.3 < noise3 < -0.299+C_ty) also falls into the first write path. That path computes noise4 = [flint getX:C_nx*0.012 Y:C_ny*0.054 octaves:2] (pools 0x00866480/0x008664b0, blx 0x008661dc) and, when 0.1 < noise4 < 0.15 (ble 0x008661fc, bpl 0x00866210), stores byte3 = 0x6a (strb 0x0086622c). The second region computes noise5 = [tin getX:C_nx*0.028+0.612 Y:C_ny+0.27 octaves:2] (pools 0x00866498/0x00866490/0x00866488, blx 0x008662e8) and repeats the same-shaped band with 0.298/0.3 constants (ble 0x00866310, bmi 0x00866324 to the write path, bpl 0x00866340, ble 0x00866354): either skip or run the second write path at 0x00866358, which computes noise6 = [flint getX:C_nx*0.035 Y:C_ny*0.072 octaves:2] (pools 0x008664a8/0x008664a0, blx 0x008663d8) and stores byte3 = 0x6b when 0.1 < noise6 < 0.15 (ble 0x008663f8, bpl 0x0086640c, strb 0x00866428). All pass-C skips thread through 0x00866430-0x00866444 to the k increment (0x00866444-0x0086644c) and 0x00866458-0x00866460 to the m increment. The 81-branch decision grid in one line: three version gates; pass A per column = six numeric guards + three tile-byte/gap gates + the cave pair + the two-sided flint band; pass B per column = bestStart skip + outer/inner loop conditions + beach gate + byte0 gate + one-sided 0.4 noise test; pass C per column = bestStart skip + loop conditions + byte0/byte3 gates + noise2 > 0 + the two mirrored band tests each with its own 0.1..0.15 window; and every skip is a short chain of unconditional branches into the loop tails. State consulted: self->world (cells 0x00865ff0, 0x00866238, 0x008664d4; offset 4) only for worldWidthMacro and dynamicWorld; self->bestStartPosition (cell 0x008664b8; offset 76); self->flintDensityNoiseFunction (cells 0x0086625c, 0x008664dc; offset 36); self->tinDensityNoiseFunction (cell 0x008664e0; offset 40); self->yHeightDivider (cell 0x00866454; offset 244); self->rockHeights (cell 0x008664e4; offset 96); self->dirtHeights (cell 0x00866510; offset 92). Measured artifacts: the _cmd spill at 0x008650cc is never re-read; the movw value stubs staged around 0x00865100-0x0086532c (e.g. into [fp,-0x134] at 0x0086513c, [sp,0x158] at 0x0086532c) are never reloaded; pass A asks [self->world worldWidthMacro] up to three times per surviving column (0x008651f8, 0x0086525c, 0x008652c4) and passes B and C re-issue the same send inside their >=0x200 clamp arms (0x00865aa0, 0x00865eec); the only memory this body mutates is the 64-byte-stride tile image at physicalBlock->tiles (+8), plus the side effect of the pass-A createTreasureChestOrTrollAtTile:atPos:loadTroll:loadTreasure: send."),
    ),
]


def signed(v: int) -> int:
    return v - (1 << 32) if v & 0x80000000 else v


def bl_target(site: int, word: int) -> int:
    if word >> 24 != 0xEB:
        raise ValueError(f'{site:#x} is not ARM bl')
    imm = word & 0xFFFFFF
    if imm & 0x800000:
        imm -= 1 << 24
    return (site + 8 + (imm << 2)) & 0xffffffff


def recover(path: Path) -> dict:
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_SHA:
        raise ValueError('unsupported ELF SHA-256; fixed-IMP analysis requires pinned original')
    memory = ELFMemory(path)
    elf = ELFFile(io.BytesIO(data))

    def cstr(addr):
        off = memory.offset(addr, 1)
        if off is None:
            return None
        end = data.find(b'\0', off, off + 256)
        return data[off:end].decode('utf-8', 'replace') if end >= 0 else None

    dynsym = {}
    for sec in elf.iter_sections():
        if sec.name == '.dynsym':
            for s in sec.iter_symbols():
                if s['st_value']:
                    dynsym.setdefault(s['st_value'], s.name)
    relocs = {}
    for sec in elf.iter_sections():
        if not isinstance(sec, RelocationSection):
            continue
        syms = elf.get_section(sec['sh_link'])
        for r in sec.iter_relocations():
            if r['r_info_sym']:
                relocs[r['r_offset']] = syms.get_symbol(r['r_info_sym']).name

    methods = []
    for spec in SPECS:
        text = (NATIVE / spec['disasm']).read_text()
        words = verify_disassembly(memory, text, spec['start'], spec['end'])
        rows = {}
        for mm in re.finditer(r'\b(0x[0-9a-f]{8})\s+[0-9a-f]{8}\s+(.*)', text):
            rows[int(mm.group(1), 16)] = mm.group(2).split(';')[0].strip()

        base = None
        if spec['base_add'] is not None:
            base = (spec['base_add'] + 8 + signed(memory.word(spec['base_literal']))) & 0xffffffff
            if base != EXPECTED_BASE:
                raise ValueError(f"{spec['name']}: PIC base drift {base:#x}")

        selectors = {}
        for cell, (expected_slot, expected_name) in spec['selectors'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: selector cell {cell:#x} -> {slot:#x}")
            got = cstr(memory.word(slot))
            if got != expected_name:
                raise ValueError(f"{spec['name']}: selector drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'selector': got}

        for cell, (expected_slot, expected_symbol) in spec.get('classes', {}).items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: class cell {cell:#x} -> {slot:#x}")
            entry = memory.word(slot)
            if entry is None:
                got = relocs.get(slot, '')
                if got != expected_symbol:
                    raise ValueError(f"{spec['name']}: class reloc drifted at {cell:#x}: {got!r}")
                selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got,
                                              'route': 'ABS32 relocation symbol'}
                continue
            got = dynsym.get(entry, '')
            if got != expected_symbol:
                raise ValueError(f"{spec['name']}: class drifted at {cell:#x}: {got!r}")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'class': got,
                                          'route': 'dynsym entry at slot word'}

        for cell, (expected_slot, expected_name) in spec['imports'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: import cell {cell:#x} -> {slot:#x}")
            got = memory.imports.get(slot)
            route = 'PLT/GOT relocation (R_ARM_JUMP_SLOT / GLOB_DAT)'
            if got is None:
                got = relocs.get(slot)
                route = 'ABS32 relocation symbol'
            if got != expected_name:
                raise ValueError(f"{spec['name']}: import drifted at {cell:#x}: {got!r} ({route})")
            selectors[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'import': got, 'route': route}

        ivars = {}
        for cell, (expected_slot, expected_symbol, expected_offset) in spec['ivars'].items():
            slot = (base + signed(memory.word(cell))) & 0xffffffff
            if slot != expected_slot:
                raise ValueError(f"{spec['name']}: ivar cell {cell:#x} -> {slot:#x}")
            entry = memory.word(slot)
            symbol = dynsym.get(entry, '')
            offset = memory.word(entry)
            if symbol != expected_symbol or offset != expected_offset:
                raise ValueError(f"{spec['name']}: ivar {cell:#x} drifted: {symbol!r}@{offset}")
            ivars[f'0x{cell:08x}'] = {'slot': f'0x{slot:08x}', 'symbol': symbol, 'offset': offset}

        inrange = {a: ins for a, ins in rows.items() if spec['start'] <= a < spec['end']}
        listed = {a for a, ins in inrange.items() if re.match(r'^blx?\s', ins)}
        expected_sites = {site for site, _ in spec['calls']}
        if listed != expected_sites:
            raise ValueError(f"{spec['name']}: call set drifted: {sorted(listed ^ expected_sites)}")
        calls = []
        for site, route in spec['calls']:
            if rows[site] != route:
                raise ValueError(f"{spec['name']}: route drifted at {site:#x}: {rows[site]!r}")
            target = None
            if route.startswith('bl '):
                target = bl_target(site, memory.word(site))
                expected = ROUTE_TARGETS.get(route)
                if expected is None or target != expected:
                    raise ValueError(f"{spec['name']}: bl target drifted at {site:#x}: {target:#x}")
            calls.append({'site': f'0x{site:08x}', 'route': route,
                          'callee': f'0x{target:08x}' if target else None})

        listed_branches = set()
        disjoint = []
        for a, ins in inrange.items():
            m = re.match(r'^(b\w*)\s+(0x[0-9a-f]+)', ins)
            if not m or m.group(1) in ('bl', 'blx'):
                continue
            dest = int(m.group(2), 16)
            if spec['start'] <= dest < spec['end']:
                listed_branches.add((a, m.group(1), dest))
            else:
                disjoint.append({'address': f'0x{a:08x}', 'mnemonic': m.group(1),
                                 'destination': f'0x{dest:08x}'})
        expected_branches = {(a, mn, dest) for a, mn, dest in spec['branches']}
        if listed_branches != expected_branches:
            raise ValueError(f"{spec['name']}: branch set drifted: {sorted(listed_branches ^ expected_branches)}")

        for address, expected_text in spec['instructions']:
            if rows.get(address) != expected_text:
                raise ValueError(f"{spec['name']}: instruction drifted at {address:#x}: "
                                 f"{rows.get(address)!r} != {expected_text!r}")

        methods.append({
            'name': spec['name'],
            'method': spec['method'],
            'types': spec['types'],
            'imp': f"0x{spec['start']:08x}",
            'boundary_end': f"0x{spec['end']:08x}",
            'boundary': spec['boundary'],
            'verified_words': words,
            'pic_base': f'0x{base:08x}' if base else None,
            'selectors': selectors,
            'ivars': ivars,
            'calls': calls,
            'branches': [{'address': f'0x{a:08x}', 'mnemonic': mn,
                          'destination': f'0x{d:08x}'}
                         for a, mn, d in spec['branches']],
            'disjoint_branch_rows': disjoint,
            'semantics': spec['semantics'],
        })

    return {
        'schema': 1,
        'elf_sha256': sha,
        'batch': "Physical-block version-upgrade batch (E15): the WorldTileLoader block upgrader - updatePhysicalBlockToLatestVersion: rewrites a record's 64-byte-stride tile image in up to three cumulative passes gated by the record's version byte (runs while byte < 3, < 5, < 7; never writes the byte back), including the column guards, the ore-band fixups and the pass-A treasure/troll placement; 1 body",
        'claim': ('a static bounded-body map with per-instruction anchors; the concrete storage layer '
                  'behind the database calls, the caller that bumps the version byte, the tile-type '
                  'names behind the raw tile bytes and the coordinate-geometry meaning of the noise '
                  'offsets are outside this body'),
        'classes': methods,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('elf', type=Path)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--output', type=Path,
                        default=NATIVE / 'block_migration.json')
    args = parser.parse_args()
    report = recover(args.elf)
    payload = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.check:
        if args.output.read_text() != payload:
            raise SystemExit('stale block_migration.json')
    else:
        args.output.write_text(payload)
    total = sum(m['verified_words'] for m in report['classes'])
    print(f"classes={len(report['classes'])} words={total}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
