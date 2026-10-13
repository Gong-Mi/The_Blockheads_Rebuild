// Recovered fact: how the original decides a blockhead is male, and who sets it.
//
// Blockhead -[isMale] returns a SIGNED BYTE read from Blockhead's own skin options - the gender the game shows is
// derived from the blockhead's appearance, not stored as its own flag. Walked from the binary by the cell chain this
// project uses everywhere, with ARM's own pc rule (pc = instruction address + 8):
//
//     0xc86548  Blockhead -[isMale]                       IMP from the ObjC method table
//     0xc8654c  ldr  r2,[pc,#0x2c]                        pool word at 0xc86580 = 0x3d959c
//     0xc86550  add  r2,pc,r2                             v = (0xc86550+8) + 0x3d959c = 0x105faf4 = PIC_BASE
//     0xc86554  ldr  r3,[pc,#0x20]                        r3 = *(0xc8657c) = 0xfffff5ac
//     0xc86558  ldr  r2,[r3,r2]                           cell_va = r3 + v = 0x105f0a0, cell = 0xf3544c
//     0xc86564  ldr  r0,[sp,#4]                           r0 = self
//     0xc86568  ldr  r1,[r2]                              r1 = the offset the cell holds = 728
//     0xc8656c  add  r0,r0,r1                             self + 728
//     0xc86570  ldrsb r0,[r0]  ; bx lr                    read as one signed byte
//
//     OBJC_IVAR_$_Blockhead.skinOptions is the symbol whose cell is 0xf3544c.
//
// WHO SETS IT: inside Blockhead -[customizationComplete:] (IMP 0xc89eec) the code reaches the same cell,
// loads the constant 1 and stores one byte:
//     0xc89f78  mov  r3,#1
//     0xc89f7c  strb r3,[r0,r1]      r0 = self, r1 = the offset from the cell  ->  self[728] = 1
// so finishing the customisation screen sets this byte to 1 (male); the other value comes from the editing
// path, which Blockhead -[customizationChanged:] holds the cell for. Note the write's site is a FUSED chain -
// the add that computes the base, the cell load, the offset load and the store are spread over ~24 bytes -
// which is why the scanner reports the ADD's address (0xc89f2c) and the store must be found by following it.
// Three
// readers are on the record too: Blockhead -[previewData] (0xb9d678) and
// Blockhead -[drawForButtonProjectionMatrix:modelViewMatrix:] (0xbedd08) dereference the cell, and
// Blockhead -[customizationChanged:] (0xc89e4c) holds it while the appearance is being edited.
//
// A DERIVATION ERROR WORTH KEEPING, because the first version of this file was wrong and sounded confident: I used
// the pc of the 'ldr' (0xc8654c + 8) where the 'add' (0xc86550 + 8) is what ARM uses. Four bytes low put the cell on
// 0xf35440 and named the ivar "shoesCube at 280". From that wrong cell I then recorded that the project's
// ivar-cell scanner had a blind spot on this ivar. It does not: it resolves the real cell and reports five sites on
// it, including the writer above. A four-byte arithmetic slip had turned into a plausible-sounding tool defect -
// which is the reason this paragraph stays in the file rather than being tidied away.
//
// The truth rule is "the byte is non-zero", not "== 1": the original returns a signed char and callers branch on its
// truth - the same rule the DynamicObject flag cluster uses, and a reading this project already got wrong once.
//
// NOT YET USABLE BY THE REPLACEMENT, and that is why this file exists rather than a call site: the rewrite models
// clothing as clothingHead/clothingLegs and has no skin options, so isMale has no counterpart to compute. The
// original plays one of the two sleep-sigh assets from Blockhead -[sleepOnSpotIfPossible], choosing between them by
// this byte, so wiring a sleep sound without it would mean picking a variant arbitrarily - a fabricated choice, not
// a recovered one. The asset names are discussed here WITHOUT being written out, deliberately:
// tools/test_audio_wiring_model.py counts a reference as an asset's file name appearing in a shipped source file,
// so naming one in a comment about NOT wiring it would move it into the referenced column.
#pragma once

#include <cstddef>
#include <cstdint>

namespace blockheads::recovered::blockhead_gender {

// OBJC_IVAR_$_Blockhead.skinOptions, by the cell chain above
inline constexpr std::size_t kOffsetSkinOptions = 728;
inline constexpr std::uint32_t kCellSkinOptions = 0x00f3544cU;

// the IMPs the derivation goes through, so it can be re-walked from the binary
inline constexpr std::uint32_t kImpIsMale = 0x00c86548U;
inline constexpr std::uint32_t kImpCustomizationComplete = 0x00c89eecU;
inline constexpr std::uint32_t kSiteWriteSkinOptions = 0x00c89f2cU;   // 'strb' inside -[customizationComplete:]

// The rule the original's ldrsb + branch implements: any non-zero byte means male.
constexpr bool isMaleFromSkinOptions(std::int8_t skin_options) {
    return skin_options != 0;
}

}  // namespace blockheads::recovered::blockhead_gender
