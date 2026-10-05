// Recovered fact: how the original decides a blockhead is male.
//
// Blockhead -[isMale] is an eight-instruction getter that returns a SIGNED BYTE, and the byte it returns is
// Blockhead.shoesCube - the gender the game shows is derived from the blockhead's appearance, not stored as a
// gender flag. Derived from the code (never guessed), by the same cell chain this project uses everywhere:
//
//     0xc86548  Blockhead -[isMale]                       (IMP from the ObjC method table)
//     0xc8654c  ldr  r2,[pc,#0x2c] ; add r2,pc,r2         r2 = 0x105faf0, i.e. PIC_BASE - 4
//     0xc86554  ldr  r3,[pc,#0x20]                        r3 = *(0xc85b08) = 0xfffff5ac
//     0xc86564  ldr  r0,[sp,#4]                           r0 = self
//     0xc86568  ldr  r1,[r2]                              r1 = *(0x105f09c) = 0xf35440   (the ivar cell)
//     0xc8656c  add  r0,r0,r1                             self + the offset the cell holds
//     0xc86570  ldrsb r0,[r0]  ; bx lr                    the signed byte
//
//     cell 0xf35440 holds 280, and OBJC_IVAR_$_Blockhead.shoesCube is the symbol whose cell is 0xf35440.
//
// The truth rule is therefore "the byte is non-zero", not "the byte is 1" - the same rule the DynamicObject flag
// cluster uses, and for the same reason: the original returns a signed char and callers branch on its truth, so a
// negative encoding counts as male just as a positive one does.
//
// NOT YET USABLE BY THE REPLACEMENT, and that is why this file exists rather than a call site: the rewrite models
// clothing as clothingHead/clothingLegs and has no shoesCube, so isMale has no counterpart to compute. The
// original plays sighFemale.wav or sighMale.wav from Blockhead -[sleepOnSpotIfPossible] depending on this byte, so
// wiring a sleep sound without it would mean picking a variant arbitrarily. That is a fabricated choice, not a
// recovered one, so the sleep sound stays unmatched until the rewrite can distinguish the two.
#pragma once

#include <cstddef>
#include <cstdint>

namespace blockheads::recovered::blockhead_gender {

// OBJC_IVAR_$_Blockhead.shoesCube, by the cell chain above
inline constexpr std::size_t kOffsetShoesCube = 280;
inline constexpr std::uint32_t kCellShoesCube = 0x00f35440U;

// Blockhead -[isMale]'s IMP, so the derivation can be re-walked from the binary
inline constexpr std::uint32_t kImpIsMale = 0x00c86548U;

// The rule the original's ldrsb + branch implements: any non-zero byte means male.
constexpr bool isMaleFromShoesCube(std::int8_t shoes_cube) {
    return shoes_cube != 0;
}

}  // namespace blockheads::recovered::blockhead_gender
