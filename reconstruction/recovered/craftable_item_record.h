// Recovered model: the CraftableItem record - the 124-byte value the crafting pipeline copies.
//
// The evidence here is unusually direct: the type encoding in the original's own method table IS a layout
// description. -[PaintingCraftableItemObject initWithCraftableItem:imageData:outputImageData:] declares
//
//     @140@0:4{CraftableItem=ii[8i][8i]iiiSSi[8i]}8@132@136
//
// so the record is eleven fields of int / unsigned short / int[8] in that order. Its size comes out the
// same two independent ways: the encoding sums to 124 bytes, and the argument offsets in the same
// signature step from 8 to 132, a difference of 124. The 51 recorded 124-byte copy sites agree too.
//
// The offsets below are computed from the encoding by tools/test_craftable_item_record.py, which also
// re-derives them from the method table and requires this header to match - so a hand-edited offset fails
// instead of quietly retyping the binary.
//
// WHAT IS STILL NOT KNOWN, and is not faked here: what the fields MEAN. They are positional (f0..f10).
// The two int[8] arrays read like per-slot inventories or counted lists and the two `S` fields like small
// counts, but that is a reading, not evidence. The shape is now machine-checked; the semantics remain the
// open problem this project has carried the longest.
#pragma once

#include <cstddef>
#include <cstdint>

namespace blockheads::recovered {

struct CraftableItemRecord {
    std::int32_t f0;  // +0
    std::int32_t f1;  // +4
    std::int32_t f2[8];  // +8
    std::int32_t f3[8];  // +40
    std::int32_t f4;  // +72
    std::int32_t f5;  // +76
    std::int32_t f6;  // +80
    std::uint16_t f7;  // +84
    std::uint16_t f8;  // +86
    std::int32_t f9;  // +88
    std::int32_t f10[8];  // +92
};

static_assert(sizeof(CraftableItemRecord) == 124, "the encoding sums to 124 bytes");
static_assert(offsetof(CraftableItemRecord, f0) == 0, "field f0");
static_assert(offsetof(CraftableItemRecord, f1) == 4, "field f1");
static_assert(offsetof(CraftableItemRecord, f2) == 8, "field f2");
static_assert(offsetof(CraftableItemRecord, f3) == 40, "field f3");
static_assert(offsetof(CraftableItemRecord, f4) == 72, "field f4");
static_assert(offsetof(CraftableItemRecord, f5) == 76, "field f5");
static_assert(offsetof(CraftableItemRecord, f6) == 80, "field f6");
static_assert(offsetof(CraftableItemRecord, f7) == 84, "field f7");
static_assert(offsetof(CraftableItemRecord, f8) == 86, "field f8");
static_assert(offsetof(CraftableItemRecord, f9) == 88, "field f9");
static_assert(offsetof(CraftableItemRecord, f10) == 92, "field f10");

// Where the record actually lives, from the deserialiser evidence
// (reconstruction/reverse-v3/native/craftableitem_initsavedict.json, batch b3c):
//   * CraftableItemObject stores it inline at ivar offset 4 (cell 0x00f34ea0) - i.e. immediately
//     after the object's isa pointer, which is why the class's instance size is 128: 4 + 124;
//   * it is serialised as an opaque 124-byte NSData blob under the key `craftableItem`, written by
//     getBytes:length: at site 0x00ac7a18 into 0x00ac79f8;
//   * PaintingCraftableItemObject and BlockheadCraftableItemObject keep their own additions after it
//     (imageData/outputImageData at 128/132, name then a 20-byte skinOptions at 128/132).
//
// That is why the field MEANINGS are still open while the shape is not: the bytes arrive as an opaque
// blob, so what f0..f10 mean has to come from whoever BUILDS the blob (the crafting pipeline), not from
// the deserialiser.
namespace craftable_item_host {

// The serialisation pair, located by scanning .text for the `craftableItem` cfstring literal - there are
// exactly TWO references to that key in the whole binary, one per direction:
//   reader  CraftableItemObject -[initWithSaveDict:] @0x00ac7900, key site 0x00ac79a8 (copies 124 bytes
//           into ivar offset 4 via getBytes:length: at 0x00ac7a18);
//   writer  CraftableItemObject -[getSaveDict] @0x00ac7a54, key site 0x00ac7a68, whose body materialises
//           movw r5,#0x7c (124) into the argument list and adds the record pointer to the ivar offset.
// The selector NAMES at the two call sites are not resolved: these bodies call in the blx-through-slot
// form, which neither the trampoline tracer nor the selector watchlist covers. Recorded as unknown.
inline constexpr std::uint32_t kCraftableItemCfstringVa = 0x00f9b7b8U;
inline constexpr std::uint32_t kCraftableItemReaderKeySite = 0x00ac79a8U;
inline constexpr std::uint32_t kCraftableItemWriterKeySite = 0x00ac7a68U;
inline constexpr std::size_t kCraftableItemKeyReferencesInBinary = 2;

// The by-value initialiser -[PaintingCraftableItemObject initWithCraftableItem:imageData:outputImageData:]
// is the entry point a caller would use to hand in a freshly built record, and it is where the field
// semantics should be readable. Its senders are NOT findable statically today: the selector's cfstring
// (0x00fec1f8) and a slot containing it (0x00146c10) both exist, but no .text pool word addresses that slot
// PIC-relatively, and find_selector_senders.py reports 0 slots and 0 send sites for it. So its dispatch is
// not dispatched through the selector channel at all: probe_objc_send_channel.py shows NO __objc_selrefs
// slot and NO msgrefs entry for it, and the only holder of the name is its own __objc_const metadata. So
// within this image it has no static call site. "No static caller here" is not "never called" - the SEL
// could be built at run time and this image is a Mach-O conversion - and that is the supported statement.
inline constexpr bool kCraftableItemInitializerDispatchUnknown = true;

// The way in, found by resolving the base-class selectors' selref slots through the same chain that works
// for cfstrings: each resolves to exactly ONE loader.
//   setCraftableItem:        slot 0x00e7f55c -> loader 0x0067390c in PaintMixUI -[craftButton:]
//   initWithCraftableItem:   slot 0x00e80abc -> loader 0x00741c6c in the Painting subclass's initialiser
// The first is the crafting entry point: one place in the image hands a CraftableItem to an object, so the
// field values are computed in or below it. That is where f0..f10 would get their meaning.
inline constexpr std::uint32_t kCraftableItemSetSelectorSlot = 0x00e7f55cU;
inline constexpr std::uint32_t kCraftableItemCraftEntryPoint = 0x0067390cU;
inline constexpr std::size_t kCraftableItemObjectRecordOffset = 4;
inline constexpr std::uint32_t kCraftableItemObjectRecordCell = 0x00f34ea0U;
inline constexpr std::size_t kCraftableItemObjectInstanceSize = 128;   // isa (4) + record (124)
inline constexpr std::size_t kCraftableItemBlobLength = 124;
inline constexpr const char* kCraftableItemBlobKey = "craftableItem";
static_assert(kCraftableItemObjectRecordOffset + kCraftableItemBlobLength == kCraftableItemObjectInstanceSize);
}  // namespace blockheads::recovered::craftable_item_host

}  // namespace blockheads::recovered