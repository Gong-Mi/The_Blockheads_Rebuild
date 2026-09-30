#pragma once
#include "inventory_capacity.h"
#include <cstdint>

namespace recovered::pickup_currency {
using Object = inventory_capacity::Object;

// ITEM_MONEY (0x12a) currency-split region 0xc628f8..0xc62fec of
// Blockhead -[pickupFreeblockIfPossible:inTile:intentional:] (pinned ARM
// ELF 733d8210...b94c7). Message order and re-reads are mandatory; nil
// messaging and object lifetime come from the real runtime.
struct Runtime {
    virtual ~Runtime() = default;
    // [freeblock itemType]: sent TWICE unconditionally (0xc628f8, 0xc6296c),
    // each result is a distinct read.
    virtual std::int32_t itemType(Object freeblock) = 0;
    // type==0xb pre-branch 0xc6292c..0xc62968: [freeblock setNeedsRemoved:1]
    // (signed 1 via sxtb), then the blx FALLS THROUGH to the second itemType
    // read (original bytes, not an early return).
    virtual void setNeedsRemoved(Object freeblock, std::int8_t value) = 0;
    // dataA first (0xc629b0..0xc629f8), then dataB (0xc629fc..0xc62a14);
    // both sends read the freeblock directly and the results pass uxth:
    // low 16 bits zero-extended. Read exactly once per region entry.
    virtual std::int32_t dataA(Object freeblock) = 0;
    virtual std::int32_t dataB(Object freeblock) = 0;
    // Per-iteration capacity gate (receiver self): [self
    // canPickUpItemOfType:denom subItems:nil dataA:0 dataB:0].
    // Only exactly 1 continues; any other value ends THIS level now.
    virtual std::int32_t sendCanPickUp(Object self, std::int32_t denom) = 0;
    // [InventoryItem alloc] (class-reference slot 0xc63850).
    virtual Object allocItem() = 0;
    // [item initWithType:denom dataA:0 dataB:0 subItems:nil
    //        dynamicObjectSaveDict:nil]
    virtual Object sendInitWithType(Object item, std::int32_t denom) = 0;
    virtual Object sendAutorelease(Object item) = 0;
    // [self addItemToInventory:item flash:1]; return value not read.
    virtual void sendAddItemFlash(Object self, Object item) = 0;
};

enum class Stop : std::int8_t {
    NonMoney,     // second itemType != 0x12a -> fall through to 0xc63340
    Residual,     // residual > 0 branch at 0xc62fb4 -> tail 0xc62ff0
    ZeroResidual  // residual <= 0 fell to 0xc630a8
};

struct Outcome {
    Stop stop;
    std::int32_t platinum = 0; // inserted 0x104 loop 1
    std::int32_t gold = 0;     // inserted 0xa7  loop 2
    std::int32_t copper = 0;   // inserted 0xa6  loop 3
    std::int32_t residual = 0; // limit3 - copper
    std::int32_t thousands = 0;
    std::int32_t remainder = 0;
};

// Denomination model: 1 platinum(0x104) = 100 gold(0xa7) = 10000 copper(0xa6).
// dataA counts platinum, dataB counts sub-platinum copper cents; failed
// insertions cascade down the unit conversions at 0xc62bd8 (idiv r1=100
// survives the mul) and 0xc62db8 (modsi3):
//   limit1 = uxth(dataA)
//   limit2 = (dataA - platinum) * 100 + dataB / 100
//   limit3 = (limit2   - gold)    * 100 + dataB % 100
// Each level inserts while its own counter < limit AND the gate returns 1;
// a failed gate exits the level immediately. Loop counter and success
// counter advance together (failure jumps past both), so they stay equal.
// The tails beyond the stop edges were first thought to read unresolvable
// lazily initialized slots; that was wrong (manifest correction 2026-09-12):
// they are GOT-anchor recomputes and every literal now resolves. The
// residual>0 tail re-emits makeIntpair(rem/10000, rem%10000) as a NEW
// 0x12a freeblock via createFreeBlockAtPosition:... on the blockhead's
// dynamicWorld at its pos (see INVENTORY_PICKUP_CURRENCY.md). Modeled by
// K/R here but NOT ported: this module stops at the edges and callers must
// perform no other side effects beyond them.
Outcome splitMoney(Runtime&, Object self, Object freeblock);

inline std::int32_t uxth(std::int32_t raw) {
    return static_cast<std::uint16_t>(static_cast<std::uint32_t>(raw));
}
} // namespace recovered::pickup_currency
