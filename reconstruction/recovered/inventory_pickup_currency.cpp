#include "inventory_pickup_currency.h"

namespace recovered::pickup_currency {
// Byte-for-byte ordered local recovery of 0xc628f8..0xc62fec. Both itemType
// sends are unconditional and distinct. The 0xb branch executes
// setNeedsRemoved:1 then FALLS THROUGH to the money comparison; only the
// second itemType result decides the money region. Loop limits recompute
// from the ORIGINAL dataA minus platinum insertions (not a running balance).
static void runDenomination(Runtime& r, Object self, std::int32_t denom,
                            std::int32_t limit, std::int32_t& inserted) {
    while (inserted < limit) {
        if (r.sendCanPickUp(self, denom) != 1) return; // bne level-exit
        const Object item = r.allocItem();
        const Object init = r.sendInitWithType(item, denom);
        const Object armed = r.sendAutorelease(init);
        r.sendAddItemFlash(self, armed);
        ++inserted;
    }
}

Outcome splitMoney(Runtime& r, Object self, Object freeblock) {
    Outcome out{};
    const std::int32_t type1 = r.itemType(freeblock); // 0xc628f8
    if (type1 == 0xb) {
        // 0xc6292c..0xc62968: [freeblock setNeedsRemoved:1] (signed 1 via
        // sxtb). The blx at 0xc62968 FALLS THROUGH to the second itemType
        // (verified: ARM trace for type 0xb ends itemType/setNeedsRemoved/
        // itemType/nonmoney-tail), so the money loops are still gated by
        // the 0x12a comparison below.
        r.setNeedsRemoved(freeblock, 1);
    }
    const std::int32_t type2 = r.itemType(freeblock);  // 0xc6296c
    if (type2 != 0x12a) {
        out.stop = Stop::NonMoney;
        return out;
    }
    const std::int32_t a = uxth(r.dataA(freeblock));   // 0xc629b0..0xc629f8
    const std::int32_t b = uxth(r.dataB(freeblock));   // 0xc629fc..0xc62a14
    runDenomination(r, self, 0x104, a, out.platinum);  // loop 1 platinum
    // 0xc62bd8..0xc62c1c: limit2 = (dataA - platinum)*100 + b/100
    const std::int32_t limit2 = (a - out.platinum) * 100 + b / 100;
    runDenomination(r, self, 0xa7, limit2, out.gold);  // loop 2 gold
    // 0xc62db8..0xc62df4: limit3 = (limit2 - gold)*100 + b%100
    const std::int32_t limit3 = (limit2 - out.gold) * 100 + b % 100;
    runDenomination(r, self, 0xa6, limit3, out.copper); // loop 3 copper
    out.residual = limit3 - out.copper;                 // 0xc62f9c..0xc62fa8
    if (out.residual > 0) {                             // 0xc62fb4 bgt
        out.stop = Stop::Residual;
        out.thousands = out.residual / 10000;           // smmul magic == /10000
        out.remainder = out.residual % 10000;           // mls  #0x2710
    } else {
        out.stop = Stop::ZeroResidual;                  // ble 0xc630a8
    }
    return out;
}
} // namespace recovered::pickup_currency
