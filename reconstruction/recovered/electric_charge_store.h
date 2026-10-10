// Recovered contract: the electric charge store (the Workbench grid cell)
// (E75 workbench electricity / E76 furnace fuel / E75 solar).
//
// Evidence (reverse-v3 level A):
//   - The charge store is a u16 member (the fffff150 cell):
//       * availableElectricity (0x00b01284) reads it with `ldrh`;
//       * subtractElectricty: (0x00b0137c) keeps the amount as a halfword
//         (`strh r2, [fp,-0x1a]` @0xb013a4), guards `cmp r0, r1; bgt`
//         (@0xb013c0-0xb013c8: not enough exits), writes back
//         `sub r0, r2, r0; strh r0, [r1]` (@0xb013f0-0xb013f4) and sets its
//         dirty byte + the ffffc8d8/c8b4/c89c propagation chain.
//   - addToFuel: (0x00afdf94) type 0xf (15) reads the same u16 (`ldrh`
//     @0xafe0c4) and fences at 0x64 (100): `cmp r0, 0x64; bge` (@0xafe0c8)
//     rejects the add; the accepting path booleanizes (`movlt 1` @0xafe128)
//     and writes back `add r0, r3, r0; strh r0, [r1]` @0xafe180-0xafe184.
//   - energyFraction (0x00b01ec0) type 0x15 (21) divides the stored u16 by
//     0x2000 (8192): `movw r0, 0x2000` + `vcvt.f32.u32; vdiv.f32`
//     (@0xb01fe4-0xb02010).
//   - The type tables (all pinned compares): generate = {0xf, 0x14}
//     (generatesElectricity 0x00b01c24); storage = {0x15} (isStorageDevice
//     0x00b01bd4); the 9-compare use-set (0x00b01cac) covers
//     0xf/0x14/0x15/0x11/0x10/0x1b/...
//
// This module models the u16 store semantics: the read, the drain with the
// sufficient-units gate, the add with the furnace fence (100), the
// capacity-fraction divisor (8192) and the pinned type tables.
//
// Boundaries (do not promote beyond evidence):
//   - The dirty-propagation chains (ffffc8d8/c8b4/c89c) and the objc
//     notifies are callback-side here.
//   - The fence applies at type 0xf for the fuel add; other types' caps are
//     NOT asserted beyond the 8192 divisor (storage).
//   - All values are u16: the store wraps at 16 bits like the listing's
//     `strh` (the tests pin the 16-bit domain).
#pragma once

#include <cstdint>

namespace blockheads::recovered {

// The pinned type codes (reverse-v3 E75).
inline constexpr std::int32_t kWorkbenchTypeGeneratorA = 0x0f;  // 15 - generates
inline constexpr std::int32_t kWorkbenchTypeGeneratorB = 0x14;  // 20 - generates (+live level)
inline constexpr std::int32_t kWorkbenchTypeStorage = 0x15;     // 21 - stores (fraction /8192)

// The pinned constants.
inline constexpr std::uint16_t kFurnaceFuelFence = 0x64;    // 100 - `cmp r0, 0x64; bge`
inline constexpr std::uint32_t kStorageCapacity = 0x2000;   // 8192 - the fraction divisor

// The u16 charge store (the fffff150 cell semantics).
class ElectricChargeStore {
public:
    std::uint16_t units() const { return units_; }  // availableElectricity: ldrh

    // subtractElectricty: the drain. Returns true when the subtraction
    // happened (stored >= requested); false exits (cmp; bgt @0xb013c0).
    bool drain(std::uint16_t requested) {
        if (units_ < requested) {
            return false;
        }
        units_ = static_cast<std::uint16_t>(units_ - requested);  // sub + strh
        dirty_ = true;                                            // strb r0=1 @0xb013fc
        return true;
    }

    // addToFuel: type 0xf: the add is REJECTED when the store is already at
    // or above the fence (cmp 0x64; bge). Returns true when units were
    // added. The 16-bit domain wraps like `strh`.
    bool addFuelUnits(std::int32_t workbenchType, std::uint16_t amount) {
        if (workbenchType != kWorkbenchTypeGeneratorA) {
            return false;  // out of scope per evidence boundary
        }
        if (units_ >= kFurnaceFuelFence) {
            return false;  // the fence @0xafe0c8
        }
        units_ = static_cast<std::uint16_t>(units_ + amount);
        dirty_ = true;
        return true;
    }

    // energyFraction: type 0x15: stored / 8192 (vcvt.f32.u32; vdiv.f32).
    float storageFraction(std::int32_t workbenchType) const {
        if (workbenchType != kWorkbenchTypeStorage) {
            return 0.0f;
        }
        return static_cast<float>(units_) / static_cast<float>(kStorageCapacity);
    }

    // The pinned predicates.
    static bool generatesElectricity(std::int32_t t) {
        return t == kWorkbenchTypeGeneratorA || t == kWorkbenchTypeGeneratorB;
    }
    static bool isStorageDevice(std::int32_t t) { return t == kWorkbenchTypeStorage; }
    // The 9-compare use-set's pinned members (the enumeration as read).
    static bool usesStoresConductsOrProduces(std::int32_t t) {
        switch (t) {
            case 0x0f:  // 15
            case 0x14:  // 20
            case 0x15:  // 21
            case 0x11:  // 17
            case 0x10:  // 16
            case 0x1b:  // 27
                return true;
            default:
                return false;
        }
    }

    bool dirty() const { return dirty_; }
    void clearDirty() { dirty_ = false; }
    void setUnits(std::uint16_t u) { units_ = u; }

private:
    std::uint16_t units_ = 0;
    bool dirty_ = false;
};

}  // namespace blockheads::recovered
