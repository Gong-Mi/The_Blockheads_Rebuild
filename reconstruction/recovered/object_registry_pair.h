// Recovered contract: the DynamicWorld registry pair (ffffe550 / ffffe554).
//
// Evidence (reverse-v3 level A):
//   - The ivar symbol table (E30 placement.json / E31 load_session.json /
//     E40 save_remote_sim.json) pins the slots:
//       ffffe550 = dynamicObjectsToAdd          (keyed by uniqueID)
//       ffffe554 = dynamicObjectsByWorldPosIndex (keyed by world index)
//   - Registration writers (E26 interaction placer, E30 addRail/addStandard/
//     addPainting, E33 loadDebugChestAtPos:, E31 loadStandardDynamicObjectOf-
//     Type:atPos:): per object the type is read ([obj objectType] = ffe23334),
//     the world index comes from worldIndexAtWorldPos(intpair, World*), and
//     `map<u64, DynamicObject*>::operator[]` inserts into the 12-byte segments
//     of BOTH maps; the ffe232a0 flag-1 call closes the registration.
//   - The lookup faces:
//       npcWithID: (E34 0x008f23f4)     ffffe54c slice __count_unique ->
//                                        operator[](u64 const&) ; miss ->
//                                        the ffffe550 segment.
//       loadStandard (E31 0x008e6250)   ffffe554 segment __count_unique ->
//                                        operator[] -> the ffe234ac gate:
//                                        loaded -> return; else create.
//       freeBlocksExistAtPos: (E39)     ffffe588 registry __count_unique.
//   - The type gate: writers bail for type >= 0x41 (E40 saveDynamicObjects).
//   - The add-flag: ffe232a0 (flag 1) runs after both map writes (E26/E33).
//
// This module models ONLY the closed bookkeeping contract: register (both
// maps + gate), look up by uniqueID (550 face), look up by world index (554
// face), and the "loaded" boolean that the ffe234ac gate evaluates. It does
// not model object construction and does not claim runtime equivalence.
//
// Boundaries (do not promote beyond evidence):
//   - Real maps are per-type 65-segment arrays; here the type is a flat key
//     dimension. The gate behavior (< 0x41 accepted) is preserved; the segment
//     indexing is abstracted away and noted.
//   - The ffe234ac "loaded" flag is modeled as the slot's loaded boolean; its
//     transport (objc message send) is not part of the slice.
//   - uniqueID / worldIndex are u64 keys (E24/E31 `__count_unique(u64)`).
#pragma once

#include <cstdint>
#include <unordered_map>

namespace blockheads::recovered {

struct RegisteredObject {
    int type = 0;
    std::uint64_t uniqueID = 0;
    std::uint64_t worldIndex = 0;
    void* pointer = nullptr;
    bool loaded = false;  // the ffe234ac gate value
};

class ObjectRegistryPair {
public:
    // Registration face: type-gated (>= 0x41 refused), writes BOTH maps.
    // Returns false when the type gate refuses the object.
    bool registerObject(int type, std::uint64_t uniqueID, std::uint64_t worldIndex, void* pointer) {
        if (!passesGate(type)) {
            return false;
        }
        RegisteredObject obj{type, uniqueID, worldIndex, pointer, /*loaded=*/true};
        byUniqueID_[uniqueID] = obj;
        byWorldIndex_[worldIndex] = obj;
        return true;
    }

    // ffffe550 face: keyed by uniqueID.
    const RegisteredObject* lookupByUniqueID(std::uint64_t uniqueID) const {
        const auto it = byUniqueID_.find(uniqueID);
        return it == byUniqueID_.end() ? nullptr : &it->second;
    }

    // ffffe554 face: keyed by world index.
    const RegisteredObject* lookupByWorldIndex(std::uint64_t worldIndex) const {
        const auto it = byWorldIndex_.find(worldIndex);
        return it == byWorldIndex_.end() ? nullptr : &it->second;
    }

    // The ffe234ac gate: an object resolves only when present AND loaded.
    const RegisteredObject* resolvedByWorldIndex(std::uint64_t worldIndex) const {
        const RegisteredObject* obj = lookupByWorldIndex(worldIndex);
        if (obj == nullptr || !obj->loaded) {
            return nullptr;
        }
        return obj;
    }

    // The ffe234ac gate value lives on the object in the original; here the two
    // maps hold copies, so the loaded flag must be kept in sync on both faces.
    void markUnloaded(std::uint64_t uniqueID) {
        const auto it = byUniqueID_.find(uniqueID);
        if (it == byUniqueID_.end()) {
            return;
        }
        it->second.loaded = false;
        const auto wi = byWorldIndex_.find(it->second.worldIndex);
        if (wi != byWorldIndex_.end()) {
            wi->second.loaded = false;
        }
    }

    std::size_t uniqueIDSideCount() const { return byUniqueID_.size(); }
    std::size_t worldIndexSideCount() const { return byWorldIndex_.size(); }

private:
    static constexpr bool passesGate(int type) { return type < 0x41; }

    std::unordered_map<std::uint64_t, RegisteredObject> byUniqueID_;
    std::unordered_map<std::uint64_t, RegisteredObject> byWorldIndex_;
};

}  // namespace blockheads::recovered
