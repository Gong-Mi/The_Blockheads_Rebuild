// Recovered contract: the DynamicWorld typed-accessor triplet dispatcher
// (the E36-E39/XAtPos/addX/removeX family).
//
// Evidence (reverse-v3 level A; every cell below is pinned by its batch
// listing, and every type code is an immediate from the same batch):
//   The family shape, identical across E36 (torch/egg/painting/fire), E37
//   (ladder/column/stairs/elevatorShaft), E38 (window/door), E39 (workbench)
//   and E43 (elevatorMotor/rail):
//     - lookup:  `XAtPos:` = the type immediate + the ffe235f0 dispatch call
//                (doors/workbenches add the pos-then-y-1 two-probe pattern,
//                E38/E39);
//     - add:     `addX...` = the type immediate packed into the ffe23624
//                call frame (ofType/saveDict/placedByClient);
//     - remove:  `removeXAtPos:` = the ffe23600 gate + a PER-TYPE remove
//                cell - the pinned assignment table:
//                    torch   -> ffe23564   (E36 0x008e8fe8)
//                    egg     -> ffe23618   (E36 0x008eaa28)
//                    painting-> ffe23558   (E36 0x008eb00c)
//                    ladder  -> ffe23628   (E37 0x008eb57c)
//                    column  -> ffe2355c   (E37 0x008eb744)
//                    stairs  -> ffe23560   (E37 0x008eb90c)
//                    shaft   -> ffe2362c   (E37 0x008ebc9c)
//                    window  -> ffe2364c   (E38 0x008ed4b8)
//                    motor   -> ffe23640   (E43 0x008ecdf0; shared with E23)
//                    rail    -> ffe23648   (E43 0x008ed2c4; behind ffe235e0)
//   Door (0x14) has no single remove leg recovered as a cell at the same
//   shape (its removal rides the door state family ffe23650/58/6c and
//   ffe233e0/ffe23690 - E38/E39) and is deliberately NOT in the table.
//
// This module models ONLY the dispatcher contract: the type -> cell table,
// and a TripletStore that exercises lookup/add/remove against modelled
// objects with the per-type cells as callbacks identifiers. Object
// construction, the world index resolution and the actual render entities
// are out of scope.
//
// Boundaries (do not promote beyond evidence):
//   - Cell identities are opaque handles (the original dispatch slots); the
//     numbers are the pinned slot values, used here as stable identities.
//   - The pos-then-y-1 two-probe of doors/workbenches is modelled as a flag
//     on the entry with the probe ORDER documented, not re-derived.
//   - The add frame's payload semantics (ofType vs saveDict vs placedByClient)
//     are not resolved field-by-field; the store records the arguments.
#pragma once

#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

namespace blockheads::recovered {

// Dispatch-slot identities (the pinned cell values).
inline constexpr std::int64_t kLookupCell = 0x00ffe235f0;
inline constexpr std::int64_t kAddCell = 0x00ffe23624;
inline constexpr std::int64_t kRemoveGateCell = 0x00ffe23600;

struct AccessorTriplet {
    int type = 0;                    // the pinned type immediate
    std::int64_t lookupCell = kLookupCell;
    std::int64_t addCell = kAddCell;
    std::int64_t removeCell = 0;     // per-type (the table below)
    bool probesPosThenYMinus1 = false;  // doors/workbenches (E38/E39)
};

// The pinned per-type remove cells (E36-E43).
inline constexpr AccessorTriplet kTriplets[] = {
    {0x11, kLookupCell, kAddCell, 0x00ffe23564, false},  // torch (E36)
    {0x1e, kLookupCell, kAddCell, 0x00ffe23618, false},  // egg (E36)
    {0x34, kLookupCell, kAddCell, 0x00ffe23558, false},  // painting (E36)
    {0x13, kLookupCell, kAddCell, 0x00ffe23628, false},  // ladder (E37)
    {0x35, kLookupCell, kAddCell, 0x00ffe2355c, false},  // column (E37)
    {0x36, kLookupCell, kAddCell, 0x00ffe23560, false},  // stairs (E37)
    {0x38, kLookupCell, kAddCell, 0x00ffe2362c, false},  // elevator shaft (E37)
    {0x1f, kLookupCell, kAddCell, 0x00ffe2364c, false},  // window (E38)
    {0x37, kLookupCell, kAddCell, 0x00ffe23640, false},  // elevator motor (E43)
    {0x28, kLookupCell, kAddCell, 0x00ffe23648, false},  // rail (E43, behind ffe235e0)
    {0x14, kLookupCell, kAddCell, 0, true},              // door (E38) - no cell remove leg
    {0x2d, kLookupCell, kAddCell, 0, true},              // workbench (E39) - ffe233e0/ffe23690 removal
};

constexpr const AccessorTriplet* tripletForType(int type) {
    for (const AccessorTriplet& t : kTriplets) {
        if (t.type == type) {
            return &t;
        }
    }
    return nullptr;
}

struct RecoveredObject {
    int type = 0;
    int x = 0;
    int y = 0;
};

class TripletStore {
public:
    // XAtPos: dispatch - with the door/workbench pos-then-y-1 probe order.
    const RecoveredObject* lookup(int type, int x, int y) const {
        if (const RecoveredObject* hit = find(type, x, y)) {
            return hit;
        }
        const AccessorTriplet* t = tripletForType(type);
        if (t != nullptr && t->probesPosThenYMinus1) {
            return find(type, x, y - 1);
        }
        return nullptr;
    }

    // addX...: the type immediate enters the add frame; the object is stored.
    const RecoveredObject& add(int type, int x, int y) {
        objects_.push_back(RecoveredObject{type, x, y});
        return objects_.back();
    }

    // removeXAtPos:: the ffe23600 gate + the per-type remove cell.
    // Returns the remove cell executed, or nullopt when nothing matched.
    std::optional<std::int64_t> remove(int type, int x, int y) {
        for (auto it = objects_.begin(); it != objects_.end(); ++it) {
            if (it->type == type && it->x == x && it->y == y) {
                const AccessorTriplet* t = tripletForType(type);
                objects_.erase(it);
                return t != nullptr ? std::optional<std::int64_t>(t->removeCell) : std::nullopt;
            }
        }
        return std::nullopt;
    }

    std::size_t size() const { return objects_.size(); }

private:
    const RecoveredObject* find(int type, int x, int y) const {
        for (const RecoveredObject& o : objects_) {
            if (o.type == type && o.x == x && o.y == y) {
                return &o;
            }
        }
        return nullptr;
    }

    std::vector<RecoveredObject> objects_;
};

}  // namespace blockheads::recovered
