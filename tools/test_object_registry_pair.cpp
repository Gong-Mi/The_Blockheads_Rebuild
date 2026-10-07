// Contract tests for the recovered object-registry pair slice (E26/E30/E31/E33/E40).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_object_registry_pair.cpp
//       reconstruction/recovered/object_registry_pair.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "object_registry_pair.h"

#include <cassert>

using blockheads::recovered::ObjectRegistryPair;
using blockheads::recovered::RegisteredObject;

static void test_register_writes_both_maps() {
    ObjectRegistryPair reg;
    int chest = 0;
    assert(reg.registerObject(45, /*uniqueID=*/0x1111, /*worldIndex=*/0x2222, &chest));
    assert(reg.uniqueIDSideCount() == 1);      // ffffe550 face
    assert(reg.worldIndexSideCount() == 1);    // ffffe554 face
    const RegisteredObject* byID = reg.lookupByUniqueID(0x1111);
    assert(byID != nullptr);
    assert(byID->pointer == &chest);
    assert(byID->type == 45);
    const RegisteredObject* byWI = reg.lookupByWorldIndex(0x2222);
    assert(byWI != nullptr);
    assert(byWI->uniqueID == 0x1111);
}

static void test_type_gate_refuses() {
    ObjectRegistryPair reg;
    int obj = 0;
    // E40 saveDynamicObjects / the batch family: type >= 0x41 is refused.
    assert(!reg.registerObject(0x41, 1, 1, &obj));
    assert(!reg.registerObject(0x67, 2, 2, &obj));
    assert(reg.uniqueIDSideCount() == 0);
    assert(reg.worldIndexSideCount() == 0);
    assert(reg.registerObject(0x40, 3, 3, &obj));
    assert(reg.uniqueIDSideCount() == 1);
}

static void test_gate_and_unloaded() {
    ObjectRegistryPair reg;
    int boat = 0;
    assert(reg.registerObject(0x1e, 7, 9, &boat));
    // ffe234ac: an object resolves only while loaded.
    assert(reg.resolvedByWorldIndex(9) != nullptr);
    reg.markUnloaded(7);
    assert(reg.resolvedByWorldIndex(9) == nullptr);
    // The raw faces still see the entry (the maps are not erased by the gate).
    assert(reg.lookupByWorldIndex(9) != nullptr);
    assert(reg.lookupByUniqueID(7) != nullptr);
}

static void test_missing_keys_return_null() {
    ObjectRegistryPair reg;
    assert(reg.lookupByUniqueID(123) == nullptr);
    assert(reg.lookupByWorldIndex(123) == nullptr);
    assert(reg.resolvedByWorldIndex(123) == nullptr);
}

static void test_reregistration_overwrites() {
    ObjectRegistryPair reg;
    int first = 0;
    int second = 0;
    assert(reg.registerObject(16, 5, 6, &first));
    assert(reg.registerObject(17, 5, 6, &second));
    const RegisteredObject* byID = reg.lookupByUniqueID(5);
    assert(byID != nullptr && byID->pointer == &second && byID->type == 17);
    // both sides stay one entry (operator[] overwrite semantics).
    assert(reg.uniqueIDSideCount() == 1);
    assert(reg.worldIndexSideCount() == 1);
}

int main() {
    test_register_writes_both_maps();
    test_type_gate_refuses();
    test_gate_and_unloaded();
    test_missing_keys_return_null();
    test_reregistration_overwrites();
    return 0;
}
