// Contract tests for the recovered remote-receive bucket arrays (E32/E40).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_bucket_arrays.cpp
//       reconstruction/recovered/bucket_arrays.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "bucket_arrays.h"

#include <cassert>

using blockheads::recovered::bucketIndexAllowed;
using blockheads::recovered::kObjectTypeGate;
using blockheads::recovered::RemoteReceiveArrays;
using blockheads::recovered::remoteCreateSkipsType;
using blockheads::recovered::remoteUpdateTakesType;
using blockheads::recovered::SlotArray;

static void test_gates() {
    assert(kObjectTypeGate == 0x41);
    // bucket indices: [0, 0x41).
    assert(bucketIndexAllowed(0));
    assert(bucketIndexAllowed(0x40));
    assert(!bucketIndexAllowed(0x41));
    assert(!bucketIndexAllowed(-1));
    // remoteCreate skips 0xe (FreeBlock); remoteUpdate takes 0x3c.
    assert(remoteCreateSkipsType(0xe));
    assert(!remoteCreateSkipsType(0xd));
    assert(remoteUpdateTakesType(0x3c));
    assert(!remoteUpdateTakesType(0x3b));
}

static void test_lazy_create_on_null() {
    SlotArray array(0xABCD);
    // first access creates; the slot is null before.
    assert(array.peek(5) == nullptr);
    auto* bucket = array.bucketFor(5);
    assert(bucket != nullptr);
    assert(bucket->tag == 0xABCD);
    // second access returns the same bucket (no re-create).
    auto* again = array.bucketFor(5);
    assert(again == bucket);
    // peek now sees it.
    assert(array.peek(5) == bucket);
    // different index: its own slot, lazily created.
    assert(array.peek(6) == nullptr);
    auto* other = array.bucketFor(6);
    assert(other != nullptr && other != bucket);
}

static void test_gate_refusals() {
    SlotArray array(1);
    assert(array.bucketFor(0x41) == nullptr);
    assert(array.bucketFor(-1) == nullptr);
    assert(array.peek(0x41) == nullptr);
    // 0x40 is the last valid index.
    assert(array.bucketFor(0x40) != nullptr);
}

static void test_the_two_arrays_are_independent() {
    RemoteReceiveArrays arrays;
    auto* cd = arrays.creationDataArray().bucketFor(3);
    auto* rc = arrays.remoteCreateArray().bucketFor(3);
    assert(cd != nullptr && rc != nullptr);
    assert(cd != rc);
    // each array carries its own create tag (the ffe2aeb0 / ffe2aeb4 classes).
    assert(cd->tag == 0x00ffe2aeb0);
    assert(rc->tag == 0x00ffe2aeb4);
    // creating in one array does not populate the other.
    assert(arrays.creationDataArray().peek(4) == nullptr);
    assert(arrays.remoteCreateArray().peek(4) == nullptr);
}

int main() {
    test_gates();
    test_lazy_create_on_null();
    test_gate_refusals();
    test_the_two_arrays_are_independent();
    return 0;
}
