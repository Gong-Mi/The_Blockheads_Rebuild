// Contract test for the recovered InteractionTestResult record.
#include "interaction_test_result.h"

#include <cassert>
#include <cstddef>
#include <cstdio>

using namespace blockheads::recovered;

int main() {
    assert(sizeof(InteractionTestResult) == 12);

    // the layout the encoding implies
    assert(offsetof(InteractionTestResult, f0) == 0);
    assert(offsetof(InteractionTestResult, f1) == 4);
    assert(offsetof(InteractionTestResult, f2) == 8);
    assert(offsetof(InteractionTestResult, f3) == 10);

    // widths, including the two-byte fields that tail the record
    assert(sizeof(InteractionTestResult::f0) == 4);
    assert(sizeof(InteractionTestResult::f1) == 4);
    assert(sizeof(InteractionTestResult::f2) == 2);
    assert(sizeof(InteractionTestResult::f3) == 2);
    // the two narrow fields share one aligned 4-byte slot, which is why they sit at 8 and 10
    assert(offsetof(InteractionTestResult, f2) + 2 == offsetof(InteractionTestResult, f3));
    assert(offsetof(InteractionTestResult, f3) + 2 == sizeof(InteractionTestResult));

    // the host facts
    assert(kInteractionTestResultActionIvarOffset == 52);
    assert(kInteractionTestResultActionIvarCell == 0x00f33648U);

    std::puts("interaction-test-result: PASS");
    return 0;
}
