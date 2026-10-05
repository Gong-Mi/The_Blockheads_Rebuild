// Contract test for the recovered blockhead-gender fact: the header must compile and the rule must hold.
//
// The Python test next to it re-derives the whole chain from the binary - cell, offset, writer - but it skips when
// the pinned ELF is absent, which is exactly the environment CI's contracts job has. So this one covers what can be
// checked without the binary: that the model is valid C++ at all (an unreferenced header rots silently - nothing
// included this file before), and that the truth rule keeps the form the original implements.
#include "blockhead_gender.h"

#include <cassert>
#include <cstdio>

using namespace blockheads::recovered::blockhead_gender;

int main() {
    // the constants, as recovered
    static_assert(kOffsetSkinOptions == 728);
    static_assert(kCellSkinOptions == 0x00f3544cU);
    static_assert(kImpIsMale == 0x00c86548U);
    static_assert(kSiteWriteSkinOptions == 0x00c89f2cU);

    // the rule: any NON-ZERO byte is male. The original returns a signed char and callers branch on its truth, so
    // a negative encoding counts; "== 1" would be the reading this project already got wrong once for the
    // DynamicObject flags. These five values are the control - 0 and only 0 is female.
    assert(isMaleFromSkinOptions(0) == false);
    assert(isMaleFromSkinOptions(1) == true);
    assert(isMaleFromSkinOptions(-1) == true);
    assert(isMaleFromSkinOptions(127) == true);
    assert(isMaleFromSkinOptions(-128) == true);

    std::puts("blockhead-gender-model: PASS (constants and the non-zero rule)");
    return 0;
}
