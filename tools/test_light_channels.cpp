// Contract tests for the recovered light-channel array slice (E28/E29/E31/E42).
// Build (the CI recovered lane runs this loop for opt in 0 2):
//   c++ -std=c++17 -O2 -Wall -Wextra -Werror -ffp-contract=off
//       -Ireconstruction/recovered
//       tools/test_light_channels.cpp
//       reconstruction/recovered/light_channels.cpp -o /tmp/t
//   /tmp/t
// NOTE: keep this comment free of trailing backslashes - GCC -Wcomment treats
// a line-continued // comment as multi-line and CI uses -Werror with g++.
#include "light_channels.h"

#include <cassert>
#include <vector>

using blockheads::recovered::kAllChannelsArm;
using blockheads::recovered::kLightChannelCount;
using blockheads::recovered::LightChannelArray;

static void test_bounds_and_count() {
    assert(kLightChannelCount == 32);
    assert(kAllChannelsArm == -1);
}

static void test_single_channel_marks_in_range() {
    LightChannelArray channels;
    for (int i = 0; i < kLightChannelCount; ++i) {
        assert(!channels.isChanged(i));
    }
    assert(channels.markChanged(0));
    assert(channels.markChanged(31));
    assert(channels.isChanged(0));
    assert(channels.isChanged(31));
    assert(!channels.isChanged(1));
    assert(channels.changedCount() == 2);
    // out-of-range refused (both edges).
    assert(!channels.markChanged(32));
    assert(!channels.markChanged(-2));
    assert(!channels.isChanged(32));
    assert(!channels.isChanged(-1));
}

static void test_all_channels_arm() {
    LightChannelArray channels;
    // the -1 special arm marks every channel (E31 0x8e17dc path).
    assert(channels.markChanged(kAllChannelsArm));
    assert(channels.changedCount() == kLightChannelCount);
}

static void test_send_iteration_order() {
    LightChannelArray channels;
    assert(channels.markChanged(5));
    assert(channels.markChanged(1));
    std::vector<int> emitted;
    channels.forEachChanged([&](int index) { emitted.push_back(index); });
    // ascending channel order (the 0..32 loop).
    assert((emitted == std::vector<int>{1, 5}));
}

static void test_clear_all() {
    LightChannelArray channels;
    channels.markChanged(kAllChannelsArm);
    channels.clearAll();
    assert(channels.changedCount() == 0);
    channels.forEachChanged([&](int) { assert(false); });
}

int main() {
    test_bounds_and_count();
    test_single_channel_marks_in_range();
    test_all_channels_arm();
    test_send_iteration_order();
    test_clear_all();
    return 0;
}
