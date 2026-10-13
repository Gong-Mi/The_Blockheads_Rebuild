// Recovered contract: the DynamicWorld light-channel array (ffffe56c).
//
// Evidence (reverse-v3 level A):
//   - Slot: ffffe56c is the per-light-channel structure array.
//     .cxx_destruct (E29 reload_tail.json) runs its destructor as a
//     0x180/12 loop -> **32 channels** of 12-byte records; E28's
//     sendLightblocksToClients (0x008b1dd4) uses the `cmp 0x20` bound over
//     the same family (32 = 0x20).
//   - Writer: -[DynamicWorld exploreLightChangedAtMacroPos:
//     clientLightBlockIndex:] (E31 0x008e17ac) - the channel == -1 special
//     arm (ffe23404 with 0) vs the per-channel 12-byte record writes
//     (`movw r1, 0xc; mul` striding @0x8e182c-0x8e1860; the touched/dedup
//     byte stored at sp+0x3f then committed on the change path
//     @0x8e19a8).
//   - Consumer: sendLightblocksToClients walks the 32 channels and fills the
//     outgoing light queue (E28 0x008b1dd4).
//   - The 2-arg lightChangedAtMacroPos:sendReliably: forwarder (E42
//     0x008e1b68) calls ffe23580 - the queue feed itself lives in E23's
//     world_change_queues slice.
//
// This module models ONLY the channel bookkeeping: the 32-slot array, the
// per-channel changed flag, the -1 special arm and the queue-fill iteration
// contract.
//
// Boundaries (do not promote beyond evidence):
//   - The 12-byte record's remaining fields are opaque; only the
//     changed/touched byte participates in this contract.
//   - The +1 channel bound (0x20) is the send iteration count; channel
//     indices are 0..31.
//   - The ffe23404/-1 arm is modelled as "mark all" vs "mark one" (the
//     observed branch shape at 0x8e17dc).
#pragma once

#include <cstdint>
#include <functional>

namespace blockheads::recovered {

inline constexpr int kLightChannelCount = 32;      // 0x180 / 12 (E29) == cmp 0x20 (E28)
inline constexpr std::int64_t kChannelRecordStride = 12;  // the 0xc mul stride (E31)
inline constexpr std::int64_t kLightForwardCell = 0x00ffe23580;  // the 2-arg forwarder (E42)
inline constexpr int kAllChannelsArm = -1;         // the -1 special arm (E31)

struct LightChannel {
    bool changed = false;
};

class LightChannelArray {
public:
    // exploreLightChangedAtMacroPos:clientLightBlockIndex: (E31) - the -1 arm
    // marks every channel (the ffe23404-with-0 path), otherwise one channel.
    // Out-of-range indices are refused.
    bool markChanged(int channelIndex) {
        if (channelIndex == kAllChannelsArm) {
            for (LightChannel& channel : channels_) {
                channel.changed = true;
            }
            return true;
        }
        if (channelIndex < 0 || channelIndex >= kLightChannelCount) {
            return false;
        }
        channels_[channelIndex].changed = true;
        return true;
    }

    bool isChanged(int channelIndex) const {
        if (channelIndex < 0 || channelIndex >= kLightChannelCount) {
            return false;
        }
        return channels_[channelIndex].changed;
    }

    // sendLightblocksToClients (E28): iterate the 32 channels; the callback
    // receives each changed channel index (the queue fill is caller-side).
    void forEachChanged(const std::function<void(int)>& emit) const {
        for (int i = 0; i < kLightChannelCount; ++i) {
            if (channels_[i].changed) {
                emit(i);
            }
        }
    }

    int changedCount() const {
        int n = 0;
        for (const LightChannel& channel : channels_) {
            if (channel.changed) {
                ++n;
            }
        }
        return n;
    }

    void clearAll() {
        for (LightChannel& channel : channels_) {
            channel.changed = false;
        }
    }

private:
    LightChannel channels_[kLightChannelCount];
};

}  // namespace blockheads::recovered
