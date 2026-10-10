// Recovered contract: the DynamicWorld world-change queue family.
//
// Evidence (reverse-v3 level A):
//   - E22 world_save.json / WORLD_SAVE.md:
//     -[DynamicWorld worldChangedAtPos:sendReliably:] (imp 0x008df7a4):
//     exact-position dedup vector ffffe5b8; macro pair = (pos / 32) via
//     __aeabi_idiv 0x20 + makeIntpair; sendReliably routes the macro pair into
//     the ffffe570 queue (reliable) with the ffffe574 queue handling the
//     non-reliable side; erase/push both via libc++ vector paths.
//   - E23 notes / this module's cpp: lightChangedAtMacroPos:sendReliably:sendAtAll:
//     (0x008e1f18) consumes an ALREADY-macro pair and exercises the 570/574/57c
//     queue set; worldChangedAtPos:sendReliably: feeds it. waterChangedAtPos:fullBlock:
//     (0x008e0ad0) owns a separate full-block position vector (ffffe5c0) and then
//     converts to the macro queues the same /32 + makeIntpair way.
//   - E21 net_sync.json / NET_SYNC.md:
//     -[DynamicWorld saveAndSendOnlyBlocksThatNeedToBeSent] (0x008b49f8) is the
//     consumer: server-gated; pass 1 over the ffffe570 queue calls
//     savePhysicalBlockForMacroTile:sendReliably:1 dontSend:0
//     onlySaveIfClientsNeedIt:1 and erases entries whose save returned nonzero;
//     pass 2 runs the same protocol over the ffffe574 queue with
//     sendReliably:0.
//
// This module models ONLY the queue bookkeeping and the flush order/erase
// contract. The world/tile lookup and the actual physical-block save are
// callbacks (int-returning), not part of this slice.
//
// Boundaries (do not promote beyond evidence):
//   - The exact micro-order of the dual dedup vectors around the sendReliably
//     gate is recorded as observed (E22/E23); this module implements the
//     documented routing (reliable -> ffffe570, otherwise -> ffffe574).
//   - ffffe57c is touched by lightChangedAtMacroPos but its consumer role is not
//     yet established; it is exposed as `thirdMacroQueue()` and left to the
//     caller. Do not wire it into the flush.
//   - `makeIntpair` packs two int16 fields (E16/E23 route evidence); values are
//     stored as int pairs here.
//   - Division uses ARM __aeabi_idiv semantics: truncation toward zero.
#pragma once

#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

namespace blockheads::recovered {

struct WorldChangePair {
    int x = 0;
    int y = 0;
};

bool operator==(const WorldChangePair& a, const WorldChangePair& b);
bool operator!=(const WorldChangePair& a, const WorldChangePair& b);

// The macro-pair conversion observed in E22/E23: (x / 32, y / 32) with
// truncation toward zero (__aeabi_idiv).
WorldChangePair macroPairForWorldPos(int x, int y);

class WorldChangeQueues {
public:
    // ffffe5b8: every exact world position passed to worldChangedAtPos.
    std::vector<WorldChangePair>& worldChangedPositions();
    const std::vector<WorldChangePair>& worldChangedPositions() const;

    // ffffe5c0: full-block water positions (waterChangedAtPos:fullBlock:).
    std::vector<WorldChangePair>& waterChangedPositions();
    const std::vector<WorldChangePair>& waterChangedPositions() const;

    // ffffe570: the reliable macro queue consumed by flush pass 1.
    std::vector<WorldChangePair>& reliableMacroQueue();
    const std::vector<WorldChangePair>& reliableMacroQueue() const;

    // ffffe574: the non-reliable macro queue consumed by flush pass 2.
    std::vector<WorldChangePair>& unreliableMacroQueue();
    const std::vector<WorldChangePair>& unreliableMacroQueue() const;

    // ffffe57c: touched by lightChangedAtMacroPos; consumer role unestablished.
    std::vector<WorldChangePair>& thirdMacroQueue();
    const std::vector<WorldChangePair>& thirdMacroQueue() const;

    // -[DynamicWorld worldChangedAtPos:sendReliably:] (E22)
    // Dedups the exact pair first; only a NEW exact position is recorded and
    // only then is the macro pair routed (sendReliably -> reliable queue,
    // otherwise -> unreliable queue, each deduped before push).
    void worldChangedAtPos(int x, int y, bool sendReliably);

    // -[DynamicWorld waterChangedAtPos:fullBlock:] (E23), queue part only.
    // fullBlock gates the exact-position/water bookkeeping; the macro routing
    // then follows the same /32 + makeIntpair + (reliable?570:574) shape.
    void waterChangedAtPos(int x, int y, bool fullBlock);

    // -[DynamicWorld lightChangedAtMacroPos:sendReliably:sendAtAll:] (E23),
    // queue part only. Input is ALREADY a macro pair. sendReliably routes into
    // the reliable queue; the non-reliable path exercises the 574/57c queues.
    // The exact 574/57c micro-order is an open boundary (see header note).
    void lightChangedAtMacroPos(int macroX, int macroY, bool sendReliably, bool sendAtAll);

    // The flush contract of -[DynamicWorld saveAndSendOnlyBlocksThatNeedToBeSent]
    // (E21). `save` receives (macroPair, sendReliably, dontSend,
    // onlySaveIfClientsNeedIt) and returns the original save result byte;
    // nonzero erases the entry from that queue. Pass 1 always uses
    // (sendReliably=1, dontSend=0, onlySaveIfClientsNeedIt=1); pass 2 uses
    // (sendReliably=0, dontSend=0, onlySaveIfClientsNeedIt=1) per the observed
    // constant values. Entries are visited in queue order; a consumer that
    // returns zero keeps its entry (retried on the next flush).
    using SaveCallback = std::function<int(const WorldChangePair& macroPair,
                                           bool sendReliably,
                                           bool dontSend,
                                           bool onlySaveIfClientsNeedIt)>;
    void flush(bool server, const SaveCallback& save);

private:
    std::vector<WorldChangePair> worldChangedPositions_;
    std::vector<WorldChangePair> waterChangedPositions_;
    std::vector<WorldChangePair> reliableMacroQueue_;
    std::vector<WorldChangePair> unreliableMacroQueue_;
    std::vector<WorldChangePair> thirdMacroQueue_;
};

}  // namespace blockheads::recovered
