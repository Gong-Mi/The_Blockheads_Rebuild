// See world_change_queues.h for the evidence record and boundaries.
#include "world_change_queues.h"

#include <algorithm>

namespace blockheads::recovered {

namespace {

// The original dedup loops compare the pair fields directly (E22 0x8df8bc
// window and E23 0x8e1fbc window: two-word compares with a distinct-branch).
bool containsPair(const std::vector<WorldChangePair>& v, const WorldChangePair& p) {
    return std::find(v.begin(), v.end(), p) != v.end();
}

void pushBackUnique(std::vector<WorldChangePair>& v, const WorldChangePair& p) {
    if (!containsPair(v, p)) {
        v.push_back(p);
    }
}

}  // namespace

bool operator==(const WorldChangePair& a, const WorldChangePair& b) {
    return a.x == b.x && a.y == b.y;
}

bool operator!=(const WorldChangePair& a, const WorldChangePair& b) {
    return !(a == b);
}

WorldChangePair macroPairForWorldPos(int x, int y) {
    // E22 0x8dfac8-0x8dfaf0 / E23 0x8e0e80: movw r0, 0x20 + __aeabi_idiv.
    // C++ integer division truncates toward zero, matching __aeabi_idiv.
    WorldChangePair p;
    p.x = x / 32;
    p.y = y / 32;
    return p;
}

std::vector<WorldChangePair>& WorldChangeQueues::worldChangedPositions() {
    return worldChangedPositions_;
}
const std::vector<WorldChangePair>& WorldChangeQueues::worldChangedPositions() const {
    return worldChangedPositions_;
}

std::vector<WorldChangePair>& WorldChangeQueues::waterChangedPositions() {
    return waterChangedPositions_;
}
const std::vector<WorldChangePair>& WorldChangeQueues::waterChangedPositions() const {
    return waterChangedPositions_;
}

std::vector<WorldChangePair>& WorldChangeQueues::reliableMacroQueue() {
    return reliableMacroQueue_;
}
const std::vector<WorldChangePair>& WorldChangeQueues::reliableMacroQueue() const {
    return reliableMacroQueue_;
}

std::vector<WorldChangePair>& WorldChangeQueues::unreliableMacroQueue() {
    return unreliableMacroQueue_;
}
const std::vector<WorldChangePair>& WorldChangeQueues::unreliableMacroQueue() const {
    return unreliableMacroQueue_;
}

std::vector<WorldChangePair>& WorldChangeQueues::thirdMacroQueue() {
    return thirdMacroQueue_;
}
const std::vector<WorldChangePair>& WorldChangeQueues::thirdMacroQueue() const {
    return thirdMacroQueue_;
}

void WorldChangeQueues::worldChangedAtPos(int x, int y, bool sendReliably) {
    // E22 0x8df850-0x8dfab8: the exact-position scan gates ONLY the ffffe5b8
    // push - a pair already present skips the push and jumps directly to the
    // macro section (0x8df988 `bne 0x8dfac8`). The macro routing below therefore
    // runs on every call, with its own dedup at the macro queue.
    const WorldChangePair exact{x, y};
    if (!containsPair(worldChangedPositions_, exact)) {
        worldChangedPositions_.push_back(exact);
    }

    const WorldChangePair macro = macroPairForWorldPos(x, y);
    if (sendReliably) {
        pushBackUnique(reliableMacroQueue_, macro);
    } else {
        pushBackUnique(unreliableMacroQueue_, macro);
    }
}

void WorldChangeQueues::waterChangedAtPos(int x, int y, bool fullBlock) {
    // E23 0x8e0afc: the fullBlock byte gates the exact-position bookkeeping;
    // the macro routing below runs on the same shape as worldChangedAtPos.
    const WorldChangePair exact{x, y};
    if (fullBlock && !containsPair(waterChangedPositions_, exact)) {
        waterChangedPositions_.push_back(exact);
    }
    const WorldChangePair macro = macroPairForWorldPos(x, y);
    pushBackUnique(unreliableMacroQueue_, macro);
}

void WorldChangeQueues::lightChangedAtMacroPos(int macroX, int macroY, bool sendReliably, bool sendAtAll) {
    // E23 0x8e1f18: the input pair is already macro. The reliable route pushes
    // the reliable queue; the non-reliable route performs the 574/57c queue
    // work. sendAtAll additionally leaves the pair in the third queue.
    // Boundary: the observed 574/57c micro-order is not fully established; this
    // module routes conservatively and keeps the third queue separate from the
    // flush.
    const WorldChangePair macro{macroX, macroY};
    if (sendReliably) {
        pushBackUnique(reliableMacroQueue_, macro);
    } else {
        pushBackUnique(unreliableMacroQueue_, macro);
    }
    if (sendAtAll) {
        pushBackUnique(thirdMacroQueue_, macro);
    }
}

void WorldChangeQueues::flush(bool server, const SaveCallback& save) {
    // E21 0x008b49f8: server gate, then pass 1 over the reliable queue with
    // (sendReliably=1, dontSend=0, onlySaveIfClientsNeedIt=1) and pass 2 over
    // the unreliable queue with sendReliably=0. A nonzero save result erases
    // the entry (libc++ erase-on-success); a zero result keeps it.
    if (!server) {
        return;
    }
    auto pass = [&save](std::vector<WorldChangePair>& queue, bool sendReliably) {
        std::vector<WorldChangePair> kept;
        kept.reserve(queue.size());
        for (const WorldChangePair& entry : queue) {
            const int result = save(entry, sendReliably, /*dontSend=*/false,
                                    /*onlySaveIfClientsNeedIt=*/true);
            if (result == 0) {
                kept.push_back(entry);
            }
        }
        queue.swap(kept);
    };
    pass(reliableMacroQueue_, true);
    pass(unreliableMacroQueue_, false);
}

}  // namespace blockheads::recovered
