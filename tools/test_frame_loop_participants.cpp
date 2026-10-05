// Contract test for the recovered frame-loop participant list.
#include "frame_loop_participants.h"

#include <cassert>
#include <cstdio>

using namespace blockheads::recovered;

int main() {
    assert(kFrameLoopParticipants.size() == 52);
    assert(kFrameLoopSignature == "v20@0:4f8f12c16");
    assert(kFrameLoopSelector == "update:accurateDT:isSimulation:");

    // membership lookups, including the two ends of the alphabet and a middle one
    for (const char* name : {"Blockhead", "Chest", "NPC", "Tree"}) {
        assert(isFrameLoopParticipant(name));
    }
    // DynamicWorld IS a participant: it implements the protocol itself (this is the method carrying the
    // x20 divisor) AND drives the loop over its children. The first version of this test asserted the
    // opposite, which is a fact error the Debug CI build caught because it runs the asserts.
    assert(isFrameLoopParticipant("DynamicWorld"));
    // World and GameView drive the loop without implementing it - their update methods take a different
    // selector (update:accurateDT:pinchScale:dragInProgress: and update:accurateDT: respectively)
    assert(!isFrameLoopParticipant("World"));
    assert(!isFrameLoopParticipant("GameView"));
    assert(!isFrameLoopParticipant(""));
    assert(!isFrameLoopParticipant("Blockhead "));  // exact match, no prefix nonsense

    std::puts("frame-loop-participants: PASS");
    return 0;
}
