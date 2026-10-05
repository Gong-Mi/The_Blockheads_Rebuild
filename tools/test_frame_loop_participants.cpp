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
    assert(!isFrameLoopParticipant("World"));      // World is the driver, not a participant
    assert(!isFrameLoopParticipant("DynamicWorld"));
    assert(!isFrameLoopParticipant("GameView"));
    assert(!isFrameLoopParticipant(""));
    assert(!isFrameLoopParticipant("Blockhead "));  // exact match, no prefix nonsense

    std::puts("frame-loop-participants: PASS");
    return 0;
}
