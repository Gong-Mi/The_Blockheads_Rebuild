#include "net_sync_phases.h"

// Header-only behaviour; this translation unit anchors the compiled unit for
// the net-sync phase family.
namespace blockheads::recovered {
namespace {

static_assert(kNetSlotCount == 65);
static_assert(kNetIDBytes == 8);
static_assert(kNetCreationRecordBytes == 24);
static_assert(kFreeBlockType == 0xe);
static_assert(kRemoteUpdateGateType == 0x3c);
static_assert(NetSyncPhases::kPhaseCount == 4);

}  // namespace
}  // namespace blockheads::recovered
