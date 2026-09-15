#include "world_view_contracts.h"
#include <cstring>

namespace blockheads::recovered {
FrameVector2 worldTranslation(const WorldViewContractsState& state) {
    // -[World translation] 0x5536a4: stret, two integer word copies.
    static_assert(sizeof(FrameVector2) == 8);
    FrameVector2 result;
    std::memcpy(&result, &state.accurateTranslation, sizeof(result));
    return result;
}
std::int32_t worldWidthMacro(const WorldViewContractsState& state) {
    // 0x5d9848 load; 0x5d984c dmb ish. Retain a full post-load fence.
    // Portable logical mapping, not a claim of ObjC atomic ABI equivalence.
    const auto value = state.worldWidthMacro.load(std::memory_order_relaxed);
    std::atomic_thread_fence(std::memory_order_seq_cst);
    return value;
}
std::int8_t worldTranslatingToGoal(const WorldViewContractsState& state) {
    return state.translatingToGoal; // 0x5d9c10 ldrsb
}
std::int8_t worldLoadComplete(const WorldViewContractsState& state) {
    return state.loadComplete; // 0x5d9c90 ldrsb
}
std::int8_t worldIsSimulating(const WorldViewContractsState& state) {
    return state.isSimulating; // 0x567864 ldrsb
}
std::int8_t worldTakingPhoto(const WorldViewContractsState& state) {
    // 0x5c4080: [self.uiManager cameraUI]; compare returned object to nil.
    // A nil ObjC receiver returns nil; a nonnil one must execute the dispatch.
    auto* const ui = state.uiManager;
    return ui && ui->cameraUI() != nullptr ? 1 : 0;
}
}
