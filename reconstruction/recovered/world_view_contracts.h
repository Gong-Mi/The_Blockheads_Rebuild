#pragma once
#include "gameview_update.h"
#include <atomic>
#include <cstdint>

namespace blockheads::recovered {
// Logical recovered fields, NOT an Objective-C layout or a ready FrameWorld adapter.
class WorldViewUI {
public:
    virtual ~WorldViewUI() = default;
    // Actual selector cameraUI; returned object is borrowed, never released here.
    virtual void* cameraUI() = 0;
};
struct WorldViewContractsState {
    FrameVector2 accurateTranslation{};
    std::atomic<std::int32_t> worldWidthMacro{0};
    std::int8_t translatingToGoal{}, loadComplete{}, isSimulating{};
    WorldViewUI* uiManager{};
};
FrameVector2 worldTranslation(const WorldViewContractsState& state);
std::int32_t worldWidthMacro(const WorldViewContractsState& state);
// Preserve ObjC signed-char return values, not normalized C++ bools.
std::int8_t worldTranslatingToGoal(const WorldViewContractsState& state);
std::int8_t worldLoadComplete(const WorldViewContractsState& state);
std::int8_t worldIsSimulating(const WorldViewContractsState& state);
std::int8_t worldTakingPhoto(const WorldViewContractsState& state);
// setTranslation: deliberately absent: wrapping, second-vector quantization,
// and outgoing Objective-C effects remain unrecovered. No assignment fallback.
}
