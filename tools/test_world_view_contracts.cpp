#include "world_view_contracts.h"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
using namespace blockheads::recovered;
static void check(bool b, const char* message) {
    if (!b) { std::fprintf(stderr, "FAIL: %s\n", message); std::exit(1); }
}
struct UI final : WorldViewUI {
    int calls{};
    void* result{};
    WorldViewContractsState* state{};
    void* cameraUI() override {
        ++calls;
        if (state) state->loadComplete = -7;
        return result;
    }
};
int main() {
    WorldViewContractsState s;
    // Raw copy must not normalize NaN payloads, signed zero, or infinities.
    const std::array<std::uint32_t, 6> bits{0, 0x80000000, 0x7fc12345,
                                         0x7f812345, 0x7f800000, 0xff800000};
    for (auto x : bits) for (auto y : bits) {
        std::uint32_t input[]{x,y}, output[2]{};
        std::memcpy(&s.accurateTranslation, input, sizeof(input));
        const auto t = worldTranslation(s);
        std::memcpy(output, &t, sizeof(output));
        check(output[0] == x && output[1] == y, "translation raw lane copy");
    }
    for (int v = -128; v <= 127; ++v) {
        s.translatingToGoal = s.loadComplete = s.isSimulating = static_cast<std::int8_t>(v);
        check(worldTranslatingToGoal(s) == v, "translatingToGoal signed byte");
        check(worldLoadComplete(s) == v, "loadComplete signed byte");
        check(worldIsSimulating(s) == v, "isSimulating signed byte");
    }
    for (auto v : {0, 1, -1, std::numeric_limits<std::int32_t>::min(),
                  std::numeric_limits<std::int32_t>::max()}) {
        s.worldWidthMacro.store(v, std::memory_order_relaxed);
        check(worldWidthMacro(s) == v, "width unmodified int32");
    }
    check(worldTakingPhoto(s) == 0, "nil uiManager returns false");
    UI ui; s.uiManager = &ui; ui.state = &s;
    check(worldTakingPhoto(s) == 0 && ui.calls == 1, "cameraUI nil result");
    check(s.loadComplete == -7, "dispatch side effect retained");
    ui.result = &s;
    check(worldTakingPhoto(s) == 1 && ui.calls == 2, "cameraUI object result");
    ui.result = nullptr;
    check(worldTakingPhoto(s) == 0 && ui.calls == 3, "dispatch re-evaluated, no cache");
    std::puts("PASS world_view_contracts: six complete methods; bit-copy, signed bytes, width, cameraUI dispatch");
}
