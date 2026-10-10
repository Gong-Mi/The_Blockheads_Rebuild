// Host test for the replacement-side consumer of the generated load-time sound list.
//
// What is worth pinning: that the generated header is actually consumed (so it is not dead data),
// that registration is idempotent, and that the pending-wiring count matches the artifact's 6/26 split.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "sound_preload_registry.h"
#include <cassert>
#include <cstring>
#include <iostream>

using blockheads::replacement::SoundPreloadRegistry;

int main() {
    SoundPreloadRegistry reg;
    assert(!reg.registered() && reg.size() == 0 && "a fresh registry holds nothing");

    const std::size_t added = reg.registerLoadTimeSounds();
    assert(added == 32 && "the generated list has 32 load-time names");
    assert(reg.registered() && reg.size() == 32);
    assert(reg.registerLoadTimeSounds() == 0 && "registration is idempotent");
    assert(reg.size() == 32 && "and must not duplicate rows");

    assert(reg.pendingWiring() == 26 && "26 of the 32 are still unreferenced by the replacement");
    assert(reg.size() - reg.pendingWiring() == 6);

    // every row carries a name and a sha256; the generator refuses to emit otherwise
    for (const auto& e : reg.entries()) {
        assert(!e.name.empty());
        assert(e.sha256.size() == 64);
        assert(std::strstr(e.name.c_str(), ".wav") != nullptr);
    }

    const auto* yak = reg.find("yak2.wav");
    assert(yak && "a known load-time name must be findable");
    assert(yak->sha256.rfind("6944b23600", 0) == 0 && "and carry the asset's own hash");
    assert(reg.find("notASound.wav") == nullptr);

    // the two names the original names but never as an ObjC literal are NOT in this list:
    // this list is World -[incrementalLoad] only, and mixing the classes would blur that
    assert(reg.find("axe.wav") == nullptr && reg.find("bird1.wav") == nullptr);

    std::cout << "sound-preload-registry: PASS (" << reg.size() << " registered, "
              << reg.pendingWiring() << " pending wiring, idempotent)\n";
    return 0;
}
