// Contract test for the recovered audio wiring model.
#include "audio_wiring_model.h"

#include <algorithm>
#include <cassert>
#include <cstdio>
#include <string_view>

using namespace blockheads::recovered::audio;

static std::size_t countFor(std::string_view method) {
    return static_cast<std::size_t>(std::count_if(
        kAudioWiring.begin(), kAudioWiring.end(),
        [method](const Wiring& w) { return w.method == method; }));
}

int main() {
    assert(kAudioWiring.size() == 275);
    assert(kNotYetReferenced.size() == 77);

    // the largest group is anchored from both sides
    assert(countFor(kLargestLoader) == kLargestLoaderSoundCount);

    // specific wirings, so a generator that counts correctly but maps wrongly cannot pass
    const auto has = [](std::string_view sound) {
        return std::any_of(kAudioWiring.begin(), kAudioWiring.end(),
                           [sound](const Wiring& w) { return w.sound == sound; });
    };
    assert(has("blockheadDie.wav"));
    // axe.wav is one of the two shipped names the original never references through a __cfstring, so it
    // has no method attribution and CANNOT appear in a wiring table. Asserting the opposite was a fact
    // error that stayed invisible while this build had asserts compiled out.
    assert(!has("axe.wav"));

    // every entry names a method that looks like "Class -[selector]"
    for (const Wiring& w : kAudioWiring) {
        assert(!w.sound.empty());
        assert(w.method.find(" -[") != std::string_view::npos);
    }
    for (std::string_view s : kNotYetReferenced) assert(!s.empty());

    std::puts("audio-wiring-model: PASS");
    return 0;
}
