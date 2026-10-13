// Replacement-side consumer of the GENERATED load-time sound list.
//
// Deliberately NOT part of reconstruction/recovered/: everything there mirrors the original's own
// structure, and the original's MJSoundManager does not track a name list this way. Inventing state
// inside a recovered class would create exactly the "two sources of truth" problem this project
// avoids. So this lives on the replacement side and is honest about what it is:
//
//   * it registers which of the original's load-time names the replacement knows about,
//   * it does NOT play anything, claim playback order, or touch an audio backend.
//
// The list itself is generated (reconstruction/recovered/sound_preload_list.h) with a --check gate,
// so this file never hard-codes a name.
#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "sound_preload_list.h"

namespace blockheads::replacement {

struct PreloadRegistration {
    std::string name;
    std::string sha256;   // empty when the generator refused to emit a row without one
    bool already_wired;   // true when the replacement already referenced the name before this
};

class SoundPreloadRegistry {
public:
    // Registers the original's load-time names exactly once; returns how many were added.
    std::size_t registerLoadTimeSounds() {
        if (registered_) return 0;
        for (int i = 0; i < blockheads::recovered::kOriginalLoadTimeSoundCount; ++i) {
            const auto& s = blockheads::recovered::kOriginalLoadTimeSounds[i];
            if (!s.name) continue;
            entries_.push_back(PreloadRegistration{
                s.name, s.sha256 ? std::string(s.sha256) : std::string(), s.already_wired});
        }
        registered_ = true;
        return entries_.size();
    }

    bool registered() const { return registered_; }
    std::size_t size() const { return entries_.size(); }
    const std::vector<PreloadRegistration>& entries() const { return entries_; }

    // A name is "pending wiring" when the original names it but the replacement did not reference it.
    std::size_t pendingWiring() const {
        std::size_t n = 0;
        for (const auto& e : entries_) if (!e.already_wired) ++n;
        return n;
    }

    const PreloadRegistration* find(const std::string& name) const {
        for (const auto& e : entries_) if (e.name == name) return &e;
        return nullptr;
    }

private:
    std::vector<PreloadRegistration> entries_;
    bool registered_{};
};

}  // namespace blockheads::replacement
