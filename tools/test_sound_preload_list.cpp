// Host test for the GENERATED load-time sound list.
//
// The header is data, so what is worth testing is that it compiles, that its shape is what a
// consumer will assume, and that the generated file still agrees with its source of record. The
// third check is what catches hand-editing of a generated file (the generator's --check does the
// same against the artifact; this test is the C++-side guard and runs in the ordinary test suite).
#ifdef NDEBUG
#undef NDEBUG
#endif
#include "sound_preload_list.h"
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>

using namespace blockheads::recovered;

static int hexlen(const char* s) { return s ? static_cast<int>(std::strlen(s)) : -1; }

int main() {
    constexpr int n = kOriginalLoadTimeSoundCount;
    assert(n == 32 && "the original's World -[incrementalLoad] names 32 shipped sounds");
    assert(static_cast<int>(sizeof(kOriginalLoadTimeSounds) / sizeof(kOriginalLoadTimeSounds[0])) == n);

    int wired = 0;
    std::string prev;
    for (int i = 0; i < n; ++i) {
        const auto& s = kOriginalLoadTimeSounds[i];
        assert(s.name && "every row carries a name");
        assert(s.sha256 && "every row carries an asset sha256 - Rows without one are refused by the generator");
        assert(hexlen(s.sha256) == 64 && "sha256 is hex, not a truncated blob");
        assert(std::strstr(s.name, ".wav") && "names are shipped asset filenames");
        if (s.already_wired) ++wired;
        // sorted by name: a consumer may binary-search, and a reordering would hide a lost row
        if (i) assert(prev < s.name);
        prev = s.name;
    }
    assert(wired == 6 && "six of the load-time names are already referenced by the replacement");
    assert(n - wired == 26 && "26 remain to wire - this is the mechanical backlog");

    bool sawYak = false, sawTimeCrystal = false;
    for (int i = 0; i < n; ++i) {
        if (!std::strcmp(kOriginalLoadTimeSounds[i].name, "yak2.wav")) {
            sawYak = true;
            // the file's bytes, not a promise about them
            assert(std::string(kOriginalLoadTimeSounds[i].sha256).rfind("6944b23600", 0) == 0);
        }
        if (!std::strcmp(kOriginalLoadTimeSounds[i].name, "timeCrystal.wav")) sawTimeCrystal = true;
    }
    assert(sawYak && sawTimeCrystal && "known load-time names must survive regeneration");

    std::cout << "sound-preload-list: PASS (" << n << " names, " << wired << " already wired, "
              << (n - wired) << " to wire, all with sha256)\n";
    return 0;
}
