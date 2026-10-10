// Per-class CTest driver for the recovered tree-family LONG loader contract
// (reconstruction/recovered/treefamily9_long_init.cpp + the thin wrappers in
// treefamily9_long_init_classes.h).
//
// One shared static lib + one shared thin driver; CMake registers nine CTest
// entries, each passing one class name so every class's own superref/selector
// binding is exercised. Runs in CTest so CI checks the contract without the
// original ELF; tools/test_treefamily9_long_init_arm.py executes the nine
// original ARM bodies and must produce the same forwarded tuples and traces.
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "treefamily9_long_init.h"
#include "treefamily9_long_init_classes.h"

namespace {

using blockheads::recovered::kArgCache;
using blockheads::recovered::kArgDynamicWorld;
using blockheads::recovered::kArgSaveDict;
using blockheads::recovered::kArgSeasonOffsetNoiseFunction;
using blockheads::recovered::kArgTreeDensityNoiseFunction;
using blockheads::recovered::kArgWorld;
using blockheads::recovered::kTreeForward9Classes;
using blockheads::recovered::TreeForward9Class;
using blockheads::recovered::TreeForward9Inputs;
using blockheads::recovered::TreeForward9Result;
using blockheads::recovered::treefamily9_long_init_forward;

int failures = 0;

void expect(bool condition, const char* what) {
    if (!condition) {
        std::printf("FAIL: %s\n", what);
        ++failures;
    }
}

// Independent expectation of the b3i decode, transcribed from
// reconstruction/reverse-v3/native/TREEFAMILY9_LONG_INITWITHWORLD.md (NOT from
// the generated .inc): the nine classes' IMP addresses. A regenerated table
// that silently changed an entry point fails here, not just against itself.
struct PinnedImp {
    const char* name;
    std::uintptr_t imp;
};
constexpr PinnedImp kPinned[] = {
    {"CactusTree", 0x00B533BCu},  {"CherryTree", 0x00D0DF2Cu},
    {"CoconutTree", 0x00A99948u}, {"CoffeeTree", 0x007DEB28u},
    {"GemTree", 0x00529134u},     {"LimeTree", 0x00809C3Cu},
    {"MangoTree", 0x00D4B4F4u},   {"MapleTree", 0x00DB5FB4u},
    {"OrangeTree", 0x00A96604u},
};

// The six argument tokens used by both the C++ and the ARM side. Distinct so a
// permuted forward is a mismatch.
constexpr std::uintptr_t kTokens[6] = {
    0x11110000u, 0x22220000u, 0x33330000u, 0x44440000u, 0x55550000u,
    0x66660000u,
};

TreeForward9Inputs make_inputs(const TreeForward9Class& cls) {
    TreeForward9Inputs in;
    for (int i = 0; i < 6; ++i) {
        in.args[i] = kTokens[i];
    }
    in.class_ref = cls.superref_slot;
    in.selector_ref = cls.selector_cell;
    return in;
}

void check_class(const TreeForward9Class& cls, bool full_suite) {
    const TreeForward9Inputs in = make_inputs(cls);
    const TreeForward9Result ok = treefamily9_long_init_forward(in);
    expect(!ok.returned_nil, "happy path returns self (not nil)");
    expect(ok.calls.size() == 1, "exactly one call (the super forward)");
    expect(ok.super_class_ref == cls.superref_slot, "class ref is the cell");
    expect(ok.super_selector_ref == cls.selector_cell, "selector ref is the cell");
    for (int i = 0; i < 6; ++i) {
        expect(ok.forwarded[i] == in.args[i],
               "all six arguments spill through in declared order");
    }
    // Spill order independence: the tuple must be positional, not sorted.
    for (int i = 0; i < 6; ++i) {
        expect(ok.forwarded[i] == kTokens[i],
               "argument position i carries token i");
    }

    TreeForward9Inputs nil_in = in;
    nil_in.super_returns_nil = true;
    const TreeForward9Result nil = treefamily9_long_init_forward(nil_in);
    expect(nil.returned_nil, "nil super → returns nil");
    expect(nil.calls.size() == 1, "nil super → still exactly the super call");
    for (int i = 0; i < 6; ++i) {
        expect(nil.forwarded[i] == kTokens[i],
               "nil path forwards the same tuple");
    }

    (void)full_suite;
}

// The size of the generated table is the independent count of the b3i record.
void check_table() {
    constexpr int kCount = static_cast<int>(sizeof(kTreeForward9Classes) /
                                            sizeof(kTreeForward9Classes[0]));
    expect(kCount == 9, "nine classes in the table");
    for (int i = 0; i < kCount; ++i) {
        const TreeForward9Class& cls = kTreeForward9Classes[i];
        bool found = false;
        for (const PinnedImp& p : kPinned) {
            if (std::strcmp(p.name, cls.name) == 0) {
                found = true;
                expect(cls.imp == p.imp, "IMP matches the pinned b3i decode");
            }
        }
        expect(found, "class is one of the nine pinned tree classes");
        expect(cls.boundary - cls.imp == 62u * 4u, "body is 62 words");
        expect(cls.superref_slot != 0 && cls.selector_cell != 0,
               "cells are populated");
    }
    // Distinctness: a copied row would collapse two classes onto one cell.
    for (int i = 0; i < kCount; ++i) {
        for (int j = i + 1; j < kCount; ++j) {
            expect(kTreeForward9Classes[i].superref_slot !=
                       kTreeForward9Classes[j].superref_slot,
                   "superref cells are distinct");
            expect(kTreeForward9Classes[i].selector_cell !=
                       kTreeForward9Classes[j].selector_cell,
                   "selector cells are distinct");
            expect(kTreeForward9Classes[i].imp != kTreeForward9Classes[j].imp,
                   "IMPs are distinct");
        }
    }
}

}  // namespace

int main(int argc, char** argv) {
    const char* only = argc > 1 ? argv[1] : nullptr;
    check_table();
    int ran = 0;
    for (const TreeForward9Class& cls : kTreeForward9Classes) {
        if (only != nullptr && std::strcmp(only, cls.name) != 0) {
            continue;
        }
        check_class(cls, true);
        ++ran;
    }
    if (only != nullptr) {
        expect(ran == 1, "the requested class exists exactly once");
    } else {
        expect(ran == 9, "all nine classes exercised");
    }

    if (failures == 0) {
        std::printf("recovered_treefamily9_long_init%s%s: PASS\n",
                    only ? "[" : "", only ? only : "");
    }
    return failures == 0 ? 0 : 1;
}
