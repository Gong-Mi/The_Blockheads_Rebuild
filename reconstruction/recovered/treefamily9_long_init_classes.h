// Per-class thin wrappers over the shared tree-family LONG loader contract.
//
// The nine classes' bodies are byte-identical (b3i): the only per-class state
// is the tail literal cells (own-class superref + selector cell). Rather than
// copying the body nine times, each class is a one-line wrapper that binds its
// own cells and delegates to treefamily9_long_init_forward. The cell values
// are generated from the frozen static decode by
// tools/gen_treefamily9_class_table.py (--check gated); the row file is
// expanded twice here -- once into the descriptor table the CTest and tests
// walk, once into the named wrappers that carry the per-class entry points.
#pragma once

#include <cstdint>

#include "treefamily9_long_init.h"

namespace blockheads::recovered {

struct TreeForward9Class {
    const char* name;
    std::uintptr_t imp;
    std::uintptr_t boundary;
    std::uintptr_t superref_slot;
    std::uintptr_t selector_cell;
};

#define BLOCKHEADS_TREE9_ROW(NAME, NAME_STR, IMP, BOUNDARY, SUPERREF, SEL) \
    {NAME_STR, IMP, BOUNDARY, SUPERREF, SEL},
inline constexpr TreeForward9Class kTreeForward9Classes[] = {
#include "treefamily9_long_init_classes.inc"
};
#undef BLOCKHEADS_TREE9_ROW

#define BLOCKHEADS_TREE9_ROW(NAME, NAME_STR, IMP, BOUNDARY, SUPERREF, SEL)     \
    inline TreeForward9Result NAME##_long_init(const TreeForward9Inputs& in) { \
        TreeForward9Inputs bound = in;                                         \
        bound.class_ref = SUPERREF;                                            \
        bound.selector_ref = SEL;                                              \
        return treefamily9_long_init_forward(bound);                           \
    }
#include "treefamily9_long_init_classes.inc"
#undef BLOCKHEADS_TREE9_ROW

}  // namespace blockheads::recovered
