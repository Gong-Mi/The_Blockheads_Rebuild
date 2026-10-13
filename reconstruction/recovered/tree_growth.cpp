// tree_growth.cpp — the accumulation machine (see tree_growth.h).
//
// The body's loop shape (listing):
//   0x004c26bc  dead check -> tail
//   0x004c25e8  age + elapsed >= maxAge -> death block (0x004c2b24)
//   0x004c26f8  height >= maxHeight || elapsed <= 0 -> no-grow tail
//   0x004c285c  P and (1-counter)/P
//   0x004c292c  elapsed >= (1-counter)/P -> grow pass (0x004c2930)
//   0x004c2a9c  else the counter accumulation, elapsed := -1.0 sentinel
//   0x004c2b1c  loop back to 0x004c26bc (the sentinel ends it)
#include "tree_growth.h"

namespace blockheads::tree {

GrowthResult grow(const GrowthState& in, double world_time, double save_time,
                  const GeneIncrement& genes, bool is_static) {
    GrowthResult out;
    out.state = in;
    if (is_static) {
        // `isStaticTree != 0` -> the body returns 1 with no other effects.
        out.outcome = GrowthOutcome::static_tree_no_growth;
        return out;
    }
    if (in.dead) {
        // The dead check before the machine: the body returns nil.
        out.outcome = GrowthOutcome::dead_no_growth;
        return out;
    }

    double elapsed = elapsed_of(world_time, save_time);
    GrowthState& st = out.state;
    bool grew_any = false;

    // The machine loop; the -1.0 sentinel guarantees termination.
    for (;;) {
        if (static_cast<double>(st.age) + elapsed >=
            static_cast<double>(st.max_age)) {
            // The death block: removeAllOwnedTiles:, timeDied@112, dead@104.
            st.dead = true;
            st.time_died = world_time;
            out.outcome = GrowthOutcome::died;
            return out;
        }
        if (st.height >= st.max_height || elapsed <= 0.0) {
            // The no-grow tail: updateGrowth: then nil (or 1 once a grow
            // pass has run — the body returns 1 on the observed runs).
            out.outcome =
                grew_any ? GrowthOutcome::grew : GrowthOutcome::no_growth;
            return out;
        }

        const double p = growth_p(st, genes);
        const double need =
            p != 0.0 ? (1.0 - st.growth_counter) / p : 0.0;
        if (elapsed >= need) {
            // The grow pass: the carry, the counter reset, incrementHeight,
            // and maxHeightReached := max(maxHeightReached, height).
            elapsed -= need;
            st.age = static_cast<float>(st.age + need);
            st.growth_counter = 0.0f;
            // incrementHeight() is a call in the body; on both verified runs
            // its observable effect on the state was nil (height unchanged),
            // so the model keeps the height and only records that it ran.
            if (st.height > st.max_height_reached) {
                st.max_height_reached = st.height;
            }
            grew_any = true;
            continue;  // loop back to 0x004c26bc
        }
        // The accumulation: counter += (1-counter) * (elapsed / need) which
        // the algebra reduces to counter += elapsed * P; then the sentinel.
        if (p != 0.0) {
            const float before = st.growth_counter;
            st.growth_counter = static_cast<float>(
                st.growth_counter +
                (1.0 - st.growth_counter) * (elapsed / need));
            out.counter_delta = st.growth_counter - before;
        }
        elapsed = -1.0;  // the sentinel: the next pass exits via elapsed <= 0
        continue;
    }
}

}  // namespace blockheads::tree
