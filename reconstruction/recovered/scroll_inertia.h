#pragma once

// Numerical/state slice of GameView.update, not a whole-game replacement.
// Preconditions: entry hasRenderedFrame/loadComplete gates have passed;
// finite inputs, ordinary IEEE arithmetic (no fast-math/FP contraction).
namespace blockheads::recovered {
struct Vec2 { float x; float y; };
struct ScrollState {
    bool scrolling;
    bool pinching;
    bool hasVelocity;
    Vec2 velocity;
};
struct InertiaResult {
    ScrollState state;
    bool writeTranslation;
    Vec2 translation;
};
InertiaResult stepInertia(ScrollState state, bool translatingToGoal,
                          Vec2 translation, float dt);
}
