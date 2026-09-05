#pragma once

namespace blockheads::recovered {
// Only lane offsets are proved; dimension names/units remain unverified.
struct ProjectionInput {
    double pinchScale;
    float lane0; // GameView.windowInfo +0
    float lane1; // GameView.windowInfo +4
};
struct ProjectionResult {
    float matrix[16]; // exact contiguous helper output; no transpose
    float cameraZ;
};
// Preserve IEEE exceptional inputs. Build without fast-math or FP contraction.
ProjectionResult buildProjection(ProjectionInput input);
} // namespace blockheads::recovered
