#include "projection_update.h"
#include <cmath>

namespace blockheads::recovered {
namespace {
// Complete arithmetic/store contract of ARM helper 0x0092f170..0x0092f290.
void makeMatrix(float* matrix, float angle, float aspect, float nearPlane,
                float farPlane) {
    const float halfAngle = angle / 2.0f;
    const float cotangent = 1.0f / ::tanf(halfAngle);
    matrix[0] = cotangent / aspect;
    matrix[1] = matrix[2] = matrix[3] = matrix[4] = 0.0f;
    matrix[5] = cotangent;
    matrix[6] = matrix[7] = matrix[8] = matrix[9] = 0.0f;
    const float sum = farPlane + nearPlane;
    const float difference = nearPlane - farPlane;
    matrix[10] = sum / difference;
    matrix[11] = -1.0f;
    matrix[12] = matrix[13] = 0.0f;
    const float twiceFar = 2.0f * farPlane;
    const float product = twiceFar * nearPlane;
    matrix[14] = product / difference;
    matrix[15] = 0.0f;
}
} // namespace

ProjectionResult buildProjection(ProjectionInput input) {
    // ARM vcmpe/bpl selects 1 for >= and unordered, NOT std::min semantics.
    const double scale = input.pinchScale < 1.0 ? input.pinchScale : 1.0;
    // Original binary64 pool value is widened binary32 PI/3, not double PI/3.
    float angle = static_cast<float>(0x1.0c1524p+0 * scale);
    if (input.lane0 > input.lane1) {
        const float ratio = input.lane1 / input.lane0;
        angle = angle * ratio;
    }
    const float aspect = input.lane0 / input.lane1;
    ProjectionResult result;
    makeMatrix(result.matrix, angle, aspect, 1.0f, 2048.0f);
    const float numerator = input.lane1 * 0x1.99999ap-6f;
    // Opcode 0xeeb60a00 encodes 0.5, although r2 prints '5'.
    const float halfAngle = angle * 0.5f;
    const float denominator = 2.0f * ::tanf(halfAngle);
    result.cameraZ = numerator / denominator;
    return result;
}
} // namespace blockheads::recovered
