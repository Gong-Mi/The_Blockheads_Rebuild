#ifndef MATRIX_UTILS_H
#define MATRIX_UTILS_H

#include <cmath>

class Matrix {
public:
    static void ortho(float* m, float left, float right, float bottom, float top, float near, float far) {
        float r_l = right - left;
        float t_b = top - bottom;
        float f_n = far - near;
        m[0] = 2.0f / r_l; m[1] = 0.0f; m[2] = 0.0f; m[3] = 0.0f;
        m[4] = 0.0f; m[5] = 2.0f / t_b; m[6] = 0.0f; m[7] = 0.0f;
        m[8] = 0.0f; m[9] = 0.0f; m[10] = -2.0f / f_n; m[11] = 0.0f;
        m[12] = -(right + left) / r_l; m[13] = -(top + bottom) / t_b; m[14] = -(far + near) / f_n; m[15] = 1.0f;
    }

    static void translate(float* m, float x, float y, float z) {
        m[12] += m[0] * x + m[4] * y + m[8] * z;
        m[13] += m[1] * x + m[5] * y + m[9] * z;
        m[14] += m[2] * x + m[6] * y + m[10] * z;
        m[15] += m[3] * x + m[7] * y + m[11] * z;
    }
};

#endif
