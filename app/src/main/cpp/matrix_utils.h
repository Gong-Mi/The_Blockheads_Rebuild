#ifndef MATRIX_UTILS_H
#define MATRIX_UTILS_H

#include <cmath>

class Matrix {
public:
    static void setIdentity(float* m) {
        for (int i = 0; i < 16; i++) m[i] = 0;
        m[0] = m[5] = m[10] = m[15] = 1.0f;
    }

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

    static void rotate(float* m, float angle, float x, float y, float z) {
        float a = angle * 3.14159265f / 180.0f;
        float s = sin(a);
        float c = cos(a);
        float t = 1.0f - c;

        float len = sqrt(x*x + y*y + z*z);
        if (len > 0) { x/=len; y/=len; z/=len; }

        float r[16];
        r[0] = x * x * t + c;     r[1] = x * y * t + z * s; r[2] = x * z * t - y * s; r[3] = 0;
        r[4] = y * x * t - z * s; r[5] = y * y * t + c;     r[6] = y * z * t + x * s; r[7] = 0;
        r[8] = z * x * t + y * s; r[9] = z * y * t - x * s; r[10] = z * z * t + c;    r[11] = 0;
        r[12] = 0; r[13] = 0; r[14] = 0; r[15] = 1;

        float res[16];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                res[i*4 + j] = m[i*4 + 0] * r[j] + m[i*4 + 1] * r[j+4] + m[i*4 + 2] * r[j+8] + m[i*4 + 3] * r[j+12];
            }
        }
        for (int i = 0; i < 16; i++) m[i] = res[i];
    }

    static void scale(float* m, float sx, float sy, float sz) {
        m[0] *= sx; m[1] *= sx; m[2] *= sx; m[3] *= sx;
        m[4] *= sy; m[5] *= sy; m[6] *= sy; m[7] *= sy;
        m[8] *= sz; m[9] *= sz; m[10] *= sz; m[11] *= sz;
    }
};

#endif
