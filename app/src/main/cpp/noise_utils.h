#ifndef NOISE_UTILS_H
#define NOISE_UTILS_H

#include <cmath>
#include <cstdlib>

// Simple 1D Perlin-like Noise for terrain height
class Noise {
public:
    static float fract(float x) { return x - floor(x); }
    static float lerp(float a, float b, float t) { return a + (b - a) * t; }
    static float fade(float t) { return t * t * t * (t * (t * 6 - 15) + 10); }

    static float hash(float n) {
        return fract(sin(n) * 43758.5453123f);
    }

    static float noise1d(float x) {
        float i = floor(x);
        float f = fract(x);
        float u = fade(f);
        return lerp(hash(i), hash(i + 1.0f), u);
    }

    // Fractal Brownian Motion (Octaves)
    static float fbm(float x, int octaves) {
        float v = 0.0f;
        float a = 0.5f;
        float shift = 0.0f;
        for (int i = 0; i < octaves; ++i) {
            v += a * noise1d(x);
            x = x * 2.0f + shift;
            a *= 0.5f;
        }
        return v;
    }
    
    // Simple 2D noise for caves
    static float hash2d(float x, float y) {
        return fract(sin(x * 12.9898f + y * 78.233f) * 43758.5453f);
    }

    static float noise2d(float x, float y) {
        float ix = floor(x); float iy = floor(y);
        float fx = fract(x); float fy = fract(y);
        float ux = fade(fx); float uy = fade(fy);
        
        float a = hash2d(ix, iy);
        float b = hash2d(ix + 1, iy);
        float c = hash2d(ix, iy + 1);
        float d = hash2d(ix + 1, iy + 1);
        
        return lerp(lerp(a, b, ux), lerp(c, d, ux), uy);
    }
};

#endif
