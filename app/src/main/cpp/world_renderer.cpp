#include <GLES2/gl2.h>
#include <vector>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <android/log.h>
#include "matrix_utils.h"

#define STB_IMAGE_IMPLEMENTATION
#include "external/stb_image.h"

#define LOG_TAG "BlockheadsRenderer"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

struct Vertex {
    float x, y;
    float u, v;
    float brightness; // 用于模拟侧边阴影
};

class WorldRenderer {
public:
    GLuint program;
    GLuint textureID;
    GLuint vbo;
    GLint uMatrix;
    float camX = 0, camY = 0;
    float targetX = 0, targetY = 0;

    void init(AAssetManager* mgr) {
        // ... 纹理加载代码 ...
        const char* vShader = "uniform mat4 u_Matrix; attribute vec4 aPos; attribute vec2 aTex; "
                              "attribute float aBright; varying vec2 vTex; varying float vBright; "
                              "void main() { gl_Position = u_Matrix * aPos; vTex = aTex; vBright = aBright; }";
        const char* fShader = "precision mediump float; uniform sampler2D uTex; "
                              "varying vec2 vTex; varying float vBright; "
                              "void main() { vec4 color = texture2D(uTex, vTex); "
                              "gl_FragColor = vec4(color.rgb * vBright, color.a); }";
        
        // ... 编译逻辑 ...
    }

    void pushBlock(std::vector<Vertex>& buffer, float x, float y, int type) {
        if (type == 0) return;
        float ts = 32.0f / 512.0f;
        float tx = (float)((type - 1) % 16) * ts;
        float ty = (float)((type - 1) / 16) * ts;

        float size = 0.1f;
        float depth = 0.02f; // 2.5D 边缘的厚度

        // --- 1. 正面渲染 (亮度 1.0) ---
        buffer.push_back({x, y, tx, ty, 1.0f});
        buffer.push_back({x+size, y, tx+ts, ty, 1.0f});
        buffer.push_back({x, y-size, tx, ty+ts, 1.0f});
        buffer.push_back({x+size, y, tx+ts, ty, 1.0f});
        buffer.push_back({x+size, y-size, tx+ts, ty+ts, 1.0f});
        buffer.push_back({x, y-size, tx, ty+ts, 1.0f});

        // --- 2. 侧面阴影 (亮度 0.6，模拟 2.5D 厚度) ---
        // 原版通过在方块底部绘制一个斜向下的色块来实现立体感
        buffer.push_back({x, y-size, tx, ty+ts, 0.6f});
        buffer.push_back({x+size, y-size, tx+ts, ty+ts, 0.6f});
        buffer.push_back({x+depth, y-size-depth, tx, ty+ts, 0.6f});
        
        buffer.push_back({x+size, y-size, tx+ts, ty+ts, 0.6f});
        buffer.push_back({x+size+depth, y-size-depth, tx+ts, ty+ts, 0.6f});
        buffer.push_back({x+depth, y-size-depth, tx, ty+ts, 0.6f});
    }

    void renderFrame() {
        glClearColor(0.52f, 0.80f, 0.92f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        glUseProgram(program);
        
        std::vector<Vertex> vertices;
        // 渲染视口内的方块 (此处为测试，只画几个)
        for(int i=0; i<5; i++) pushBlock(vertices, -0.5f + i*0.1f, 0.0f, i+1);

        glBindBuffer(GL_ARRAY_BUFFER, vbo);
        glBufferData(GL_ARRAY_BUFFER, vertices.size() * sizeof(Vertex), vertices.data(), GL_STREAM_DRAW);
        
        // 开启顶点属性并绘制
        glDrawArrays(GL_TRIANGLES, 0, vertices.size());
    }
};