#include <GLES2/gl2.h>
#include <vector>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <android/log.h>

#define STB_IMAGE_IMPLEMENTATION
#include "external/stb_image.h"

#define LOG_TAG "BlockheadsRenderer"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

struct Vertex {
    float x, y;
    float u, v;
};

class WorldRenderer {
public:
    GLuint program;
    GLuint textureID;
    GLuint vbo;
    GLint posAttrib, texAttrib;

    void init(AAssetManager* mgr) {
        // --- 1. 加载纹理 (NEAREST 过滤以保留像素感) ---
        AAsset* asset = AAssetManager_open(mgr, "TileMap.png", AASSET_MODE_BUFFER);
        int w, h, n;
        unsigned char* data = stbi_load_from_memory((unsigned char*)AAsset_getBuffer(asset), AAsset_getLength(asset), &w, &h, &n, 4);
        glGenTextures(1, &textureID);
        glBindTexture(GL_TEXTURE_2D, textureID);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, data);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
        stbi_image_free(data);
        AAsset_close(asset);

        // --- 2. 编译核心渲染着色器 ---
        const char* vShader = "attribute vec4 aPos; attribute vec2 aTex; "
                              "varying vec2 vTex; void main() { "
                              "gl_Position = aPos; vTex = aTex; }";
        const char* fShader = "precision mediump float; uniform sampler2D uTex; "
                              "varying vec2 vTex; void main() { "
                              "gl_FragColor = texture2D(uTex, vTex); }";
        
        program = glCreateProgram();
        // ... 此处省略 glCompileShader 的样板代码 ...
        
        glGenBuffers(1, &vbo);
    }

    // 根据方块类型计算 TileMap.png (512x512) 中的 UV
    void pushBlock(std::vector<Vertex>& buffer, float x, float y, int type) {
        if (type == 0) return;
        float ts = 32.0f / 512.0f; // 假设每个 Tile 是 32 像素
        float tx = (float)((type - 1) % 16) * ts;
        float ty = (float)((type - 1) / 16) * ts;

        // 两个三角形拼成一个方块
        buffer.push_back({x, y, tx, ty});
        buffer.push_back({x+0.1f, y, tx+ts, ty});
        buffer.push_back({x, y-0.1f, tx, ty+ts});
        buffer.push_back({x+0.1f, y, tx+ts, ty});
        buffer.push_back({x+0.1f, y-0.1f, tx+ts, ty+ts});
        buffer.push_back({x, y-0.1f, tx, ty+ts});
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