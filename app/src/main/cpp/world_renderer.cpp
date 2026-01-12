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
    float brightness;
    float damage; // 0.0 - 1.0
};

void pushBlock(std::vector<Vertex>& buffer, float x, float y, int type, float damage) {
    // ... 计算 UV ...
    // 在 push 顶点时加入 damage 参数
    buffer.push_back({x, y, tx, ty, 1.0f, damage});
    // ...
}
        // ... 原有的纹理加载 ...
        
        // 加载受损贴图 (还原自原版 TileDestruct.png)
        AAsset* dAsset = AAssetManager_open(mgr, "TileDestruct.png", AASSET_MODE_BUFFER);
        unsigned char* dData = stbi_load_from_memory((unsigned char*)AAsset_getBuffer(dAsset), AAsset_getLength(dAsset), &w, &h, &n, 4);
        glGenTextures(1, &destructTextureID);
        glBindTexture(GL_TEXTURE_2D, destructTextureID);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, dData);
        // ... 过滤设置 ...

        const char* fShader = "precision mediump float; uniform sampler2D uTex; "
                              "uniform sampler2D uDestruct; varying vec2 vTex; "
                              "varying float vBright; varying float vDamage; "
                              "void main() { vec4 color = texture2D(uTex, vTex); "
                              "vec4 crack = texture2D(uDestruct, vTex); "
                              "vec3 finalColor = mix(color.rgb, crack.rgb, vDamage); "
                              "gl_FragColor = vec4(finalColor * vBright, color.a); }";
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