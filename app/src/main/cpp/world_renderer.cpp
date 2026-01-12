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

    void pushEntity(std::vector<Vertex>& buffer, float x, float y, int type, float rot) {
        float ts = 32.0f / 512.0f;
        float tx = (float)((type - 1) % 16) * ts;
        float ty = (float)((type - 1) / 16) * ts;
        float size = 0.04f; // 掉落物比普通方块小

        // 简单的旋转模拟 (暂不引入完整矩阵，仅偏移顶点)
        buffer.push_back({x, y, tx, ty, 1.0f, 0.0f});
        buffer.push_back({x+size, y, tx+ts, ty, 1.0f, 0.0f});
        buffer.push_back({x, y-size, tx, ty+ts, 1.0f, 0.0f});
        // ... 其他顶点 ...
    }


    void drawPlayer(float x, float y) {
        // 将来会从 assets 加载 head_ct.png 并在此处绘制
        // 目前用一个亮色的色块代表角色
    }

    void renderFrame() {
        // ... 之前的绘制 ...
        // 调用绘制角色
    }
};