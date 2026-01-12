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
    float damage;
};

class WorldRenderer {
public:
    GLuint program;
    GLuint textureID, destructID;
    GLuint headID, bodyID, armID, legID; // 角色贴图
    GLuint vbo;
    GLint uMatrix;
    float camX = 0, camY = 0;
    float targetX = 0, targetY = 0;
    float animTime = 0;

    void init(AAssetManager* mgr) {
        textureID = loadTex(mgr, "TileMap.png");
        destructID = loadTex(mgr, "TileDestruct.png");
        
        // 加载角色部位 (还原自 HDTex)
        headID = loadTex(mgr, "HDTex/head_ct.png");
        bodyID = loadTex(mgr, "HDTex/body_ct.png");
        armID = loadTex(mgr, "HDTex/arms_ct.png");
        legID = loadTex(mgr, "HDTex/legs_ct.png");

        const char* vShader = "uniform mat4 u_Matrix; attribute vec4 aPos; attribute vec2 aTex; "
                              "attribute float aBright; attribute float aDamage; "
                              "varying vec2 vTex; varying float vBright; varying float vDamage; "
                              "void main() { gl_Position = u_Matrix * aPos; vTex = aTex; "
                              "vBright = aBright; vDamage = aDamage; }";
        
        const char* fShader = "precision mediump float; uniform sampler2D uTex; "
                              "uniform sampler2D uDestruct; varying vec2 vTex; "
                              "varying float vBright; varying float vDamage; "
                              "void main() { vec4 color = texture2D(uTex, vTex); "
                              "if (vDamage > 0.1) { vec4 crack = texture2D(uDestruct, vTex); color.rgb = mix(color.rgb, crack.rgb, vDamage); } "
                              "gl_FragColor = vec4(color.rgb * vBright, color.a); }";

        program = createProgram(vShader, fShader);
        uMatrix = glGetUniformLocation(program, "u_Matrix");
        glGenBuffers(1, &vbo);
    }

    GLuint loadTex(AAssetManager* mgr, const char* name) {
        AAsset* asset = AAssetManager_open(mgr, name, AASSET_MODE_BUFFER);
        if(!asset) { LOGI("Failed to load: %s", name); return 0; }
        int w, h, n;
        unsigned char* d = stbi_load_from_memory((unsigned char*)AAsset_getBuffer(asset), AAsset_getLength(asset), &w, &h, &n, 4);
        GLuint id;
        glGenTextures(1, &id);
        glBindTexture(GL_TEXTURE_2D, id);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, d);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        stbi_image_free(d);
        AAsset_close(asset);
        return id;
    }

    GLuint createProgram(const char* vs, const char* fs) {
        GLuint v = glCreateShader(GL_VERTEX_SHADER);
        glShaderSource(v, 1, &vs, NULL); glCompileShader(v);
        GLuint f = glCreateShader(GL_FRAGMENT_SHADER);
        glShaderSource(f, 1, &fs, NULL); glCompileShader(f);
        GLuint p = glCreateProgram();
        glAttachShader(p, v); glAttachShader(p, f); glLinkProgram(p);
        return p;
    }

    // 绘制角色肢体 (带旋转)
    void pushPart(std::vector<Vertex>& buffer, float x, float y, float w, float h, float angle) {
        // 简化版：目前先作为矩形渲染，将来引入局部旋转矩阵
        buffer.push_back({x, y, 0, 0, 1.0f, 0.0f});
        buffer.push_back({x+w, y, 1, 0, 1.0f, 0.0f});
        buffer.push_back({x, y-h, 0, 1, 1.0f, 0.0f});
        buffer.push_back({x+w, y, 1, 0, 1.0f, 0.0f});
        buffer.push_back({x+w, y-h, 1, 1, 1.0f, 0.0f});
        buffer.push_back({x, y-h, 0, 1, 1.0f, 0.0f});
    }

    void drawPlayer(std::vector<Vertex>& buffer, float px, float py, bool walking) {
        float swing = walking ? sin(animTime * 10.0f) * 0.5f : 0;
        
        // 绘制顺序：后腿 -> 后手 -> 身体 -> 头 -> 前腿 -> 前手 (模拟 2.5D 遮挡)
        pushPart(buffer, px, py, 0.06f, 0.08f, 0); // 身体
        pushPart(buffer, px+0.01f, py+0.04f, 0.04f, 0.04f, 0); // 头
    }

    void renderFrame() {
        animTime += 0.016f; // 假设 60fps
        camX += (targetX - camX) * 0.1f;
        camY += (targetY - camY) * 0.1f;

        glClearColor(0.52f, 0.80f, 0.92f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
        glEnable(GL_BLEND);
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
        
        glUseProgram(program);
        float matrix[16];
        Matrix::ortho(matrix, -1.0f, 1.0f, -1.0f, 1.0f, -1.0f, 1.0f);
        Matrix::translate(matrix, -camX, -camY, 0);
        glUniformMatrix4fv(uMatrix, 1, GL_FALSE, matrix);
    }
};