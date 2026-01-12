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
    GLuint textureID, destructID, normalID;
    GLuint vbo;
    GLint uMatrix;
    float camX = 0, camY = 0;
    float targetX = 0, targetY = 0;
    float animTime = 0;

    void init(AAssetManager* mgr) {
        textureID = loadTex(mgr, "TileMap.png");
        destructID = loadTex(mgr, "TileDestruct.png");
        normalID = loadTex(mgr, "ItemNormals.png");

        const char* vShader = "uniform mat4 u_Matrix; attribute vec4 aPos; attribute vec2 aTex; "
                              "attribute float aBright; attribute float aDamage; "
                              "varying vec2 vTex; varying float vBright; varying float vDamage; "
                              "void main() { gl_Position = u_Matrix * aPos; vTex = aTex; "
                              "vBright = aBright; vDamage = aDamage; }";
        
        const char* fShader = "precision mediump float; uniform sampler2D uTex; "
                              "uniform sampler2D uNormal; uniform sampler2D uDestruct; "
                              "varying vec2 vTex; varying float vBright; varying float vDamage; "
                              "void main() { "
                              "  vec4 color = texture2D(uTex, vTex); "
                              "  vec3 normal = texture2D(uNormal, vTex).rgb * 2.0 - 1.0; "
                              "  vec3 lightDir = normalize(vec3(0.5, 0.5, 1.0)); "
                              "  float diffuse = max(dot(normal, lightDir), 0.3); "
                              "  if (vDamage > 0.1) { vec4 crack = texture2D(uDestruct, vTex); color.rgb = mix(color.rgb, crack.rgb, vDamage); } "
                              "  gl_FragColor = vec4(color.rgb * vBright * diffuse, color.a); "
                              "}";

        program = createProgram(vShader, fShader);
        uMatrix = glGetUniformLocation(program, "u_Matrix");
        glGenBuffers(1, &vbo);
    }

    GLuint loadTex(AAssetManager* mgr, const char* name) {
        AAsset* asset = AAssetManager_open(mgr, name, AASSET_MODE_BUFFER);
        if(!asset) return 0;
        int w, h, n;
        unsigned char* d = stbi_load_from_memory((unsigned char*)AAsset_getBuffer(asset), AAsset_getLength(asset), &w, &h, &n, 4);
        GLuint id;
        glGenTextures(1, &id);
        glBindTexture(GL_TEXTURE_2D, id);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, d);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
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

    void pushBlock(std::vector<Vertex>& buffer, float x, float y, int type, float damage) {
        if (type == 0) return;
        float ts = 32.0f/512.0f;
        float tx = (float)((type-1)%16)*ts; float ty = (float)((type-1)/16)*ts;
        float s = 0.1f;
        buffer.push_back({x, y, tx, ty, 1.0f, damage});
        buffer.push_back({x+s, y, tx+ts, ty, 1.0f, damage});
        buffer.push_back({x, y-s, tx, ty+ts, 1.0f, damage});
        buffer.push_back({x+s, y, tx+ts, ty, 1.0f, damage});
        buffer.push_back({x+s, y-s, tx+ts, ty+ts, 1.0f, damage});
        buffer.push_back({x, y-s, tx, ty+ts, 1.0f, damage});
    }

    void renderFrame() {
        animTime += 0.016f;
        camX += (targetX - camX) * 0.1f;
        camY += (targetY - camY) * 0.1f;

        glClearColor(0.52f, 0.80f, 0.92f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
        glUseProgram(program);
        
        glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, textureID);
        glActiveTexture(GL_TEXTURE1); glBindTexture(GL_TEXTURE_2D, normalID);
        glActiveTexture(GL_TEXTURE2); glBindTexture(GL_TEXTURE_2D, destructID);

        float matrix[16];
        Matrix::ortho(matrix, -1.0f, 1.0f, -1.0f, 1.0f, -1.0f, 1.0f);
        Matrix::translate(matrix, -camX, -camY, 0);
        glUniformMatrix4fv(uMatrix, 1, GL_FALSE, matrix);
    }
};

WorldRenderer* g_renderer = nullptr;

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_onSurfaceCreatedNative(JNIEnv* env, jobject obj, jobject assetMgr) {
    g_renderer = new WorldRenderer();
    g_renderer->init(AAssetManager_fromJava(env, assetMgr));
}
