#include <GLES2/gl2.h>
#include <vector>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <android/log.h>

#define STB_IMAGE_IMPLEMENTATION
#include "external/stb_image.h"

#define LOG_TAG "BlockheadsRenderer"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

class WorldRenderer {
public:
    GLuint program;
    GLuint textureID;
    GLint posAttrib, texAttrib, uMatrix;

    void init(AAssetManager* mgr) {
        // --- 1. 加载 TileMap.png ---
        AAsset* asset = AAssetManager_open(mgr, "TileMap.png", AASSET_MODE_BUFFER);
        off_t length = AAsset_getLength(asset);
        unsigned char* buffer = (unsigned char*)AAsset_getBuffer(asset);
        
        int w, h, n;
        unsigned char* data = stbi_load_from_memory(buffer, length, &w, &h, &n, 4);
        
        glGenTextures(1, &textureID);
        glBindTexture(GL_TEXTURE_2D, textureID);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, data);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST); // 保持像素感
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
        
        stbi_image_free(data);
        AAsset_close(asset);

        // --- 2. 编译着色器 ---
        const char* vShader = 
            "attribute vec4 a_Position; attribute vec2 a_TexCoord; "
            "varying vec2 v_TexCoord; "
            "void main() { gl_Position = a_Position; v_TexCoord = a_TexCoord; }";
        const char* fShader = 
            "precision mediump float; uniform sampler2D u_Texture; "
            "varying vec2 v_TexCoord; "
            "void main() { gl_FragColor = texture2D(u_Texture, v_TexCoord); }";

        program = glCreateProgram();
        // (简化处理：实际应调用 glCompileShader)
        LOGI("Renderer Initialized with Texture: %dx%d", w, h);
    }

    void drawBlock(float x, float y, int type) {
        // 这里将来会实现批量渲染逻辑
        // 根据 type 计算 UV 坐标 (32x32 分割)
    }

    void renderFrame() {
        glClearColor(0.52f, 0.80f, 0.92f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        glUseProgram(program);
        // 渲染流程...
    }
};

static WorldRenderer* g_renderer = nullptr;

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_onSurfaceCreatedNative(JNIEnv* env, jobject obj, jobject assetMgr) {
    g_renderer = new WorldRenderer();
    g_renderer->init(AAssetManager_fromJava(env, assetMgr));
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_onDrawFrameNative(JNIEnv* env, jobject obj) {
    if (g_renderer) g_renderer->renderFrame();
}