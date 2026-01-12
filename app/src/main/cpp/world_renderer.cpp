#include <GLES2/gl2.h>
#include <vector>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <android/log.h>

#define LOG_TAG "BlockheadsRenderer"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

GLuint loadShader(GLenum type, const char* source) {
    GLuint shader = glCreateShader(type);
    glShaderSource(shader, 1, &source, NULL);
    glCompileShader(shader);
    return shader;
}

class WorldRenderer {
public:
    GLuint program;
    GLuint tileMapTexture;

    // 加载 TileMap.png (还原自原版资源)
    void loadTexture(AAssetManager* mgr) {
        // 此处将来会调用 stb_image 或是 Android Bitmap 加载
        // 暂时预留 ID
        glGenTextures(1, &tileMapTexture);
        glBindTexture(GL_TEXTURE_2D, tileMapTexture);
        LOGI("Texture ID Generated: %d", tileMapTexture);
    }

    void init(AAssetManager* assetManager) {
        const char* vShader = "attribute vec4 vPosition; attribute vec2 vTexCoord; "
                              "varying vec2 outTexCoord; void main() { "
                              "gl_Position = vPosition; outTexCoord = vTexCoord; }";
        const char* fShader = "precision mediump float; uniform sampler2D uTexture; "
                              "varying vec2 outTexCoord; void main() { "
                              "gl_FragColor = texture2D(uTexture, outTexCoord); }";

        program = glCreateProgram();
        glAttachShader(program, loadShader(GL_VERTEX_SHADER, vShader));
        glAttachShader(program, loadShader(GL_FRAGMENT_SHADER, fShader));
        glLinkProgram(program);
        loadTexture(assetManager);
    }

    void renderWorld(const std::vector<float>& vertices) {
        glClearColor(0.52f, 0.80f, 0.92f, 1.0f); // 还原原版天空色
        glClear(GL_COLOR_BUFFER_BIT);
        glUseProgram(program);
        // 此处将实现方块阵列的绘制
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
    if (g_renderer) {
        std::vector<float> empty;
        g_renderer->renderWorld(empty);
    }
}
