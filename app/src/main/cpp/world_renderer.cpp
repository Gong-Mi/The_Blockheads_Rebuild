#include <GLES2/gl2.h>
#include <vector>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>

// 简单的着色器加载函数
GLuint loadShader(GLenum type, const char* source) {
    GLuint shader = glCreateShader(type);
    glShaderSource(shader, 1, &source, NULL);
    glCompileShader(shader);
    return shader;
}

class WorldRenderer {
public:
    GLuint program;
    GLuint textureID;

    void init(AAssetManager* assetManager) {
        // 在此处加载 assets/shaders/Block.vsh 和 Block.fsh
        // 暂时使用占位逻辑，实际开发时会从 assetManager 读取文件内容
        const char* vShaderCode = "attribute vec4 vPosition; void main() { gl_Position = vPosition; }";
        const char* fShaderCode = "precision mediump float; void main() { gl_FragColor = vec4(1.0, 1.0, 1.0, 1.0); }";

        GLuint vertexShader = loadShader(GL_VERTEX_SHADER, vShaderCode);
        GLuint fragmentShader = loadShader(GL_FRAGMENT_SHADER, fShaderCode);

        program = glCreateProgram();
        glAttachShader(program, vertexShader);
        glAttachShader(program, fragmentShader);
        glLinkProgram(program);
    }

    void drawFrame() {
        glClearColor(0.5f, 0.8f, 1.0f, 1.0f); // 天蓝色背景
        glClear(GL_COLOR_BUFFER_BIT);
        glUseProgram(program);
        // 此处将实现方块的批量渲染 (Batch Rendering)
    }
};

static WorldRenderer* g_renderer = nullptr;

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_onSurfaceCreatedNative(JNIEnv* env, jobject obj, jobject assetMgr) {
    g_renderer = new WorldRenderer();
    AAssetManager* mgr = AAssetManager_fromJava(env, assetMgr);
    g_renderer->init(mgr);
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_onDrawFrameNative(JNIEnv* env, jobject obj) {
    if (g_renderer) g_renderer->drawFrame();
}
