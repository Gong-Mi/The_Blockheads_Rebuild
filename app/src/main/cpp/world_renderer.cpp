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
        // ... 加载纹理逻辑保持不变 ...
        const char* vShader = "uniform mat4 u_Matrix; attribute vec4 aPos; attribute vec2 aTex; "
                              "varying vec2 vTex; void main() { "
                              "gl_Position = u_Matrix * aPos; vTex = aTex; }";
        // ... 片元着色器保持不变 ...
        
        program = glCreateProgram();
        // 编译代码并获取 uMatrix 位置
        uMatrix = glGetUniformLocation(program, "u_Matrix");
        glGenBuffers(1, &vbo);
    }

    void updateCamera() {
        // --- 还原自原版的平滑跟踪逻辑 (Lerp) ---
        camX += (targetX - camX) * 0.1f;
        camY += (targetY - camY) * 0.1f;
    }

    void renderFrame(int screenW, int screenY) {
        updateCamera();
        glClearColor(0.52f, 0.80f, 0.92f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        glUseProgram(program);

        float matrix[16];
        Matrix::ortho(matrix, -1.0f, 1.0f, -1.0f, 1.0f, -1.0f, 1.0f);
        Matrix::translate(matrix, -camX, -camY, 0); // 摄像机平移
        glUniformMatrix4fv(uMatrix, 1, GL_FALSE, matrix);

        // 绘制逻辑...
    }
};

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