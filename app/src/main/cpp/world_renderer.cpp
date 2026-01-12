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

    int vertexCount = 0;

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

        // --- TEST DATA ---
        std::vector<Vertex> testData;
        // Draw a 10x10 grid of blocks
        for(int x=-5; x<5; x++) {
            for(int y=-5; y<5; y++) {
                pushBlock(testData, (float)x * 0.1f, (float)y * 0.1f, (abs(x+y)%3)+1, 0.0f);
            }
        }
        vertexCount = testData.size();
        
        glBindBuffer(GL_ARRAY_BUFFER, vbo);
        glBufferData(GL_ARRAY_BUFFER, testData.size() * sizeof(Vertex), testData.data(), GL_STATIC_DRAW);
        glBindBuffer(GL_ARRAY_BUFFER, 0);
        
        LOGI("Initialized with %d vertices", vertexCount);
    }

    GLuint loadTex(AAssetManager* mgr, const char* name) {
        AAsset* asset = AAssetManager_open(mgr, name, AASSET_MODE_BUFFER);
        if(!asset) {
            LOGI("Failed to load texture: %s", name);
            return 0;
        }
        int w, h, n;
        unsigned char* d = stbi_load_from_memory((unsigned char*)AAsset_getBuffer(asset), AAsset_getLength(asset), &w, &h, &n, 4);
        GLuint id;
        glGenTextures(1, &id);
        glBindTexture(GL_TEXTURE_2D, id);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, d);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST); // Pixelated look
        stbi_image_free(d);
        AAsset_close(asset);
        return id;
    }

    GLuint createProgram(const char* vs, const char* fs) {
        GLuint v = glCreateShader(GL_VERTEX_SHADER);
        glShaderSource(v, 1, &vs, NULL); glCompileShader(v);
        // Check compile errors...
        
        GLuint f = glCreateShader(GL_FRAGMENT_SHADER);
        glShaderSource(f, 1, &fs, NULL); glCompileShader(f);
        // Check compile errors...

        GLuint p = glCreateProgram();
        glAttachShader(p, v); glAttachShader(p, f); glLinkProgram(p);
        return p;
    }

    void pushBlock(std::vector<Vertex>& buffer, float x, float y, int type, float damage) {
        if (type == 0) return;
        float ts = 32.0f/512.0f; // TileMap is 512x512, tiles are 32x32 (approx)
        // Adjust UV mapping logic if needed based on actual TileMap layout
        float tx = (float)((type-1)%16)*ts; float ty = (float)((type-1)/16)*ts;
        float s = 0.1f; // Block size
        
        // Quad vertices (Two triangles)
        // BL, BR, TL, BR, TR, TL
        buffer.push_back({x, y, tx, ty+ts, 1.0f, damage});
        buffer.push_back({x+s, y, tx+ts, ty+ts, 1.0f, damage});
        buffer.push_back({x, y+s, tx, ty, 1.0f, damage});
        
        buffer.push_back({x+s, y, tx+ts, ty+ts, 1.0f, damage});
        buffer.push_back({x+s, y+s, tx+ts, ty, 1.0f, damage});
        buffer.push_back({x, y+s, tx, ty, 1.0f, damage});
    }

    void renderFrame() {
        // animTime += 0.016f;
        // Simple auto-rotate camera or just static for now
        // camX = sin(animTime) * 0.5f; 

        glClearColor(0.52f, 0.80f, 0.92f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
        glUseProgram(program);
        
        glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, textureID);
        glUniform1i(glGetUniformLocation(program, "uTex"), 0);
        
        glActiveTexture(GL_TEXTURE1); glBindTexture(GL_TEXTURE_2D, normalID);
        glUniform1i(glGetUniformLocation(program, "uNormal"), 1);
        
        glActiveTexture(GL_TEXTURE2); glBindTexture(GL_TEXTURE_2D, destructID);
        glUniform1i(glGetUniformLocation(program, "uDestruct"), 2);

        float matrix[16];
        // Widen the view: -2 to 2 instead of -1 to 1
        Matrix::ortho(matrix, -2.0f, 2.0f, -2.0f * (9.0f/16.0f), 2.0f * (9.0f/16.0f), -1.0f, 1.0f);
        Matrix::translate(matrix, -camX, -camY, 0);
        glUniformMatrix4fv(uMatrix, 1, GL_FALSE, matrix);
        
        glBindBuffer(GL_ARRAY_BUFFER, vbo);
        
        // Vertex struct: float x, y; float u, v; float brightness; float damage;
        // Total stride = 6 * sizeof(float)
        int stride = 6 * sizeof(float);
        
        GLint posLoc = glGetAttribLocation(program, "aPos");
        glEnableVertexAttribArray(posLoc);
        glVertexAttribPointer(posLoc, 2, GL_FLOAT, GL_FALSE, stride, (void*)0);
        
        GLint texLoc = glGetAttribLocation(program, "aTex");
        glEnableVertexAttribArray(texLoc);
        glVertexAttribPointer(texLoc, 2, GL_FLOAT, GL_FALSE, stride, (void*)(2 * sizeof(float)));
        
        GLint brightLoc = glGetAttribLocation(program, "aBright");
        if(brightLoc >= 0) {
            glEnableVertexAttribArray(brightLoc);
            glVertexAttribPointer(brightLoc, 1, GL_FLOAT, GL_FALSE, stride, (void*)(4 * sizeof(float)));
        }

        GLint dmgLoc = glGetAttribLocation(program, "aDamage");
        if(dmgLoc >= 0) {
            glEnableVertexAttribArray(dmgLoc);
            glVertexAttribPointer(dmgLoc, 1, GL_FLOAT, GL_FALSE, stride, (void*)(5 * sizeof(float)));
        }
        
        glDrawArrays(GL_TRIANGLES, 0, vertexCount);
        
        glBindBuffer(GL_ARRAY_BUFFER, 0);
    }
};

WorldRenderer* g_renderer = nullptr;

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_onSurfaceCreatedNative(JNIEnv* env, jobject obj, jobject assetMgr) {
    g_renderer = new WorldRenderer();
    g_renderer->init(AAssetManager_fromJava(env, assetMgr));
}
