#include "world_renderer.h"
#include <android/asset_manager_jni.h>
#include <android/log.h>
#include <cmath>
#include "matrix_utils.h"

#define STB_IMAGE_IMPLEMENTATION
#include "external/stb_image.h"

#undef LOG_TAG
#define LOG_TAG "BlockheadsRenderer"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

WorldRenderer* g_renderer = nullptr;

void WorldRenderer::init(AAssetManager* mgr) {
    textureID = loadTex(mgr, "TileMap.png");
    destructID = loadTex(mgr, "TileDestruct.png");
    normalID = loadTex(mgr, "ItemNormals.png");
    playerTexID = loadTex(mgr, "BlockheadBody.png");
    itemsTexID = loadTex(mgr, "Items.png");

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
    vertexCount = 0;
}

GLuint WorldRenderer::loadTex(AAssetManager* mgr, const char* name) {
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
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    stbi_image_free(d);
    AAsset_close(asset);
    return id;
}

GLuint WorldRenderer::createProgram(const char* vs, const char* fs) {
    GLuint v = glCreateShader(GL_VERTEX_SHADER);
    glShaderSource(v, 1, &vs, NULL); glCompileShader(v);
    GLuint f = glCreateShader(GL_FRAGMENT_SHADER);
    glShaderSource(f, 1, &fs, NULL); glCompileShader(f);
    GLuint p = glCreateProgram();
    glAttachShader(p, v); glAttachShader(p, f); glLinkProgram(p);
    return p;
}

void WorldRenderer::pushBlock(std::vector<Vertex>& buffer, float x, float y, int type, float damage) {
    if (type == 0) return;
    float ts = 32.0f/512.0f;
    float tx = (float)((type-1)%16)*ts; float ty = (float)((type-1)/16)*ts;
    float s = 0.1f;
    buffer.push_back({x, y, tx, ty+ts, 1.0f, damage});
    buffer.push_back({x+s, y, tx+ts, ty+ts, 1.0f, damage});
    buffer.push_back({x, y+s, tx, ty, 1.0f, damage});
    buffer.push_back({x+s, y, tx+ts, ty+ts, 1.0f, damage});
    buffer.push_back({x+s, y+s, tx+ts, ty, 1.0f, damage});
    buffer.push_back({x, y+s, tx, ty, 1.0f, damage});
}

void WorldRenderer::updateMesh(const std::vector<PhysicalBlock*>& chunks) {
    std::vector<Vertex> vertices;
    for (PhysicalBlock* chunk : chunks) {
        if (!chunk) continue;
        for (int i = 0; i < CHUNK_SIZE * CHUNK_SIZE; i++) {
            Tile& t = chunk->tiles[i];
            if (t.foreground == 0) continue;
            int lx = i % CHUNK_SIZE;
            int ly = i / CHUNK_SIZE;
            float wx = (chunk->x * CHUNK_SIZE + lx) * 0.1f;
            float wy = (chunk->y * CHUNK_SIZE + ly) * 0.1f;
            pushBlock(vertices, wx, wy, t.foreground, t.damage > 0 ? (float)t.damage / 255.0f : 0.0f);
        }
    }
    glBindBuffer(GL_ARRAY_BUFFER, vbo);
    glBufferData(GL_ARRAY_BUFFER, vertices.size() * sizeof(Vertex), vertices.data(), GL_DYNAMIC_DRAW);
    glBindBuffer(GL_ARRAY_BUFFER, 0);
    vertexCount = vertices.size();
}

void WorldRenderer::renderFrame() {
    camX += (targetX - camX) * 0.1f;
    camY += (targetY - camY) * 0.1f;

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
    Matrix::ortho(matrix, -2.0f, 2.0f, -2.0f * (9.0f/16.0f), 2.0f * (9.0f/16.0f), -1.0f, 1.0f);
    Matrix::translate(matrix, -camX, -camY, 0);
    glUniformMatrix4fv(uMatrix, 1, GL_FALSE, matrix);
    
    glBindBuffer(GL_ARRAY_BUFFER, vbo);
    int stride = sizeof(Vertex);
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
    
    if (playerTexID != 0) {
        glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, playerTexID);
        glActiveTexture(GL_TEXTURE1); glBindTexture(GL_TEXTURE_2D, playerTexID);
        glActiveTexture(GL_TEXTURE2); glBindTexture(GL_TEXTURE_2D, 0);
        float w = 0.15f, h = 0.3f;
        Vertex pVerts[] = {
            {playerX - w/2, playerY, 0.0f, 1.0f, 1.0f, 0.0f},
            {playerX + w/2, playerY, 1.0f, 1.0f, 1.0f, 0.0f},
            {playerX - w/2, playerY + h, 0.0f, 0.0f, 1.0f, 0.0f},
            {playerX + w/2, playerY, 1.0f, 1.0f, 1.0f, 0.0f},
            {playerX + w/2, playerY + h, 1.0f, 0.0f, 1.0f, 0.0f},
            {playerX - w/2, playerY + h, 0.0f, 0.0f, 1.0f, 0.0f}
        };
        glVertexAttribPointer(posLoc, 2, GL_FLOAT, GL_FALSE, stride, &pVerts[0].x);
        glVertexAttribPointer(texLoc, 2, GL_FLOAT, GL_FALSE, stride, &pVerts[0].u);
        if(brightLoc >= 0) glVertexAttribPointer(brightLoc, 1, GL_FLOAT, GL_FALSE, stride, &pVerts[0].brightness);
        if(dmgLoc >= 0) glVertexAttribPointer(dmgLoc, 1, GL_FLOAT, GL_FALSE, stride, &pVerts[0].damage);
        glDrawArrays(GL_TRIANGLES, 0, 6);
    }
    
    // --- Draw Drop Items ---
    if (itemsTexID != 0 && !dropItems.empty()) {
        glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, itemsTexID);
        glActiveTexture(GL_TEXTURE1); glBindTexture(GL_TEXTURE_2D, itemsTexID);
        glActiveTexture(GL_TEXTURE2); glBindTexture(GL_TEXTURE_2D, 0);
        
        for (const auto& item : dropItems) {
            float w = 0.1f, h = 0.1f;
            // Simple UV mapping for test: just use the first icon (0,0) -> (1/16, 1/16)
            // Real logic needs to map item.type to UV
            float u0 = 0.0f, v0 = 0.0f;
            float u1 = 1.0f/16.0f, v1 = 1.0f/16.0f;
            
            Vertex iVerts[] = {
                {item.x - w/2, item.y,       u0, v1, 1.0f, 0.0f},
                {item.x + w/2, item.y,       u1, v1, 1.0f, 0.0f},
                {item.x - w/2, item.y + h,   u0, v0, 1.0f, 0.0f},
                {item.x + w/2, item.y,       u1, v1, 1.0f, 0.0f},
                {item.x + w/2, item.y + h,   u1, v0, 1.0f, 0.0f},
                {item.x - w/2, item.y + h,   u0, v0, 1.0f, 0.0f}
            };
            
            glVertexAttribPointer(posLoc, 2, GL_FLOAT, GL_FALSE, stride, &iVerts[0].x);
            glVertexAttribPointer(texLoc, 2, GL_FLOAT, GL_FALSE, stride, &iVerts[0].u);
            if(brightLoc >= 0) glVertexAttribPointer(brightLoc, 1, GL_FLOAT, GL_FALSE, stride, &iVerts[0].brightness);
            if(dmgLoc >= 0) glVertexAttribPointer(dmgLoc, 1, GL_FLOAT, GL_FALSE, stride, &iVerts[0].damage);
            
            glDrawArrays(GL_TRIANGLES, 0, 6);
        }
    }
    
    glBindBuffer(GL_ARRAY_BUFFER, 0);
}

extern "C" JNIEXPORT void JNICALL
Java_com_noodlecake_blockheads_rebuild_GameActivity_onSurfaceCreatedNative(JNIEnv* env, jobject obj, jobject assetMgr) {
    g_renderer = new WorldRenderer();
    g_renderer->init(AAssetManager_fromJava(env, assetMgr));
}