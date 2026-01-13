#include "world_renderer.h"
#include <android/asset_manager_jni.h>
#include <android/log.h>
#include <cmath>
#include <algorithm>
#include "matrix_utils.h"

#define STB_IMAGE_IMPLEMENTATION
#include "external/stb_image.h"

#undef LOG_TAG
#define LOG_TAG "BlockheadsRenderer"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

WorldRenderer* g_renderer = nullptr;

char* WorldRenderer::loadShaderSource(AAssetManager* mgr, const char* name) {
    AAsset* asset = AAssetManager_open(mgr, name, AASSET_MODE_BUFFER);
    if (!asset) return nullptr;
    off_t size = AAsset_getLength(asset);
    char* buf = (char*)malloc(size + 1);
    AAsset_read(asset, buf, size);
    buf[size] = '\0';
    AAsset_close(asset);
    return buf;
}

void WorldRenderer::init(AAssetManager* mgr) {
    textureID = loadTex(mgr, "TileMap.png");
    destructID = loadTex(mgr, "TileDestruct.png");
    normalID = loadTex(mgr, "ItemNormals.png");
    itemsTexID = loadTex(mgr, "Items.png");
    
    char* vSource = loadShaderSource(mgr, "Block.vsh");
    char* fSource = loadShaderSource(mgr, "Block.fsh");
    
    if (vSource && fSource) {
        program = createProgram(vSource, fSource);
        free(vSource); free(fSource);
    } else {
        LOGE("Critical Error: Failed to load original shaders Block.vsh/fsh");
    }

    uMatrix = glGetUniformLocation(program, "mvp_matrix");
    
    headTexID = loadTex(mgr, "head_ct.png");
    bodyTexID = loadTex(mgr, "body_ct.png");
    armsTexID = loadTex(mgr, "arms_ct.png");
    legsTexID = loadTex(mgr, "legs_ct.png");
}

void WorldRenderer::resize(int w, int h) {
    screenW = w;
    screenH = h;
    glViewport(0, 0, w, h);
}

GLuint WorldRenderer::loadTex(AAssetManager* mgr, const char* name) {
    AAsset* asset = AAssetManager_open(mgr, name, AASSET_MODE_BUFFER);
    if(!asset) {
        LOGE("!!! CRITICAL: Asset NOT FOUND in APK: %s", name);
        return 0;
    }
    int w, h, n;
    unsigned char* d = stbi_load_from_memory((unsigned char*)AAsset_getBuffer(asset), AAsset_getLength(asset), &w, &h, &n, 4);
    if(!d) {
        LOGE("!!! CRITICAL: stbi_load FAILED for: %s", name);
        AAsset_close(asset);
        return 0;
    }
    
    // Validate data
    LOGE("SUCCESS: %s (%dx%d) Pixel0: R:%d G:%d B:%d A:%d", name, w, h, d[0], d[1], d[2], d[3]);

    GLuint id;
    glGenTextures(1, &id);
    glBindTexture(GL_TEXTURE_2D, id);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, d);
    
    glGenerateMipmap(GL_TEXTURE_2D);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR);
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

void WorldRenderer::pushBlock(std::vector<Vertex>& buffer, float x, float y, int type, float damage, float sun, float art) {
    if (type == 0) return;
    
    int idx = type - 1;
    float tx = (float)(idx % 32); 
    float ty = (float)(idx / 32);
    float s = 1.0f;
    
    auto pushV = [&](float vx, float vy, uint8_t vu, uint8_t vv) {
        Vertex v_out;
        v_out.x = vx; v_out.y = vy; v_out.z = 0.0f; v_out.w = tx;
        v_out.u = vu; v_out.v = vv; v_out.s = (uint8_t)art; v_out.t = 0;
        v_out.otherX = 0; v_out.otherY = 0; v_out.otherZ = ty; v_out.otherW = 0;
        v_out.r = 255; v_out.g = 255; v_out.b = 255; v_out.a = (uint8_t)damage;
        buffer.push_back(v_out);
    };

    pushV(x,   y,   0,   255);
    pushV(x+s, y,   255, 255);
    pushV(x,   y+s, 0,   0);
    pushV(x+s, y,   255, 255);
    pushV(x+s, y+s, 255, 0);
    pushV(x,   y+s, 0,   0);
}

void WorldRenderer::updateMesh(const std::vector<PhysicalBlock*>& chunks) {
    std::lock_guard<std::mutex> lock(meshMutex);
    
    for (PhysicalBlock* chunk : chunks) {
        if (!chunk || !chunk->meshReady) continue;

        ChunkRenderData* data = nullptr;
        for (auto& m : chunkMeshes) {
            if (m.cx == chunk->x && m.cy == chunk->y) {
                data = &m;
                break;
            }
        }

        if (!data) {
            chunkMeshes.push_back(ChunkRenderData());
            data = &chunkMeshes.back();
            data->cx = chunk->x;
            data->cy = chunk->y;
            glGenBuffers(1, &data->vbo);
        }

        {
            std::lock_guard<std::mutex> dataLock(chunk->dataMutex);
            glBindBuffer(GL_ARRAY_BUFFER, data->vbo);
            glBufferData(GL_ARRAY_BUFFER, chunk->vertexCache.size() * sizeof(float), chunk->vertexCache.data(), GL_STATIC_DRAW);
            data->vertexCount = chunk->vertexCache.size() / 16; 
        }
        
        data->active = (data->vertexCount > 0);
        chunk->meshReady = false; 
    }
}

void WorldRenderer::renderFrame() {
    animTime += 0.05f; 
    worldTime += 0.0001f; 
    if (worldTime > 1.0f) worldTime = 0;

    camX += (targetX - camX) * 0.1f;
    camY += (targetY - camY) * 0.1f;

    float sunPower = std::sin(worldTime * 3.14159f); 
    if (sunPower < 0) sunPower = 0;

    float skyR = 0.2f + sunPower * 0.2f;
    float skyG = 0.4f + sunPower * 0.3f;
    float skyB = 0.6f + sunPower * 0.2f;
    
    glClearColor(skyR, skyG, skyB, 1.0f); 
    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    glEnable(GL_DEPTH_TEST);
    glDepthFunc(GL_LEQUAL);
    glUseProgram(program);
    
    // Refresh matrix uniform location
    uMatrix = glGetUniformLocation(program, "mvp_matrix");
    
    // Bind Textures
    glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, textureID);
    glUniform1i(glGetUniformLocation(program, "texture"), 0);
    
    glActiveTexture(GL_TEXTURE1); glBindTexture(GL_TEXTURE_2D, destructID);
    glUniform1i(glGetUniformLocation(program, "destruct_texture"), 1);
    
    static GLuint whiteTex = 0;
    if (whiteTex == 0) {
        uint32_t p = 0xFFFFFFFF;
        glGenTextures(1, &whiteTex);
        glBindTexture(GL_TEXTURE_2D, whiteTex);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 1, 1, 0, GL_RGBA, GL_UNSIGNED_BYTE, &p);
    }
    glActiveTexture(GL_TEXTURE2); glBindTexture(GL_TEXTURE_2D, whiteTex);
    glUniform1i(glGetUniformLocation(program, "light_texture"), 2);

    // Daylight vector according to original shader expectations
    glUniform4f(glGetUniformLocation(program, "daylight"), 1.0f, 1.0f, 1.0f, 1.0f);
    glUniform4f(glGetUniformLocation(program, "lightPosition"), camX, camY + 20.0f, 5.0f, 1.0f);

    float matrix[16];
    float aspect = (float)screenW / (float)screenH;
    float h_cam = 10.0f * camZoom; 
    float w_cam = h_cam * aspect;
    Matrix::ortho(matrix, -w_cam, w_cam, -h_cam, h_cam, -10.0f, 10.0f);
    Matrix::translate(matrix, -camX, -camY, 0);
    glUniformMatrix4fv(uMatrix, 1, GL_FALSE, matrix);
    
    GLint posLoc = glGetAttribLocation(program, "position");
    GLint texLoc = glGetAttribLocation(program, "texCoord");
    GLint otherLoc = glGetAttribLocation(program, "other");
    GLint paintLoc = glGetAttribLocation(program, "paintColor");
    
    glEnableVertexAttribArray(posLoc);
    glEnableVertexAttribArray(texLoc);
    glEnableVertexAttribArray(otherLoc);
    glEnableVertexAttribArray(paintLoc);

    int stride = 16 * sizeof(float);

    if (menuMode) {
        if (bodyTexID != 0) {
            float breath = std::sin(animTime * 2.0f) * 0.05f;
            float scale = 8.0f; 
            float m_menu[16];
            Matrix::ortho(m_menu, -aspect, aspect, -1.0f, 1.0f, -1.0f, 1.0f);
            
            auto drawM = [&](GLuint tex, float dx, float dy, float pw, float ph) {
                glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, tex);
                float m_part[16]; std::copy(m_menu, m_menu + 16, m_part);
                Matrix::translate(m_part, -aspect * 0.5f + dx, -0.7f + dy + breath, 0);
                Matrix::scale(m_part, scale, scale, 1.0f);
                glUniformMatrix4fv(uMatrix, 1, GL_FALSE, m_part);
                
                float w2 = pw/2, h2 = ph/2;
                float pV[] = {
                    -w2, -h2, 0, 0,  0, 255, 255, 0,  255, 0, 0, 0,  1, 1, 1, 1,
                     w2, -h2, 0, 0,  255, 255, 255, 0,  255, 0, 0, 0,  1, 1, 1, 1,
                    -w2,  h2, 0, 0,  0, 0, 255, 0,  255, 0, 0, 0,  1, 1, 1, 1,
                     w2, -h2, 0, 0,  255, 255, 255, 0,  255, 0, 0, 0,  1, 1, 1, 1,
                     w2,  h2, 0, 0,  255, 0, 255, 0,  255, 0, 0, 0,  1, 1, 1, 1,
                    -w2,  h2, 0, 0,  0, 0, 255, 0,  255, 0, 0, 0,  1, 1, 1, 1
                };
                glBindBuffer(GL_ARRAY_BUFFER, 0);
                glVertexAttribPointer(posLoc, 4, GL_FLOAT, GL_FALSE, stride, &pV[0]);
                glVertexAttribPointer(texLoc, 4, GL_FLOAT, GL_FALSE, stride, &pV[4]);
                glVertexAttribPointer(otherLoc, 4, GL_FLOAT, GL_FALSE, stride, &pV[8]);
                glVertexAttribPointer(paintLoc, 4, GL_FLOAT, GL_FALSE, stride, &pV[12]);
                glDrawArrays(GL_TRIANGLES, 0, 6);
            };
            drawM(bodyTexID, 0, 0.15f, 0.15f, 0.25f);
            drawM(headTexID, 0, 0.35f, 0.12f, 0.12f);
        }
        return; 
    }

    {
        std::lock_guard<std::mutex> lock(meshMutex);
        totalVertexCount = 0;
        for (const auto& m : chunkMeshes) {
            if (!m.active) continue;

            float cw = (float)CHUNK_SIZE;
            if (m.cx * cw + cw < camX - w_cam || m.cx * cw > camX + w_cam ||
                m.cy * cw + cw < camY - h_cam || m.cy * cw > camY + h_cam) {
                continue; 
            }

            glBindBuffer(GL_ARRAY_BUFFER, m.vbo);
            glVertexAttribPointer(posLoc, 4, GL_FLOAT, GL_FALSE, stride, (void*)0);
            glVertexAttribPointer(texLoc, 4, GL_FLOAT, GL_FALSE, stride, (void*)(4 * sizeof(float)));
            glVertexAttribPointer(otherLoc, 4, GL_FLOAT, GL_FALSE, stride, (void*)(8 * sizeof(float)));
            glVertexAttribPointer(paintLoc, 4, GL_FLOAT, GL_FALSE, stride, (void*)(12 * sizeof(float)));
            
            glDrawArrays(GL_TRIANGLES, 0, m.vertexCount);
            totalVertexCount += m.vertexCount;
        }
    }

    // --- Draw ActionSquare (Original Logic) ---
    if (showActionSquare && actionSquareProgram != 0) {
        glUseProgram(actionSquareProgram);
        glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, actionSquareTexID);
        glUniform1i(glGetUniformLocation(actionSquareProgram, "texture"), 0);
        
        float pulse = 0.7f + std::sin(animTime * 15.0f) * 0.3f;
        glUniform4f(glGetUniformLocation(actionSquareProgram, "light"), pulse, pulse, pulse, 1.0f);
        
        float m_sq[16];
        std::copy(matrix, matrix + 16, m_sq);
        // Slightly larger than block (1.1x) and offset to center
        float s_ext = 1.1f;
        float offset = -0.05f;
        Matrix::translate(m_sq, (float)targetBlockX + offset, (float)targetBlockY + offset, 0.2f);
        glUniformMatrix4fv(glGetUniformLocation(actionSquareProgram, "mvp_matrix"), 1, GL_FALSE, m_sq);

        float sqVerts[] = {
            0,     0,     0, 1,  0, 1,
            s_ext, 0,     0, 1,  1, 1,
            0,     s_ext, 0, 1,  0, 0,
            s_ext, 0,     0, 1,  1, 1,
            s_ext, s_ext, 0, 1,  1, 0,
            0,     s_ext, 0, 1,  0, 0
        };
        GLint pL = glGetAttribLocation(actionSquareProgram, "position");
        GLint tL = glGetAttribLocation(actionSquareProgram, "texCoord");
        glEnableVertexAttribArray(pL);
        glEnableVertexAttribArray(tL);
        glVertexAttribPointer(pL, 4, GL_FLOAT, GL_FALSE, 6 * sizeof(float), &sqVerts[0]);
        glVertexAttribPointer(tL, 2, GL_FLOAT, GL_FALSE, 6 * sizeof(float), &sqVerts[4]);
                glDrawArrays(GL_TRIANGLES, 0, 6);
            }
            
            glBindBuffer(GL_ARRAY_BUFFER, 0);
        }
        