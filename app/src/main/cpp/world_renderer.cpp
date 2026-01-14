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
    
    char* cVSource = loadShaderSource(mgr, "BlockheadBody.vsh");
    char* cFSource = loadShaderSource(mgr, "BlockheadBody.fsh");
    if (cVSource && cFSource) {
        charProgram = createProgram(cVSource, cFSource);
        free(cVSource); free(cFSource);
    }

    actionSquareTexID = loadTex(mgr, "actionSquare.png");

    char* asVSource = loadShaderSource(mgr, "ActionSquare.vsh");
    char* asFSource = loadShaderSource(mgr, "ActionSquare.fsh");
    if (asVSource && asFSource) {
        actionSquareProgram = createProgram(asVSource, asFSource);
        free(asVSource); free(asFSource);
    }

    headTexID = loadTex(mgr, "head_ct.png");
    bodyTexID = loadTex(mgr, "body_ct.png");
    armsTexID = loadTex(mgr, "arms_ct.png");
    legsTexID = loadTex(mgr, "legs_ct.png");
    dodoBodyTexID = loadTex(mgr, "dodoBody.png");
    dodoHeadTexID = loadTex(mgr, "dodoHead.png");
    dodoLegTexID = loadTex(mgr, "dodoLeg.png");

    // --- DEBUG SHADER (Inline) ---
    const char* debugVS = 
        "attribute vec4 position;\n"
        "attribute vec2 texCoord;\n"
        "varying vec2 v_texCoord;\n"
        "uniform mat4 mvp_matrix;\n"
        "void main() {\n"
        "  gl_Position = mvp_matrix * position;\n"
        "  v_texCoord = texCoord;\n"
        "}\n";
    const char* debugFS = 
        "precision mediump float;\n"
        "varying vec2 v_texCoord;\n"
        "uniform sampler2D texture;\n"
        "void main() {\n"
        "  gl_FragColor = texture2D(texture, v_texCoord);\n"
        "  if(gl_FragColor.a < 0.1) discard;\n"
        "}\n";
    debugProgram = createProgram(debugVS, debugFS);
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
    
    int texRow = 0, texCol = 0;
    if (type == ITEM_DIRT) { texRow = 0; texCol = 0; }
    else if (type == ITEM_STONE) { texRow = 0; texCol = 1; }
    else if (type == BLOCK_WOOD) { texRow = 0; texCol = 2; }
    else if (type == BLOCK_LEAVES) { texRow = 0; texCol = 3; }
    else if (type == BLOCK_GRASS) { texRow = 0; texCol = 4; }
    else if (type == BLOCK_SAND) { texRow = 1; texCol = 0; }
    else if (type == ITEM_COPPER_ORE) { texRow = 1; texCol = 1; }
    else if (type == ITEM_TIN_ORE) { texRow = 1; texCol = 2; }
    else if (type == BLOCK_SNOW) { texRow = 1; texCol = 3; }
    else if (type == BLOCK_ICE) { texRow = 1; texCol = 4; }
    else if (type == BLOCK_CACTUS) { texRow = 1; texCol = 5; }
    else if (type == BLOCK_GLASS) { texRow = 1; texCol = 6; }
    else if (type == ITEM_WORKBENCH) { texRow = 2; texCol = 0; }
    else if (type == ITEM_TOOLBENCH) { texRow = 2; texCol = 1; }
    else if (type == ITEM_TORCH) { texRow = 3; texCol = 0; }
    else {
        texCol = (type - 1) % 32;
        texRow = (type - 1) / 32;
    }

    float tx = (float)texCol;
    float ty = (float)texRow;
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
        if (bodyTexID != 0 && charProgram != 0) {
            glUseProgram(charProgram);
            float breath = std::sin(animTime * 2.0f) * 0.05f;
            
            // --- FINAL ADJUSTMENT SETTINGS ---
            // Scale 0.35 should be ~1/3 of screen height (assuming ortho height is 2.0)
            float scale = 0.35f;
            // Position: -aspect is left edge, -1.0 is bottom edge
            // Moving up (-0.5) and right (+0.6)
            float baseX = -aspect + 0.6f; 
            float baseY = -0.5f;
            
            static bool logged = false;
            if(!logged) {
                LOGE("RenderChar: FINAL ADJUSTMENT - Scale: %f, Pos: %f,%f", scale, baseX, baseY);
                logged = true;
            }

            float m_menu[16];
            Matrix::ortho(m_menu, -aspect, aspect, -1.0f, 1.0f, -1.0f, 1.0f);

            // High ambient light for menu display
            glUniform4f(glGetUniformLocation(charProgram, "daylight"), 1.2f, 1.2f, 1.2f, 1.0f);
            glUniform4f(glGetUniformLocation(charProgram, "artificalLight"), 0.5f, 0.5f, 0.5f, 1.0f);
            glUniform4f(glGetUniformLocation(charProgram, "skinColor"), 1.0f, 0.85f, 0.7f, 1.0f);
            glUniform4f(glGetUniformLocation(charProgram, "clothingColorA"), 1.0f, 1.0f, 1.0f, 1.0f);
            glUniform4f(glGetUniformLocation(charProgram, "clothingColorB"), 0.9f, 0.9f, 0.9f, 1.0f);
            glUniform3f(glGetUniformLocation(charProgram, "artificialLightDirection"), 0.5f, 0.5f, 1.0f);
            glUniform4f(glGetUniformLocation(charProgram, "lightPosition"), 0.0f, 0.0f, 10.0f, 1.0f);

            // Helper to draw a cube (w, h, d)
            auto drawCube = [&](GLuint tex, float x, float y, float z, float w, float h, float d, float u1, float v1, float u2, float v2) {
                glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, tex);
                glUniform1i(glGetUniformLocation(charProgram, "texture"), 0);

                float m_part[16]; std::copy(m_menu, m_menu + 16, m_part);
                
                Matrix::translate(m_part, baseX + x, baseY + y + breath, 0.5f + z);
                Matrix::scale(m_part, scale * w, scale * h, scale * d); 
                glUniformMatrix4fv(glGetUniformLocation(charProgram, "mvp_matrix"), 1, GL_FALSE, m_part);
                
                // Normal matrix
                float m_norm[16]; 
                m_norm[0]=1; m_norm[1]=0; m_norm[2]=0; m_norm[3]=0;
                m_norm[4]=0; m_norm[5]=1; m_norm[6]=0; m_norm[7]=0;
                m_norm[8]=0; m_norm[9]=0; m_norm[10]=1; m_norm[11]=0;
                m_norm[12]=0; m_norm[13]=0; m_norm[14]=0; m_norm[15]=1;
                glUniformMatrix4fv(glGetUniformLocation(charProgram, "normal_matrix"), 1, GL_FALSE, m_norm);

                // Front Face (Normal 0,0,1)
                float pV[] = {
                    -0.5f, -0.5f, 0.5f,  u1, v2,  0, 0, 1,
                     0.5f, -0.5f, 0.5f,  u2, v2,  0, 0, 1,
                    -0.5f,  0.5f, 0.5f,  u1, v1,  0, 0, 1,
                     0.5f, -0.5f, 0.5f,  u2, v2,  0, 0, 1,
                     0.5f,  0.5f, 0.5f,  u2, v1,  0, 0, 1,
                    -0.5f,  0.5f, 0.5f,  u1, v1,  0, 0, 1
                };

                GLint pLoc = glGetAttribLocation(charProgram, "position");
                GLint tLoc = glGetAttribLocation(charProgram, "texCoord");
                GLint nLoc = glGetAttribLocation(charProgram, "normal");
                glEnableVertexAttribArray(pLoc);
                glEnableVertexAttribArray(tLoc);
                glEnableVertexAttribArray(nLoc);
                
                glVertexAttribPointer(pLoc, 3, GL_FLOAT, GL_FALSE, 8 * sizeof(float), &pV[0]);
                glVertexAttribPointer(tLoc, 2, GL_FLOAT, GL_FALSE, 8 * sizeof(float), &pV[3]);
                glVertexAttribPointer(nLoc, 3, GL_FLOAT, GL_FALSE, 8 * sizeof(float), &pV[5]);
                
                glDrawArrays(GL_TRIANGLES, 0, 6);
            };

            // Draw Body (Center)
            drawCube(bodyTexID, 0.0f, 0.0f, 0.0f, 0.15f, 0.25f, 0.1f, 0.0f, 0.0f, 1.0f, 1.0f);
            
            // Draw Head (Top)
            float lookX = (menuTouchX / (float)screenW) * 2.0f - 1.0f;
            float lookY = 1.0f - (menuTouchY / (float)screenH) * 2.0f;
            
            // Calculate rotations based on look target (simple clamping for natural feel)
            float headYaw = lookX * 45.0f; // Max 45 degrees left/right
            float headPitch = lookY * 30.0f; // Max 30 degrees up/down

            auto drawHead = [&](GLuint tex, float x, float y, float z, float w, float h, float d, float u1, float v1, float u2, float v2) {
                glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, tex);
                glUniform1i(glGetUniformLocation(charProgram, "texture"), 0);

                float m_part[16]; std::copy(m_menu, m_menu + 16, m_part);
                Matrix::translate(m_part, baseX + x, baseY + y + breath, 0.5f + z);
                
                // Apply look rotation
                Matrix::rotate(m_part, headYaw, 0, 1, 0);
                Matrix::rotate(m_part, -headPitch, 1, 0, 0);

                Matrix::scale(m_part, scale * w, scale * h, scale * d); 
                glUniformMatrix4fv(glGetUniformLocation(charProgram, "mvp_matrix"), 1, GL_FALSE, m_part);
                
                float m_norm[16]; Matrix::setIdentity(m_norm);
                glUniformMatrix4fv(glGetUniformLocation(charProgram, "normal_matrix"), 1, GL_FALSE, m_norm);

                float pV[] = { -0.5f,-0.5f,0.5f, u1,v2, 0,0,1, 0.5f,-0.5f,0.5f, u2,v2, 0,0,1, -0.5f,0.5f,0.5f, u1,v1, 0,0,1,
                                0.5f,-0.5f,0.5f, u2,v2, 0,0,1, 0.5f,0.5f,0.5f, u2,v1, 0,0,1, -0.5f,0.5f,0.5f, u1,v1, 0,0,1 };
                glVertexAttribPointer(glGetAttribLocation(charProgram, "position"), 3, GL_FLOAT, GL_FALSE, 8*sizeof(float), &pV[0]);
                glVertexAttribPointer(glGetAttribLocation(charProgram, "texCoord"), 2, GL_FLOAT, GL_FALSE, 8*sizeof(float), &pV[3]);
                glVertexAttribPointer(glGetAttribLocation(charProgram, "normal"), 3, GL_FLOAT, GL_FALSE, 8*sizeof(float), &pV[5]);
                glDrawArrays(GL_TRIANGLES, 0, 6);
            };

            drawHead(headTexID, 0.0f, 0.22f, 0.0f, 0.18f, 0.18f, 0.18f, 0.25f, 0.5f, 0.5f, 1.0f);

            // Draw Legs (Bottom)
            drawCube(legsTexID, -0.05f, -0.25f, 0.0f, 0.05f, 0.25f, 0.05f, 0.0f, 0.0f, 1.0f, 1.0f);
            drawCube(legsTexID,  0.05f, -0.25f, 0.0f, 0.05f, 0.25f, 0.05f, 0.0f, 0.0f, 1.0f, 1.0f);

            // Draw Arms (Sides)
            float armSwing = std::sin(animTime * 3.0f) * 0.1f;
            drawCube(armsTexID, -0.13f, 0.0f + armSwing, 0.0f, 0.05f, 0.25f, 0.05f, 0.0f, 0.0f, 1.0f, 1.0f);
            drawCube(armsTexID,  0.13f, 0.0f - armSwing, 0.0f, 0.05f, 0.25f, 0.05f, 0.0f, 0.0f, 1.0f, 1.0f);
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

    // --- Render Player Character (In Game) ---
    if (charProgram != 0 && bodyTexID != 0) {
        glUseProgram(charProgram);
        glUniform4f(glGetUniformLocation(charProgram, "daylight"), 1.0f, 1.0f, 1.0f, 1.0f);
        glUniform4f(glGetUniformLocation(charProgram, "skinColor"), 1.0f, 0.85f, 0.7f, 1.0f);
        glUniform4f(glGetUniformLocation(charProgram, "clothingColorA"), 1.0f, 1.0f, 1.0f, 1.0f);
        glUniform4f(glGetUniformLocation(charProgram, "clothingColorB"), 0.9f, 0.9f, 0.9f, 1.0f);
        glUniform3f(glGetUniformLocation(charProgram, "artificialLightDirection"), 0.5f, 0.5f, 1.0f);
        
        // Helper to draw a cube (same as menu but with game matrix)
        auto drawCharCube = [&](GLuint tex, float x, float y, float z, float w, float h, float d, float u1, float v1, float u2, float v2) {
            glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, tex);
            glUniform1i(glGetUniformLocation(charProgram, "texture"), 0);

            float m_part[16]; std::copy(matrix, matrix + 16, m_part);
            Matrix::translate(m_part, playerX + x, playerY + y + 0.5f, z);
            Matrix::scale(m_part, w, h, d); 
            glUniformMatrix4fv(glGetUniformLocation(charProgram, "mvp_matrix"), 1, GL_FALSE, m_part);
            
            float m_norm[16]; Matrix::setIdentity(m_norm);
            glUniformMatrix4fv(glGetUniformLocation(charProgram, "normal_matrix"), 1, GL_FALSE, m_norm);

            float pV[] = { -0.5f,-0.5f,0.5f, u1,v2, 0,0,1, 0.5f,-0.5f,0.5f, u2,v2, 0,0,1, -0.5f,0.5f,0.5f, u1,v1, 0,0,1,
                            0.5f,-0.5f,0.5f, u2,v2, 0,0,1, 0.5f,0.5f,0.5f, u2,v1, 0,0,1, -0.5f,0.5f,0.5f, u1,v1, 0,0,1 };
            glVertexAttribPointer(glGetAttribLocation(charProgram, "position"), 3, GL_FLOAT, GL_FALSE, 8*sizeof(float), &pV[0]);
            glVertexAttribPointer(glGetAttribLocation(charProgram, "texCoord"), 2, GL_FLOAT, GL_FALSE, 8*sizeof(float), &pV[3]);
            glVertexAttribPointer(glGetAttribLocation(charProgram, "normal"), 3, GL_FLOAT, GL_FALSE, 8*sizeof(float), &pV[5]);
            glEnableVertexAttribArray(glGetAttribLocation(charProgram, "position"));
            glEnableVertexAttribArray(glGetAttribLocation(charProgram, "texCoord"));
            glEnableVertexAttribArray(glGetAttribLocation(charProgram, "normal"));
            glDrawArrays(GL_TRIANGLES, 0, 6);
        };

        // Render character with walking animation in game
        float walkAnim = std::sin(animTime * 10.0f);
        
        // Body
        drawCharCube(bodyTexID, 0, 0.25f, 0, 0.4f, 0.6f, 0.2f, 0, 0, 1, 1);
        // Head
        drawCharCube(headTexID, 0, 0.75f, 0, 0.5f, 0.5f, 0.5f, 0.25f, 0.5f, 0.5f, 1.0f);
        // Legs
        drawCharCube(legsTexID, -0.1f, -0.2f + (walkAnim > 0 ? walkAnim*0.1f : 0), 0, 0.15f, 0.5f, 0.15f, 0, 0, 1, 1);
        drawCharCube(legsTexID,  0.1f, -0.2f + (walkAnim < 0 ? -walkAnim*0.1f : 0), 0, 0.15f, 0.5f, 0.15f, 0, 0, 1, 1);
        // Arms
        drawCharCube(armsTexID, -0.25f, 0.25f, 0, 0.12f, 0.5f, 0.12f, 0, 0, 1, 1);
        drawCharCube(armsTexID,  0.25f, 0.25f, 0, 0.12f, 0.5f, 0.12f, 0, 0, 1, 1);
    }

    // --- Render Mobs ---
    if (charProgram != 0 && dodoBodyTexID != 0) {
        glUseProgram(charProgram);
        // Reuse uniforms from player render (light etc is global-ish)
        
        auto drawMobPart = [&](GLuint tex, float mx, float my, float x, float y, float z, float w, float h, float d) {
            glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, tex);
            glUniform1i(glGetUniformLocation(charProgram, "texture"), 0);
            float m_part[16]; std::copy(matrix, matrix + 16, m_part);
            Matrix::translate(m_part, mx + x, my + y, z);
            Matrix::scale(m_part, w, h, d); 
            glUniformMatrix4fv(glGetUniformLocation(charProgram, "mvp_matrix"), 1, GL_FALSE, m_part);
            float m_norm[16]; Matrix::setIdentity(m_norm);
            glUniformMatrix4fv(glGetUniformLocation(charProgram, "normal_matrix"), 1, GL_FALSE, m_norm);
            float pV[] = { -0.5f,-0.5f,0.5f, 0,1, 0,0,1, 0.5f,-0.5f,0.5f, 1,1, 0,0,1, -0.5f,0.5f,0.5f, 0,0, 0,0,1,
                            0.5f,-0.5f,0.5f, 1,1, 0,0,1, 0.5f,0.5f,0.5f, 1,0, 0,0,1, -0.5f,0.5f,0.5f, 0,0, 0,0,1 };
            glVertexAttribPointer(glGetAttribLocation(charProgram, "position"), 3, GL_FLOAT, GL_FALSE, 8*sizeof(float), &pV[0]);
            glVertexAttribPointer(glGetAttribLocation(charProgram, "texCoord"), 2, GL_FLOAT, GL_FALSE, 8*sizeof(float), &pV[3]);
            glVertexAttribPointer(glGetAttribLocation(charProgram, "normal"), 3, GL_FLOAT, GL_FALSE, 8*sizeof(float), &pV[5]);
            glDrawArrays(GL_TRIANGLES, 0, 6);
        };

        for (const auto& mob : mobs) {
            if (mob.type == ENTITY_DODO) {
                float wAnim = std::sin(animTime * 15.0f + mob.x * 10.0f);
                // Body
                drawMobPart(dodoBodyTexID, mob.x, mob.y + 0.3f, 0, 0, 0, 0.4f, 0.3f, 0.2f);
                // Head
                drawMobPart(dodoHeadTexID, mob.x, mob.y + 0.3f, 0.25f, 0.2f, 0, 0.2f, 0.2f, 0.2f);
                // Legs
                drawMobPart(dodoLegTexID, mob.x, mob.y + 0.3f, -0.05f, -0.2f + (wAnim>0?wAnim*0.1f:0), 0, 0.05f, 0.2f, 0.05f);
                drawMobPart(dodoLegTexID, mob.x, mob.y + 0.3f, 0.05f, -0.2f + (wAnim<0?-wAnim*0.1f:0), 0, 0.05f, 0.2f, 0.05f);
            }
        }
    }

    // --- Render Drop Items ---
    if (program != 0 && itemsTexID != 0) {
        glUseProgram(program);
        glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, itemsTexID);
        for (const auto& item : dropItems) {
            float m_item[16]; std::copy(matrix, matrix + 16, m_item);
            Matrix::translate(m_item, item.x, item.y + 0.2f, 0.1f);
            Matrix::scale(m_item, 0.4f, 0.4f, 1.0f);
            glUniformMatrix4fv(uMatrix, 1, GL_FALSE, m_item);
            
            float itX = (float)((item.type - 1) % 32);
            float itY = (float)((item.type - 1) / 32);
            glUniform4f(glGetAttribLocation(program, "other"), 0, 0, itY, 0); // Hacky pass of UV Y

            float iV[] = { 0,0, itX, 1, 1,0, itX, 1, 0,1, itX, 1, 1,0, itX, 1, 1,1, itX, 1, 0,1, itX, 1 };
            glVertexAttribPointer(posLoc, 2, GL_FLOAT, GL_FALSE, 4*sizeof(float), &iV[0]);
            glVertexAttribPointer(texLoc, 2, GL_FLOAT, GL_FALSE, 4*sizeof(float), &iV[2]);
            glDrawArrays(GL_TRIANGLES, 0, 6);
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
        GLint asMatrix = glGetUniformLocation(actionSquareProgram, "mvp_matrix");
        glUniformMatrix4fv(asMatrix, 1, GL_FALSE, m_sq);

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