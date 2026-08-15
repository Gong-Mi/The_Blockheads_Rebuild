#include "world_renderer.h"
#include "item_manager.h"
#include "crafting_manager.h"
#include <GLES2/gl2.h>

extern CraftingManager* g_crafting;
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
    if (size <= 0 || size > 1024 * 1024) { // Max 1MB
        AAsset_close(asset);
        return nullptr;
    }
    char* buf = (char*)malloc(size + 1);
    if (!buf) {
        AAsset_close(asset);
        return nullptr;
    }
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

    char* itemVSource = loadShaderSource(mgr, "Item.vsh");
    char* itemFSource = loadShaderSource(mgr, "Item.fsh");
    if (itemVSource && itemFSource) {
        itemProgram = createProgram(itemVSource, itemFSource);
        free(itemVSource); free(itemFSource);
    } else {
        LOGE("Critical Error: Failed to load original shaders Item.vsh/fsh");
    }
    
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
    yakBodyTexID = loadTex(mgr, "yakBody.png");
    yakHeadTexID = loadTex(mgr, "yakHead.png");
    yakLegTexID = loadTex(mgr, "yakLegs.png");
    // The native DropBear class uses the grizrat-named sprite family in the
    // 1.7.6 APK. There are no dropbearBody.png/dropbearHead.png entries.
    dropbearBodyTexID = loadTex(mgr, "grizratBodyFront.png");
    dropbearHeadTexID = loadTex(mgr, "grizratHead.png");
    
    clothingTex[0] = loadTex(mgr, "clothing0.png");
    clothingTex[1] = loadTex(mgr, "clothing1.png");
    clothingTex[2] = loadTex(mgr, "clothing2.png");
    clothingTex[3] = loadTex(mgr, "clothing3.png");

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
    
    // The original asset set contains NPOT UI textures.  Do not select a
    // mipmapped minification filter without a complete mip chain: GLES2 then
    // treats the texture as incomplete and samples transparent/black data.
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    
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
    auto def = ItemManager::getInstance().getDef(type);
    if (def) {
        texRow = def->texRow;
        texCol = def->texCol;
    } else {
        LOGE("No atlas definition for block/item id %d; refusing guessed coordinates", type);
        return;
    }

    float tx = (float)texCol;
    float ty = (float)texRow;    float s = 1.0f;
    
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

            // Scan for emitters
            data->emitters.clear();
            for(int i=0; i<32*32; i++) {
                int type = chunk->tiles[i].foreground;
                if (type == 23 || type == 16) { // ITEM_CAMPFIRE(23), ITEM_FURNACE(16)
                    Emitter e;
                    e.x = i % 32;
                    e.y = i / 32;
                    e.type = type;
                    data->emitters.push_back(e);
                }
            }
        }
        
        data->active = (data->vertexCount > 0);
        chunk->meshReady = false; 
    }
}

void WorldRenderer::renderFrame() {
    animTime += 0.05f; 
    worldTime += 0.0001f * timeScale; 
    if (worldTime > 1.0f) worldTime = 0;

    camX += (targetX - camX) * 0.1f;
    camY += (targetY - camY) * 0.1f;

    float sunPower = std::sin(worldTime * 3.14159f); 
    if (sunPower < 0) sunPower = 0;

    // Dynamic Sky
    skyR = 0.0f + sunPower * 0.4f;
    skyG = 0.0f + sunPower * 0.6f;
    skyB = 0.1f + sunPower * 0.8f;
    
    // Weather Logic
    if (rand() % 1000 < 1) weatherState = (weatherState == 0) ? (rand() % 2 + 1) : 0; // Random weather change
    
    if (weatherState > 0) {
        skyR *= 0.6f; skyG *= 0.6f; skyB *= 0.7f; // Darken sky
        
        // Spawn particles
        if (rand() % 10 < 8) {
            float px = camX + (rand() % 40 - 20);
            float py = camY + 15.0f;
            Particle p;
            p.type = PARTICLE_WEATHER; // 0
            p.x = px;
            p.y = py;
            p.vx = (weatherState == 2) ? (rand()%100 - 50) * 0.005f : 0;
            p.vy = (weatherState == 1) ? -0.8f : -0.2f;
            p.life = 3.0f;
            p.maxLife = 3.0f;
            p.size = (weatherState == 1) ? 0.1f : 0.2f;
            p.r = 1.0f; p.g = 1.0f; p.b = 1.0f; p.a = 0.8f;
            p.u = 0; p.v = 0;
            particles.push_back(p);
        }
    }

    updateParticles();

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
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    }
    glActiveTexture(GL_TEXTURE2); glBindTexture(GL_TEXTURE_2D, whiteTex);
    glUniform1i(glGetUniformLocation(program, "light_texture"), 2);

    // Daylight vector according to original shader expectations
    glUniform4f(glGetUniformLocation(program, "daylight"), sunPower, sunPower, sunPower, 1.0f);
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
            float scale = 0.35f;
            float baseX = -aspect + 0.6f; 
            float baseY = -0.5f;
            
            float m_menu[16];
            Matrix::ortho(m_menu, -aspect, aspect, -1.0f, 1.0f, -1.0f, 1.0f);

            glUniform4f(glGetUniformLocation(charProgram, "daylight"), 1.2f, 1.2f, 1.2f, 1.0f);
            glUniform4f(glGetUniformLocation(charProgram, "artificalLight"), 0.5f, 0.5f, 0.5f, 1.0f);
            glUniform4f(glGetUniformLocation(charProgram, "skinColor"), 1.0f, 0.85f, 0.7f, 1.0f);
            glUniform4f(glGetUniformLocation(charProgram, "clothingColorA"), 1.0f, 1.0f, 1.0f, 1.0f);
            glUniform4f(glGetUniformLocation(charProgram, "clothingColorB"), 0.9f, 0.9f, 0.9f, 1.0f);
            glUniform3f(glGetUniformLocation(charProgram, "artificialLightDirection"), 0.5f, 0.5f, 1.0f);
            glUniform4f(glGetUniformLocation(charProgram, "lightPosition"), 0.0f, 0.0f, 10.0f, 1.0f);

            auto drawCube = [&](GLuint tex, float x, float y, float z, float w, float h, float d, float u1, float v1, float u2, float v2) {
                glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, tex);
                glUniform1i(glGetUniformLocation(charProgram, "texture"), 0);

                float m_part[16]; std::copy(m_menu, m_menu + 16, m_part);
                Matrix::translate(m_part, baseX + x, baseY + y + breath, 0.5f + z);
                Matrix::scale(m_part, scale * w, scale * h, scale * d); 
                glUniformMatrix4fv(glGetUniformLocation(charProgram, "mvp_matrix"), 1, GL_FALSE, m_part);
                
                float m_norm[16]; 
                m_norm[0]=1; m_norm[1]=0; m_norm[2]=0; m_norm[3]=0;
                m_norm[4]=0; m_norm[5]=1; m_norm[6]=0; m_norm[7]=0;
                m_norm[8]=0; m_norm[9]=0; m_norm[10]=1; m_norm[11]=0;
                m_norm[12]=0; m_norm[13]=0; m_norm[14]=0; m_norm[15]=1;
                glUniformMatrix4fv(glGetUniformLocation(charProgram, "normal_matrix"), 1, GL_FALSE, m_norm);

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

            drawCube(bodyTexID, 0.0f, 0.0f, 0.0f, 0.15f, 0.25f, 0.1f, 0.0f, 0.0f, 1.0f, 1.0f);
            
            float lookX = (menuTouchX / (float)screenW) * 2.0f - 1.0f;
            float lookY = 1.0f - (menuTouchY / (float)screenH) * 2.0f;
            float headYaw = lookX * 45.0f;
            float headPitch = lookY * 30.0f;

            auto drawHead = [&](GLuint tex, float x, float y, float z, float w, float h, float d, float u1, float v1, float u2, float v2) {
                glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, tex);
                glUniform1i(glGetUniformLocation(charProgram, "texture"), 0);
                float m_part[16]; std::copy(m_menu, m_menu + 16, m_part);
                Matrix::translate(m_part, baseX + x, baseY + y + breath, 0.5f + z);
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
            drawCube(legsTexID, -0.05f, -0.25f, 0.0f, 0.05f, 0.25f, 0.05f, 0.0f, 0.0f, 1.0f, 1.0f);
            drawCube(legsTexID,  0.05f, -0.25f, 0.0f, 0.05f, 0.25f, 0.05f, 0.0f, 0.0f, 1.0f, 1.0f);
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
            
            // Process Emitters (Smoke)
            for (const auto& e : m.emitters) {
                if (rand() % 100 < 2) {
                    spawnSmoke(m.cx * 32.0f + e.x, m.cy * 32.0f + e.y);
                }
            }
        }
    }

    // The terrain pass leaves a VBO bound.  The character/mob paths below use
    // client-side arrays, so their pointers would otherwise be interpreted as
    // offsets into the terrain VBO and the draws would produce GL errors.
    glBindBuffer(GL_ARRAY_BUFFER, 0);

    // --- Render Player Character (In Game) ---
    if (charProgram != 0 && bodyTexID != 0) {
        glUseProgram(charProgram);
        glUniform4f(glGetUniformLocation(charProgram, "daylight"), 1.0f, 1.0f, 1.0f, 1.0f);
        glUniform4f(glGetUniformLocation(charProgram, "artificalLight"), 0.5f, 0.5f, 0.5f, 1.0f);
        glUniform4f(glGetUniformLocation(charProgram, "skinColor"), 1.0f, 0.85f, 0.7f, 1.0f);
        glUniform4f(glGetUniformLocation(charProgram, "clothingColorA"), 1.0f, 1.0f, 1.0f, 1.0f);
        glUniform4f(glGetUniformLocation(charProgram, "clothingColorB"), 0.9f, 0.9f, 0.9f, 1.0f);
        glUniform3f(glGetUniformLocation(charProgram, "artificialLightDirection"), 0.5f, 0.5f, 1.0f);
        glUniform4f(glGetUniformLocation(charProgram, "lightPosition"), camX, camY + 20.0f, 5.0f, 1.0f);
        
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

        float walkAnim = std::sin(animTime * 10.0f);
        drawCharCube(bodyTexID, 0, 0.25f, 0, 0.4f, 0.6f, 0.2f, 0, 0, 1, 1);
        drawCharCube(headTexID, 0, 0.75f, 0, 0.5f, 0.5f, 0.5f, 0.25f, 0.5f, 0.5f, 1.0f);
        drawCharCube(legsTexID, -0.1f, -0.2f + (walkAnim > 0 ? walkAnim*0.1f : 0), 0, 0.15f, 0.5f, 0.15f, 0, 0, 1, 1);
        drawCharCube(legsTexID,  0.1f, -0.2f + (walkAnim < 0 ? -walkAnim*0.1f : 0), 0, 0.15f, 0.5f, 0.15f, 0, 0, 1, 1);
        drawCharCube(armsTexID, -0.25f, 0.25f, 0, 0.12f, 0.5f, 0.12f, 0, 0, 1, 1);
        drawCharCube(armsTexID,  0.25f, 0.25f, 0, 0.12f, 0.5f, 0.12f, 0, 0, 1, 1);
        
        // --- Clothing Overlays ---
        if (clothingHead == 97) { // Linen Cap
             drawCharCube(clothingTex[0], 0, 0.76f, 0, 0.52f, 0.52f, 0.52f, 0, 0, 1, 1);
        }
        if (clothingLegs == 98) { // Linen Pants
             drawCharCube(clothingTex[1], -0.1f, -0.2f + (walkAnim > 0 ? walkAnim*0.1f : 0), 0, 0.16f, 0.51f, 0.16f, 0, 0, 1, 1);
             drawCharCube(clothingTex[1],  0.1f, -0.2f + (walkAnim < 0 ? -walkAnim*0.1f : 0), 0, 0.16f, 0.51f, 0.16f, 0, 0, 1, 1);
        }
    }

    // --- Render Mobs ---
    if (charProgram != 0 && dodoBodyTexID != 0) {
        glUseProgram(charProgram);
        auto drawMobPart = [&](GLuint tex, float mx, float my, float x, float y, float z, float w, float h, float d) {
            if (tex == 0) return;
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
                drawMobPart(dodoBodyTexID, mob.x, mob.y + 0.3f, 0, 0, 0, 0.4f, 0.3f, 0.2f);
                drawMobPart(dodoHeadTexID, mob.x, mob.y + 0.3f, 0.25f, 0.2f, 0, 0.2f, 0.2f, 0.2f);
                drawMobPart(dodoLegTexID, mob.x, mob.y + 0.3f, -0.05f, -0.2f + (wAnim>0?wAnim*0.1f:0), 0, 0.05f, 0.2f, 0.05f);
                drawMobPart(dodoLegTexID, mob.x, mob.y + 0.3f, 0.05f, -0.2f + (wAnim<0?-wAnim*0.1f:0), 0, 0.05f, 0.2f, 0.05f);
            } else if (mob.type == ENTITY_YAK) {
                float wAnim = std::sin(animTime * 10.0f + mob.x * 5.0f);
                // Yak is larger (body 0.8x0.6)
                drawMobPart(yakBodyTexID, mob.x, mob.y + 0.5f, 0, 0, 0, 0.8f, 0.6f, 0.4f);
                // Head
                drawMobPart(yakHeadTexID, mob.x, mob.y + 0.5f, 0.45f, 0.2f, 0, 0.3f, 0.3f, 0.3f);
                // Legs (4 legs for Yak)
                drawMobPart(yakLegTexID, mob.x, mob.y + 0.5f, -0.25f, -0.4f + (wAnim>0?wAnim*0.15f:0), 0.15f, 0.1f, 0.4f, 0.1f);
                drawMobPart(yakLegTexID, mob.x, mob.y + 0.5f, 0.25f, -0.4f + (wAnim<0?-wAnim*0.15f:0), 0.15f, 0.1f, 0.4f, 0.1f);
                drawMobPart(yakLegTexID, mob.x, mob.y + 0.5f, -0.25f, -0.4f + (wAnim<0?-0.15f:0), -0.15f, 0.1f, 0.4f, 0.1f);
                drawMobPart(yakLegTexID, mob.x, mob.y + 0.5f, 0.25f, -0.4f + (wAnim>0?0.15f:0), -0.15f, 0.1f, 0.4f, 0.1f);
            } else if (mob.type == ENTITY_DROPBEAR) {
                float wAnim = std::sin(animTime * 12.0f + mob.x);
                // Dropbear is more compact (dark fur)
                drawMobPart(dropbearBodyTexID, mob.x, mob.y + 0.25f, 0, 0, 0, 0.35f, 0.45f, 0.3f);
                drawMobPart(dropbearHeadTexID, mob.x, mob.y + 0.25f, 0, 0.35f, 0, 0.3f, 0.3f, 0.3f);
            }
        }
    }

    // --- Render Drop Items ---
    // Item.vsh/fsh consumes normalized UVs and ItemNormals.png. The old
    // prototype incorrectly used Block.vsh/fsh with atlas cell coordinates.
    if (itemProgram != 0 && itemsTexID != 0 && normalID != 0) {
        glUseProgram(itemProgram);
        glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, itemsTexID);
        glUniform1i(glGetUniformLocation(itemProgram, "texture"), 0);
        glActiveTexture(GL_TEXTURE1); glBindTexture(GL_TEXTURE_2D, normalID);
        glUniform1i(glGetUniformLocation(itemProgram, "normal_texture"), 1);
        glUniform4f(glGetUniformLocation(itemProgram, "light"), 1.0f, 1.0f, 1.0f, 1.0f);
        glUniform4f(glGetUniformLocation(itemProgram, "lightPosition"), camX, camY + 20.0f, 5.0f, 1.0f);
        GLint itemPosLoc = glGetAttribLocation(itemProgram, "position");
        GLint itemTexLoc = glGetAttribLocation(itemProgram, "texCoord");
        glEnableVertexAttribArray(itemPosLoc);
        glEnableVertexAttribArray(itemTexLoc);
        for (const auto& item : dropItems) {
            const auto* def = ItemManager::getInstance().getDef(item.type);
            if (!def) continue;
            float m_item[16]; std::copy(matrix, matrix + 16, m_item);
            Matrix::translate(m_item, item.x, item.y + 0.2f, 0.1f);
            Matrix::scale(m_item, 0.4f, 0.4f, 1.0f);
            glUniformMatrix4fv(glGetUniformLocation(itemProgram, "mvp_matrix"), 1, GL_FALSE, m_item);

            constexpr float atlasW = 512.0f;
            constexpr float atlasH = 256.0f;
            constexpr float cell = 16.0f;
            float u0 = def->texCol * cell / atlasW;
            float v0 = def->texRow * cell / atlasH;
            float u1 = u0 + cell / atlasW;
            float v1 = v0 + cell / atlasH;
            float iV[] = { 0,0, u0,v1, 1,0, u1,v1, 0,1, u0,v0,
                           1,0, u1,v1, 1,1, u1,v0, 0,1, u0,v0 };
            glVertexAttribPointer(itemPosLoc, 2, GL_FLOAT, GL_FALSE, 4*sizeof(float), &iV[0]);
            glVertexAttribPointer(itemTexLoc, 2, GL_FLOAT, GL_FALSE, 4*sizeof(float), &iV[2]);
            glDrawArrays(GL_TRIANGLES, 0, 6);
        }
        glDisableVertexAttribArray(itemPosLoc);
        glDisableVertexAttribArray(itemTexLoc);
    }

    // --- Render ActionSquare ---
    if (showActionSquare && actionSquareProgram != 0) {
        glUseProgram(actionSquareProgram);
        glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, actionSquareTexID);
        glUniform1i(glGetUniformLocation(actionSquareProgram, "texture"), 0);
        
        float pulse = 0.7f + std::sin(animTime * 15.0f) * 0.3f;
        glUniform4f(glGetUniformLocation(actionSquareProgram, "light"), pulse, pulse, pulse, 1.0f);
        
        float m_sq[16];
        std::copy(matrix, matrix + 16, m_sq);
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
    
    // --- Render Particles (New System) ---
    renderParticles();

    // --- Render Crafting Progress ---
    if (g_crafting) {
        std::lock_guard<std::mutex> lock(g_crafting->craftMutex);
        for (auto const& pair : g_crafting->activeCrafts) {
            uint64_t key = pair.first;
            const auto& ac = pair.second;
            float tx = (float)(key >> 32);
            float ty = (float)(key & 0xFFFFFFFF);
            renderCraftingProgress(tx, ty, ac.progress);
        }
    }
    
    glBindBuffer(GL_ARRAY_BUFFER, 0);
}
// --- Particle System ---

void WorldRenderer::spawnBlockBreakParticles(int x, int y, int blockType) {
    if (blockType == 0) return;
    auto def = ItemManager::getInstance().getDef(blockType);
    if (!def) return;
    int texRow = def->texRow;
    int texCol = def->texCol;
    
    float tileUVSize = 1.0f / 32.0f;
    float uBase = texCol * tileUVSize;
    float vBase = texRow * tileUVSize;
    float subSize = 0.25f; // Visual size (1/4 block)
    float uvStep = subSize * tileUVSize; 

    for(int i=0; i<4; i++) {
        for(int j=0; j<4; j++) {
            Particle p;
            p.type = PARTICLE_BLOCK_DEBRIS;
            p.x = (float)x + i * 0.25f + 0.125f;
            p.y = (float)y + (3-j) * 0.25f + 0.125f; // Flip Y for visual consistency
            p.vx = (rand()%100 - 50) * 0.003f; // Slightly faster spread
            p.vy = (rand()%100) * 0.001f + 0.05f; 
            p.life = 0.5f + (rand()%10)*0.05f; // Short life
            p.maxLife = p.life;
            p.size = subSize; 
            p.u = uBase + i * uvStep; 
            p.v = vBase + j * uvStep; 
            p.r = 1; p.g = 1; p.b = 1; p.a = 1;
            particles.push_back(p);
        }
    }
}

void WorldRenderer::spawnSmoke(float x, float y) {
    Particle p;
    p.type = PARTICLE_SMOKE;
    p.x = x + 0.5f;
    p.y = y + 0.5f;
    p.vx = (rand()%100 - 50) * 0.0003f;
    p.vy = 0.01f + (rand()%100)*0.0002f;
    p.life = 2.0f;
    p.maxLife = 2.0f;
    p.size = 0.2f; 
    p.r = 0.9f; p.g = 0.9f; p.b = 0.9f; p.a = 0.4f;
    p.u = 0; p.v = 0; // Not used for white texture
    particles.push_back(p);
}

void WorldRenderer::updateParticles() {
    for(auto& p : particles) {
        p.x += p.vx;
        p.y += p.vy;
        p.life -= 0.015f; 
        
        if (p.type == PARTICLE_BLOCK_DEBRIS) {
            p.vy -= 0.003f; // Stronger Gravity
            p.a = std::min(1.0f, p.life * 3.0f); 
        } else if (p.type == PARTICLE_SMOKE) {
            p.size += 0.001f; // Grow
            p.a = (p.life / p.maxLife) * 0.4f; // Fade
        }
        // Weather physics handled implicitly by constant velocity
    }
    
    // Remove dead
    particles.erase(std::remove_if(particles.begin(), particles.end(), 
         [](const Particle& p){ return p.life <= 0; }), particles.end());
}

void WorldRenderer::renderParticles() {
    if (particles.empty() || actionSquareProgram == 0) return; 
    
    glUseProgram(actionSquareProgram);
    
    GLint pLoc = glGetAttribLocation(actionSquareProgram, "position");
    GLint tLoc = glGetAttribLocation(actionSquareProgram, "texCoord");
    glEnableVertexAttribArray(pLoc);
    glEnableVertexAttribArray(tLoc);

    // Common Matrix Setup
    float matrix[16];
    float aspect = (float)screenW / (float)screenH;
    float h_cam = 10.0f * camZoom; 
    float w_cam = h_cam * aspect;
    Matrix::ortho(matrix, -w_cam, w_cam, -h_cam, h_cam, -10.0f, 10.0f);
    Matrix::translate(matrix, -camX, -camY, 0);

    auto drawQuad = [&](const Particle& p, GLuint tex) {
        float m_p[16]; std::copy(matrix, matrix + 16, m_p);
        Matrix::translate(m_p, p.x, p.y, 0.6f); // In front of blocks
        Matrix::scale(m_p, p.size, p.size, 1.0f);
        glUniformMatrix4fv(glGetUniformLocation(actionSquareProgram, "mvp_matrix"), 1, GL_FALSE, m_p);
        glUniform4f(glGetUniformLocation(actionSquareProgram, "light"), p.r, p.g, p.b, p.a);

        float u1 = p.u; 
        float v1 = p.v;
        float u2 = p.u + (p.type==PARTICLE_BLOCK_DEBRIS ? (0.25f/32.0f) : 1.0f);
        float v2 = p.v + (p.type==PARTICLE_BLOCK_DEBRIS ? (0.25f/32.0f) : 1.0f);
        
        // Quad vertices (centered)
        float qVerts[] = {
            -0.5f, -0.5f, 0, 1,  u1, v2,
             0.5f, -0.5f, 0, 1,  u2, v2,
            -0.5f,  0.5f, 0, 1,  u1, v1,
             0.5f, -0.5f, 0, 1,  u2, v2,
             0.5f,  0.5f, 0, 1,  u2, v1,
            -0.5f,  0.5f, 0, 1,  u1, v1
        };
        glVertexAttribPointer(pLoc, 4, GL_FLOAT, GL_FALSE, 6 * sizeof(float), &qVerts[0]);
        glVertexAttribPointer(tLoc, 2, GL_FLOAT, GL_FALSE, 6 * sizeof(float), &qVerts[4]);
        glDrawArrays(GL_TRIANGLES, 0, 6);
    };

    // Pass 1: Block Debris
    glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, textureID);
    glUniform1i(glGetUniformLocation(actionSquareProgram, "texture"), 0);
    for (const auto& p : particles) {
        if (p.type == PARTICLE_BLOCK_DEBRIS) drawQuad(p, textureID);
    }

    // Pass 2: White Texture (Smoke/Weather)
    static GLuint whiteTex = 0;
    if (whiteTex == 0) {
        uint32_t px = 0xFFFFFFFF;
        glGenTextures(1, &whiteTex);
        glBindTexture(GL_TEXTURE_2D, whiteTex);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 1, 1, 0, GL_RGBA, GL_UNSIGNED_BYTE, &px);
    }
    
    glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, whiteTex);
    for (const auto& p : particles) {
        if (p.type != PARTICLE_BLOCK_DEBRIS) drawQuad(p, whiteTex);
    }
}
void WorldRenderer::projectWorldToScreen(float worldX, float worldY, float& outScreenX, float& outScreenY) {
    // 1. Recreate the same MVP matrix used in renderFrame
    float matrix[16];
    float aspect = (float)screenW / (float)screenH;
    float h_cam = 10.0f * camZoom; 
    float w_cam = h_cam * aspect;
    Matrix::ortho(matrix, -w_cam, w_cam, -h_cam, h_cam, -10.0f, 10.0f);
    Matrix::translate(matrix, -camX, -camY, 0);

    // 2. Transform world coordinates to clip space (-1 to 1)
    float worldPos[4] = {worldX, worldY, 0.0f, 1.0f}; 
    float clipPos[4];
    Matrix::multiplyVec4(clipPos, matrix, worldPos);
    
    // Perspective division (not strictly necessary for ortho, but good practice)
    if (clipPos[3] != 0.0f) {
        clipPos[0] /= clipPos[3];
        clipPos[1] /= clipPos[3];
    }

    // 3. Transform clip space to screen space (pixels)
    outScreenX = (clipPos[0] + 1.0f) * 0.5f * screenW;
    outScreenY = (1.0f - clipPos[1]) * 0.5f * screenH; // Y is inverted from GL to screen
}

void WorldRenderer::renderCraftingProgress(float x, float y, float progress) {
    if (actionSquareProgram == 0) return;
    glUseProgram(actionSquareProgram);
    
    static GLuint whiteTex = 0;
    if (whiteTex == 0) {
        uint32_t px = 0xFFFFFFFF;
        glGenTextures(1, &whiteTex);
        glBindTexture(GL_TEXTURE_2D, whiteTex);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, 1, 1, 0, GL_RGBA, GL_UNSIGNED_BYTE, &px);
    }
    glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D, whiteTex);

    float matrix[16];
    float aspect = (float)screenW / (float)screenH;
    float h_cam = 10.0f * camZoom; 
    float w_cam = h_cam * aspect;
    Matrix::ortho(matrix, -w_cam, w_cam, -h_cam, h_cam, -10.0f, 10.0f);
    Matrix::translate(matrix, -camX, -camY, 0);

    GLint pLoc = glGetAttribLocation(actionSquareProgram, "position");
    GLint tLoc = glGetAttribLocation(actionSquareProgram, "texCoord");
    glEnableVertexAttribArray(pLoc);
    glEnableVertexAttribArray(tLoc);

    auto drawBar = [&](float dx, float dy, float dw, float dh, float r, float g, float b, float a) {
        float m_p[16]; std::copy(matrix, matrix + 16, m_p);
        Matrix::translate(m_p, x + dx, y + dy, 0.7f);
        Matrix::scale(m_p, dw, dh, 1.0f);
        glUniformMatrix4fv(glGetUniformLocation(actionSquareProgram, "mvp_matrix"), 1, GL_FALSE, m_p);
        glUniform4f(glGetUniformLocation(actionSquareProgram, "light"), r, g, b, a);
        float qVerts[] = { -0.5f,-0.5f,0,1, 0,0, 0.5f,-0.5f,0,1, 1,0, -0.5f,0.5f,0,1, 0,1, 0.5f,-0.5f,0,1, 1,0, 0.5f,0.5f,0,1, 1,1, -0.5f,0.5f,0,1, 0,1 };
        glVertexAttribPointer(pLoc, 4, GL_FLOAT, GL_FALSE, 6 * sizeof(float), &qVerts[0]);
        glVertexAttribPointer(tLoc, 2, GL_FLOAT, GL_FALSE, 6 * sizeof(float), &qVerts[4]);
        glDrawArrays(GL_TRIANGLES, 0, 6);
    };

    drawBar(0.5f, 1.2f, 0.8f, 0.15f, 0.2f, 0.2f, 0.2f, 0.8f);
    drawBar(0.5f - (1.0f-progress)*0.4f, 1.2f, 0.8f * progress, 0.1f, 0.0f, 1.0f, 0.0f, 1.0f);
}
