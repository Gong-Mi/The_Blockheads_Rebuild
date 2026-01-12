#ifndef WORLD_RENDERER_H
#define WORLD_RENDERER_H

#include <GLES2/gl2.h>
#include <vector>
#include <android/asset_manager.h>
#include "game_constants.h"

struct Vertex {
    float x, y;
    float u, v;
    float brightness;
    float damage;
};

class WorldRenderer {
public:
    GLuint program;
    GLuint textureID, destructID, normalID, playerTexID;
    GLuint vbo;
    GLint uMatrix;
    float camX = 0, camY = 0;
    float targetX = 0, targetY = 0;
    float animTime = 0;
    
    // Player position
    float playerX = 0, playerY = 0;

    int vertexCount = 0;
    bool meshDirty = false;

    void init(AAssetManager* mgr);
    GLuint loadTex(AAssetManager* mgr, const char* name);
    GLuint createProgram(const char* vs, const char* fs);
    void pushBlock(std::vector<Vertex>& buffer, float x, float y, int type, float damage);
    void updateMesh(const std::vector<PhysicalBlock*>& chunks);
    void renderFrame();
};

extern WorldRenderer* g_renderer;

#endif
