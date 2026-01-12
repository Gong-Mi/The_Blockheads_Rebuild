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

struct EntityRenderData {
    float x, y;
    int type; // Item ID (e.g., 1=Dirt, 2=Stone)
};

class WorldRenderer {
public:
    GLuint program;
    GLuint textureID, destructID, normalID, playerTexID, itemsTexID;
    GLuint vbo;
    GLint uMatrix;
    float camX = 0, camY = 0;
    float targetX = 0, targetY = 0;
    float animTime = 0;
    
    // Player position
    float playerX = 0, playerY = 0;
    
    // Drop items to render
    std::vector<EntityRenderData> dropItems;

    int vertexCount = 0;
    bool meshDirty = false;
    
    int screenW = 1920, screenH = 1080;

    void init(AAssetManager* mgr);
    void resize(int w, int h);
    GLuint loadTex(AAssetManager* mgr, const char* name);
    GLuint createProgram(const char* vs, const char* fs);
    void pushBlock(std::vector<Vertex>& buffer, float x, float y, int type, float damage);
    void updateMesh(const std::vector<PhysicalBlock*>& chunks);
    void renderFrame();
};

extern WorldRenderer* g_renderer;

#endif
