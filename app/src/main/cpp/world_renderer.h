#ifndef WORLD_RENDERER_H
#define WORLD_RENDERER_H

#include <GLES2/gl2.h>
#include <vector>
#include <mutex>
#include <android/asset_manager.h>
#include "game_constants.h"

struct Vertex {
    float x, y, z, w; // w is texIndex.x
    uint8_t u, v, s, t; // vsh expects 0-255
    float otherX, otherY, otherZ, otherW; // other.z is texIndex.y
    uint8_t r, g, b, a; // paintColor
};

struct ChunkRenderData {
    GLuint vbo = 0;
    int vertexCount = 0;
    bool active = false;
    int cx, cy;
};

struct EntityRenderData {
    float x, y;
    int type; 
};

class WorldRenderer {
public:
    GLuint program;
    GLuint textureID, destructID, normalID, itemsTexID;
    GLuint headTexID, bodyTexID, armsTexID, legsTexID;
    GLuint dodoBodyTexID, dodoHeadTexID, dodoLegTexID;
    GLuint yakBodyTexID, yakHeadTexID, yakLegTexID;
    GLuint dropbearBodyTexID, dropbearHeadTexID;
    GLuint actionSquareTexID, actionSquareProgram;
    GLuint charProgram;
    GLuint debugProgram; // For debugging char render
    
    int targetBlockX = -1, targetBlockY = -1;
    bool showActionSquare = false;

    std::vector<ChunkRenderData> chunkMeshes;
    std::mutex meshMutex;

    GLint uMatrix;
    float camX = 0, camY = 0;
    float targetX = 0, targetY = 0;
    float camZoom = 1.0f; 
    float animTime = 0;
    float worldTime = 0; 
    bool followingPlayer = true;
    bool menuMode = false;
    float menuTouchX = 0, menuTouchY = 0;
    
    float playerX = 0, playerY = 0;
    std::vector<EntityRenderData> dropItems;
    std::vector<EntityRenderData> mobs;
    
    // Weather
    float skyR=0.5f, skyG=0.7f, skyB=1.0f;
    int weatherState = 0; // 0: Clear, 1: Rain, 2: Snow
    struct Particle { float x, y, vx, vy, life; };
    std::vector<Particle> rainParticles;

    int totalVertexCount = 0;
    int screenW = 1920, screenH = 1080;

    void init(AAssetManager* mgr);
    void resize(int w, int h);
    GLuint loadTex(AAssetManager* mgr, const char* name);
    GLuint createProgram(const char* vs, const char* fs);
    void pushBlock(std::vector<Vertex>& buffer, float x, float y, int type, float damage, float sun, float art);
    void updateMesh(const std::vector<PhysicalBlock*>& chunks);
    void renderFrame();
    char* loadShaderSource(AAssetManager* mgr, const char* name);
};

extern WorldRenderer* g_renderer;

#endif
