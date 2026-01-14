# The Blockheads Android Rebuild - Project Documentation

## Project Status
**Current State:** Functional Prototype / Alpha
**Last Updated:** January 14, 2026

This project is a native Android reconstruction of "The Blockheads", utilizing a custom C++ engine for high-performance world simulation and rendering, bridged to a Java Android frontend.

## Technical Architecture

### 1. Native Engine (C++)
The core logic resides in `android_rebuild/app/src/main/cpp/`.

*   **Game Loop (`game_engine.cpp`)**:
    *   Driven by `onDrawFrameNative`.
    *   Handles sub-system updates: AI, Entities, Physics, World, and JNI State Syncing.
*   **World System (`game_world.cpp`)**:
    *   **Chunk Architecture**: 32x32 tiles per chunk, managed in a dynamic grid.
    *   **Wrapping**: Horizontal world wrapping implemented via `wrapChunkX`.
    *   **Generation**: Asynchronous generation (`workerLoop`) using noise for terrain, caves, and ores. Features temperature-based biomes (Snow, Sand, Dirt).
*   **Item & Recipe System**:
    *   **Current State (Hardcoded)**: 
        *   Items and recipes are currently manually defined in `ItemManager::init()` and `CraftingManager` constructor.
        *   **Consequences**: 
            *   **Maintenance Nightmare**: Adding content requires modifying C++ source, leading to recompilation delays.
            *   **ID Conflicts**: Manual integer ID management is prone to collision errors.
            *   **No Mod Support**: Impossible for external configuration or user mods.
    *   **Planned Architecture (Data-Driven)**:
        *   **Source**: JSON files (`items.json`, `recipes.json`) in `assets/gamedata/`.
        *   **Build Tool**: Python scripts (`process_items.py`) running at compile-time.
        *   **Output**: Auto-generated C++ headers/source (`generated/game_item_ids.h`, `game_item_data.cpp`) containing optimized static arrays and enums. This ensures 0-overhead runtime performance while keeping data editable.
*   **Simulation Systems**:
    *   **Lighting**: Cellular automata-based propagation for Sunlight and Artificial light (Torches, Lamps).
    *   **Fluids**: Discrete update steps for water flow, evaporation, and freezing.
    *   **Electricity**: BFS-based power propagation (Generator -> Wire -> Consumer).
    *   **Vegetation**: Tick-based growth logic for seeds.
*   **Rendering (`world_renderer.cpp`)**:
    *   OpenGL ES 2.0 pipeline.
    *   **2.5D Mesh Generation**: dynamically builds vertex buffers with "thickness" (Front, Right, Bottom faces) and per-vertex lighting.
    *   **Camera**: Smooth panning and zooming with touch input mapping.

### 2. Android Integration (Java)
Located in `android_rebuild/app/src/main/java/com/noodlecake/blockheads/rebuild/`.

*   **Activities**:
    *   `MainMenuActivity`: Entry point.
    *   `GameActivity`: Main game container, handles Native initialization.
*   **JNI Bridge**:
    *   **Input**: Touch events (Tap, Pan, Pinch) are passed to C++ for World/Camera control.
    *   **UI Sync**: C++ invokes Java methods to update Hotbar (`updateHotbarSlot`) and Status bars (`updateStatusUI`).
    *   **Audio**: C++ queues sound events; Java plays them via `SoundPool`/`MediaPlayer` (Dynamic BGM switching Day/Night).

## Build Instructions

### Prerequisites
*   **JDK**: Version 17
*   **Android SDK**: API Level 34 (Upside Down Cake)
*   **NDK**: Version 26.1.10909125
*   **CMake**: Included in Android SDK

### Compilation
The project uses Gradle with external native build support.

1.  **Clean Build**:
    ```bash
    cd android_rebuild
    ./gradlew clean assembleDebug
    ```
2.  **Output**:
    The APK will be generated at `android_rebuild/app/build/outputs/apk/debug/app-debug.apk`.

## Key Features Implemented

| Feature | Status | Details |
| :--- | :--- | :--- |
| **World Gen** | ✅ | Terrain, Caves, Ores, Biomes (Temp), Trees, Plants |
| **Rendering** | ✅ | 2.5D Blocks, Dynamic Lighting, Zoom/Pan |
| **Physics** | ⚠️ | Basic Collision, Fluid Flow (Water) |
| **Interaction** | ✅ | Mine, Place, Eat, Wear, Craft |
| **Systems** | ✅ | Electricity, Day/Night Cycle, Growth |
| **Audio** | ✅ | SFX, Adaptive BGM |
| **Save/Load** | ✅ | Full World Persistence |

## Directory Structure
*   `android_rebuild/app/src/main/cpp/`: Native engine source.
*   `android_rebuild/app/src/main/java/`: Android UI and Activity logic.
*   `android_rebuild/assets/`: Original game assets (Textures, Shaders, Audio).
*   `android_rebuild/app/build.gradle`: Build configuration.
