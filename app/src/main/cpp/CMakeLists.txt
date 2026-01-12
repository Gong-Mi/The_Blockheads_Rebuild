cmake_minimum_required(VERSION 3.4.1)

include_directories(external)

# --- Zstd 编译配置 ---
set(ZSTD_DIR external/zstd/lib)
include_directories(${ZSTD_DIR} ${ZSTD_DIR}/common)
file(GLOB ZSTD_SOURCES ${ZSTD_DIR}/common/*.c ${ZSTD_DIR}/compress/*.c ${ZSTD_DIR}/decompress/*.c)

# --- LZ4 编译配置 ---
set(LZ4_DIR external/lz4/lib)
include_directories(${LZ4_DIR})
file(GLOB LZ4_SOURCES ${LZ4_DIR}/*.c)

add_library(native-lib SHARED
            game_engine.cpp
            world_renderer.cpp
            blockhead_ai.cpp
            command_processor.cpp
            item_manager.cpp
            compression_manager.cpp
            crafting_manager.cpp
            ${ZSTD_SOURCES}
            ${LZ4_SOURCES})

find_library(log-lib log)
find_library(android-lib android)
find_library(gles2-lib GLESv2)

target_link_libraries(native-lib
                       ${log-lib}
                       ${android-lib}
                       ${gles2-lib})
