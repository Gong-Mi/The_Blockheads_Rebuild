cmake_minimum_required(VERSION 3.4.1)

# --- Zstd 编译配置 ---
set(ZSTD_DIR external/zstd/lib)
include_directories(${ZSTD_DIR})
include_directories(${ZSTD_DIR}/common)

# 收集 zstd 核心源码 (common, compress, decompress)
file(GLOB ZSTD_SOURCES
    ${ZSTD_DIR}/common/*.c
    ${ZSTD_DIR}/compress/*.c
    ${ZSTD_DIR}/decompress/*.c
)

add_library(native-lib SHARED
            game_engine.cpp
            world_renderer.cpp
            blockhead_ai.cpp
            command_processor.cpp
            item_manager.cpp
            compression_manager.cpp
            ${ZSTD_SOURCES})

find_library(log-lib log)
find_library(android-lib android)
find_library(gles2-lib GLESv2)

target_link_libraries(native-lib
                       ${log-lib}
                       ${android-lib}
                       ${gles2-lib})
