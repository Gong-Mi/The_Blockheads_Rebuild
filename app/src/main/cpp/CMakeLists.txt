cmake_minimum_required(VERSION 3.4.1)
project("TheBlockheads")

include_directories(external)
include_directories(generated) # Generated headers

# --- Code Generation ---
find_package(Python3 REQUIRED)
set(TOOL_DIR ${CMAKE_SOURCE_DIR}/../../../tools)
set(ASSET_DIR ${CMAKE_SOURCE_DIR}/../../assets/gamedata)
set(GEN_DIR ${CMAKE_CURRENT_SOURCE_DIR}/generated)

add_custom_command(
    OUTPUT ${GEN_DIR}/game_item_ids.h ${GEN_DIR}/game_item_data.cpp
    COMMAND ${Python3_EXECUTABLE} ${TOOL_DIR}/process_items.py ${ASSET_DIR}/items.json ${GEN_DIR}/game_item_ids.h ${GEN_DIR}/game_item_data.cpp
    DEPENDS ${TOOL_DIR}/process_items.py ${ASSET_DIR}/items.json
    COMMENT "Generating Item Data from JSON"
)

# --- Zstd 编译配置 ---
set(ZSTD_DIR external/zstd/lib)
add_definitions(-DZSTD_DISABLE_ASM) # 禁用汇编以确保 Android 兼容性
include_directories(${ZSTD_DIR} ${ZSTD_DIR}/common)
file(GLOB ZSTD_SOURCES ${ZSTD_DIR}/common/*.c ${ZSTD_DIR}/compress/*.c ${ZSTD_DIR}/decompress/*.c)

# --- LZ4 编译配置 ---
set(LZ4_DIR external/lz4/lib)
include_directories(${LZ4_DIR})
file(GLOB LZ4_SOURCES ${LZ4_DIR}/*.c)

add_library(native-lib SHARED
            game_engine.cpp
            game_world.cpp
            entity_manager.cpp
            blockhead_ai.cpp
            world_renderer.cpp
            compression_manager.cpp
            command_processor.cpp
            item_manager.cpp
            generated/game_item_data.cpp
            settings_manager.cpp
            ${ZSTD_SOURCES}
            ${LZ4_SOURCES})

find_library(log-lib log)
find_library(android-lib android)
find_library(gles2-lib GLESv2)

target_link_libraries(native-lib
                       ${log-lib}
                       ${android-lib}
                       ${gles2-lib})