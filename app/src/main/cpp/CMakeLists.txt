cmake_minimum_required(VERSION 3.4.1)
project("TheBlockheads")

include_directories(external)
include_directories(.) # Add this to let generated files find local headers
include_directories(generated) # Generated headers
# Client assembly app skeleton (batch b5a) includes original_client_world.h from
# the reconstruction tree; the header is what the host CI target also compiles.
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../../../reconstruction/recovered)

# --- Code Generation ---
find_package(Python3 REQUIRED)
set(TOOL_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../tools)
set(ASSET_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../assets/gamedata)
set(GEN_DIR ${CMAKE_CURRENT_SOURCE_DIR}/generated)

add_custom_command(
    OUTPUT ${GEN_DIR}/game_item_ids.h ${GEN_DIR}/game_item_data.cpp ${GEN_DIR}/game_recipe_data.h ${GEN_DIR}/game_recipe_data.cpp
    COMMAND ${Python3_EXECUTABLE} ${TOOL_DIR}/process_items.py ${ASSET_DIR}/items.json ${ASSET_DIR}/recipes.json ${GEN_DIR}/game_item_ids.h ${GEN_DIR}/game_item_data.cpp ${GEN_DIR}/game_recipe_data.h ${GEN_DIR}/game_recipe_data.cpp
    DEPENDS ${TOOL_DIR}/process_items.py ${ASSET_DIR}/items.json ${ASSET_DIR}/recipes.json
    COMMENT "Generating Item and Recipe Data from JSON"
)

# --- Zstd 编译配置 ---
set(ZSTD_DIR external/zstd/lib)
add_definitions(-DZSTD_DISABLE_ASM) # 禁用汇编以确保 Android 兼容性
# xxhash 命名空间隔离（2026-09-27 真机实测 + 链接复现）：
# zstd 源引用 ZSTD_XXH*，lz4 源引用 LZ4_XXH*（各自 xxhash.c 副本）。
# 单一全局 -DXXH_NAMESPACE 会让两份 xxhash.c 导出同名符号，
# 链接报 duplicate symbol: ZSTD_XXH_versionNumber/ZSTD_XXH32 …
# 因此两个 vendored 库各自建 STATIC 目标、各带自己的宏，不再 glob 进 native-lib。
file(GLOB ZSTD_SOURCES ${ZSTD_DIR}/common/*.c ${ZSTD_DIR}/compress/*.c ${ZSTD_DIR}/decompress/*.c)
add_library(zstd-static STATIC ${ZSTD_SOURCES})
target_compile_definitions(zstd-static PRIVATE XXH_NAMESPACE=ZSTD_)
target_include_directories(zstd-static PUBLIC ${ZSTD_DIR} ${ZSTD_DIR}/common)

# --- LZ4 编译配置 ---
set(LZ4_DIR external/lz4/lib)
file(GLOB LZ4_SOURCES ${LZ4_DIR}/*.c)
add_library(lz4-static STATIC ${LZ4_SOURCES})
target_compile_definitions(lz4-static PRIVATE XXH_NAMESPACE=LZ4_)
target_include_directories(lz4-static PUBLIC ${LZ4_DIR})

add_library(native-lib SHARED
            game_engine.cpp
            game_world.cpp
            entity_manager.cpp
            blockhead_ai.cpp
            world_renderer.cpp
            compression_manager.cpp
            original_save_format.cpp
            # b5b: original_client_world.cpp lives only in the reconstruction
            # tree (the host CI target compiles it from there; see
            # reconstruction/recovered/CMakeLists.txt). Pointing the APK build
            # at the app-local name left the native-lib target with a missing
            # source ("Cannot find source file: original_client_world.cpp"),
            # which broke configure for the whole Android build.
            ${CMAKE_CURRENT_SOURCE_DIR}/../../../../reconstruction/recovered/original_client_world.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/../../../../reconstruction/recovered/plant_full.cpp
            # bucket B: the npc chain (factory + the executed b4f contract it
            # runs; npc_full.cpp calls npc_load_values_run)
            ${CMAKE_CURRENT_SOURCE_DIR}/../../../../reconstruction/recovered/npc_full.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/../../../../reconstruction/recovered/npc_load_values_from_save_dict.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/../../../../reconstruction/recovered/tree_full.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/../../../../reconstruction/recovered/tree_load_save_dict.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/../../../../reconstruction/recovered/workbench_full.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/../../../../reconstruction/recovered/workbench_init.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/../../../../reconstruction/recovered/gatherblock_full.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/../../../../reconstruction/recovered/kelpvine_full.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/../../../../reconstruction/recovered/trainstation_full.cpp
            ${CMAKE_CURRENT_SOURCE_DIR}/../../../../reconstruction/recovered/chest_full.cpp
            original_save_dict.cpp
            dynamic_object_registry.cpp
            original_client_app.cpp
            command_processor.cpp
            item_manager.cpp
            generated/game_item_data.cpp
            generated/game_recipe_data.cpp
            settings_manager.cpp)

find_library(log-lib log)
find_library(android-lib android)
find_library(gles2-lib GLESv2)
find_library(z-lib z)

# the vendored compression libs carry their own XXH namespace; their PUBLIC
# include dirs propagate to the sources that call ZSTD_*/LZ4_*
target_link_libraries(native-lib
                       zstd-static
                       lz4-static
                       ${log-lib}
                       ${android-lib}
                       ${gles2-lib}
                       ${z-lib})