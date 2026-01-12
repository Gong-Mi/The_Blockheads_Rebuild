cmake_minimum_required(VERSION 3.4.1)

add_library(native-lib SHARED
            game_engine.cpp
            world_renderer.cpp
            blockhead_ai.cpp
            command_processor.cpp
            item_manager.cpp
            compression_manager.cpp)

# 寻找系统预装的 zstd 或者通过外部库引入
# 这里我们假设通过 vcpkg 或直接源码包含
find_library(zstd-lib zstd)

find_library(log-lib log)
find_library(android-lib android)
find_library(gles2-lib GLESv2)

target_link_libraries(native-lib
                       ${log-lib}
                       ${android-lib}
                       ${gles2-lib})
