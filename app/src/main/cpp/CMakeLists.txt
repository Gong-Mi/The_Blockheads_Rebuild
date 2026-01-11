cmake_minimum_required(VERSION 3.4.1)

add_library(native-lib SHARED
            game_engine.cpp
            world_renderer.cpp
            blockhead_ai.cpp)

find_library(log-lib log)
find_library(android-lib android)
find_library(gles2-lib GLESv2)

target_link_libraries(native-lib
                       ${log-lib}
                       ${android-lib}
                       ${gles2-lib})
