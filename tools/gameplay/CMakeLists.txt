cmake_minimum_required(VERSION 3.16)
project(BlockheadsGameplayContracts LANGUAGES CXX)
include(CTest)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
find_package(Threads REQUIRED)
get_filename_component(REPO "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
set(GENERATED "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${GENERATED}")
execute_process(COMMAND "${Python3_EXECUTABLE}" "${REPO}/tools/process_items.py"
    "${REPO}/assets/gamedata/items.json" "${REPO}/assets/gamedata/recipes.json"
    "${GENERATED}/game_item_ids.h" "${GENERATED}/game_item_data.cpp"
    "${GENERATED}/game_recipe_data.h" "${GENERATED}/game_recipe_data.cpp"
    RESULT_VARIABLE generate_result)
if(NOT generate_result EQUAL 0)
    message(FATAL_ERROR "Generating actual gameplay data failed")
endif()
# Actual APK gameplay translation units, no substitute world or inventory mock.
add_library(blockheads_gameplay_host STATIC
    "${REPO}/app/src/main/cpp/blockhead_ai.cpp"
    "${REPO}/app/src/main/cpp/entity_manager.cpp"
    "${REPO}/app/src/main/cpp/game_world.cpp"
    "${REPO}/app/src/main/cpp/item_manager.cpp"
    "${GENERATED}/game_item_data.cpp" "${GENERATED}/game_recipe_data.cpp")
target_include_directories(blockheads_gameplay_host PUBLIC "${REPO}/app/src/main/cpp" "${GENERATED}")
target_compile_features(blockheads_gameplay_host PUBLIC cxx_std_17)
target_link_libraries(blockheads_gameplay_host PUBLIC Threads::Threads)
include(CheckCXXSourceCompiles)
check_cxx_source_compiles("#ifndef __ANDROID__\n#error not Android\n#endif\nint main() { return 0; }" GAMEPLAY_ANDROID_HOST)
if(GAMEPLAY_ANDROID_HOST)
    target_link_libraries(blockheads_gameplay_host PUBLIC log)
endif()
foreach(test gameplay_loop inventory crafting_delivery)
    add_executable(test_${test} "${REPO}/tools/test_${test}.cpp")
    target_link_libraries(test_${test} PRIVATE blockheads_gameplay_host)
    target_compile_options(test_${test} PRIVATE -UNDEBUG)
endforeach()
foreach(scenario mining pickup placement loop reject)
    add_test(NAME gameplay_${scenario} COMMAND test_gameplay_loop ${scenario})
endforeach()
add_test(NAME gameplay_inventory COMMAND test_inventory)
add_test(NAME gameplay_crafting_delivery COMMAND test_crafting_delivery)
