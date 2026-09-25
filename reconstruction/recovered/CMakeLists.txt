cmake_minimum_required(VERSION 3.16)
project(BlockheadsRecoveredView LANGUAGES CXX)

add_library(blockheads_recovered_view STATIC
    gameview_update.cpp projection_update.cpp world_view_contracts.cpp world_translation.cpp sound_manager.cpp gameview_input.cpp gameview_starttouch.cpp
    pinch_return.cpp translation_return.cpp zoom_settle.cpp)
target_include_directories(blockheads_recovered_view PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(blockheads_recovered_view PUBLIC cxx_std_17)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(blockheads_recovered_view PUBLIC -fno-fast-math -ffp-contract=off)
endif()

# Inventory methods are a distinct recovered module, not the replacement Player.
add_library(blockheads_recovered_inventory STATIC
    inventory_item.cpp inventory_capacity.cpp inventory_rules.cpp inventory_add.cpp inventory_pickup.cpp inventory_ownership.cpp inventory_pickup_currency.cpp)
target_include_directories(blockheads_recovered_inventory PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(blockheads_recovered_inventory PUBLIC cxx_std_17)

# NPC loader slice (read-back line, batch b4a): recovered contract for
# -[NPC initWithWorld:dynamicWorld:saveDict:cache:]'s hunger-timer seed.
add_library(blockheads_recovered_npc STATIC npc_init_with_world.cpp)
target_include_directories(blockheads_recovered_npc PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(blockheads_recovered_npc PUBLIC cxx_std_17)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(blockheads_recovered_npc PUBLIC -fno-fast-math -ffp-contract=off)
endif()

# NPC state-load slice (read-back line, batch b4f): recovered contract for
# -[NPC loadValuesFromSaveDict:]'s 15 key chains, group gates and the
# tameCountsByClientID dictionary copy.
add_library(blockheads_recovered_npc_load_values STATIC npc_load_values_from_save_dict.cpp)
target_include_directories(blockheads_recovered_npc_load_values PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(blockheads_recovered_npc_load_values PUBLIC cxx_std_17)

# Tree growth state machine slice (read-back line, batch b4g, stage 1):
# recovered contract for -[Tree growInTimeSinceSaved:] nil-tile path.
add_library(blockheads_recovered_tree_grow STATIC tree_grow_in_time.cpp)
target_include_directories(blockheads_recovered_tree_grow PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(blockheads_recovered_tree_grow PUBLIC cxx_std_17)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(blockheads_recovered_tree_grow PUBLIC -fno-fast-math -ffp-contract=off)
endif()

# Plant read-back slice (batch b4b): recovered contract for
# -[Plant loadSaveDictValues:] including the 0x004c0b70 clamp helper.
add_library(blockheads_recovered_plant STATIC plant_load_save_dict.cpp)
target_include_directories(blockheads_recovered_plant PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(blockheads_recovered_plant PUBLIC cxx_std_17)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(blockheads_recovered_plant PUBLIC -fno-fast-math -ffp-contract=off)
endif()

# Forwarder convention slice (batch b4c): recovered contract shared by the five
# 74-word initWithWorld:dynamicWorld:saveDict:cache: forwarders.
add_library(blockheads_recovered_forwarder STATIC object_forwarder_init.cpp)
target_include_directories(blockheads_recovered_forwarder PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(blockheads_recovered_forwarder PUBLIC cxx_std_17)

# Tree loader stage-1 slice (batch b4d): recovered contract for the scalar
# chains, the treeFruit reset/enumeration entry and the isStaticTree gate.
add_library(blockheads_recovered_tree_stage1 STATIC tree_load_save_dict.cpp)
add_library(blockheads_recovered_tree_records STATIC tree_load_records.cpp)
target_include_directories(blockheads_recovered_tree_records PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(blockheads_recovered_tree_records PUBLIC cxx_std_17)
target_include_directories(blockheads_recovered_tree_stage1 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(blockheads_recovered_tree_stage1 PUBLIC cxx_std_17)

# FreightCar loader slice (batch b4h): 4th selector variant front member
add_library(blockheads_recovered_freight_car STATIC freight_car_init.cpp)
target_include_directories(blockheads_recovered_freight_car PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(blockheads_recovered_freight_car PUBLIC cxx_std_17)

# TradePortal price offsets slice (batch b4i): price normalization loop and clamp
add_library(blockheads_recovered_trade_portal_offsets STATIC trade_portal_price_offsets.cpp)
target_include_directories(blockheads_recovered_trade_portal_offsets PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(blockheads_recovered_trade_portal_offsets PUBLIC cxx_std_17)

# TradingPost slot initialization slice (batch b4j): sellSlot restoration and itemType != 11 filter
add_library(blockheads_recovered_trading_post_slots STATIC trading_post_init_slots.cpp)
target_include_directories(blockheads_recovered_trading_post_slots PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(blockheads_recovered_trading_post_slots PUBLIC cxx_std_17)

# DynamicObject derived stuff slice (batch b4k): macroTile registration and physical block loading
add_library(blockheads_recovered_dynamic_object_derived STATIC dynamic_object_init_derived_stuff.cpp)
target_include_directories(blockheads_recovered_dynamic_object_derived PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(blockheads_recovered_dynamic_object_derived PUBLIC cxx_std_17)

# Chest loader slice (batch b4m): the save-system centerpiece — five own keys
# (two of them formatted per-slot families), InventoryItem child construction,
# the private 0x00CB623C capacity rule and the shelf restore loop.
add_library(blockheads_recovered_chest STATIC chest_init_with_world.cpp)
target_include_directories(blockheads_recovered_chest PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(blockheads_recovered_chest PUBLIC cxx_std_17)

# KelpPlant BIG loader slice (batch b4n): the long-variant plant loader —
# lrand48 food refill, the age/saveTime gate with the compost elapsed rewrite
# and the multi-tile growth loop with world tile queries.
add_library(blockheads_recovered_kelp STATIC kelp_plant_init.cpp)
target_include_directories(blockheads_recovered_kelp PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(blockheads_recovered_kelp PUBLIC cxx_std_17)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(blockheads_recovered_kelp PUBLIC -fno-fast-math -ffp-contract=off)
endif()

# VinePlant BIG loader slice (batch b4o): KelpPlant's mirror twin — inverted
# tile-kind gate, the light/sun suitability key, marker 0x7C and energy 900.
add_library(blockheads_recovered_vine STATIC vine_plant_init.cpp)
target_include_directories(blockheads_recovered_vine PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(blockheads_recovered_vine PUBLIC cxx_std_17)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(blockheads_recovered_vine PUBLIC -fno-fast-math -ffp-contract=off)
endif()

# b4p: FreeBlock exact-variant loader (1,347w). The 12-key walk, the
# array-of-arrays subItems loop, the 64-bit priority resolution, the
# hovers/creationTime>900s gate with the probed itemType blacklists, the
# creationTime re-anchor and the max-16 ground-fall loop.
add_library(blockheads_recovered_freeblock STATIC freeblock_init.cpp)
target_include_directories(blockheads_recovered_freeblock PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(blockheads_recovered_freeblock PUBLIC cxx_std_17)
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(blockheads_recovered_freeblock PUBLIC -fno-fast-math -ffp-contract=off)
endif()

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    include(CTest)
    if(BUILD_TESTING)
        foreach(inventory_part item capacity rules add chain pickup ownership pickup_currency)
            add_executable(test_inventory_${inventory_part} ../../tools/test_inventory_${inventory_part}.cpp)
            target_link_libraries(test_inventory_${inventory_part} PRIVATE blockheads_recovered_inventory)
            target_compile_options(test_inventory_${inventory_part} PRIVATE -UNDEBUG)
            add_test(NAME recovered_inventory_${inventory_part} COMMAND test_inventory_${inventory_part})
        endforeach()
        add_executable(test_npc_init_with_world ../../tools/test_npc_init_with_world.cpp)
        target_link_libraries(test_npc_init_with_world PRIVATE blockheads_recovered_npc)
        target_compile_options(test_npc_init_with_world PRIVATE -UNDEBUG)
        add_test(NAME recovered_npc_init_with_world COMMAND test_npc_init_with_world)
        add_executable(test_npc_load_values ../../tools/test_npc_load_values.cpp)
        target_link_libraries(test_npc_load_values PRIVATE blockheads_recovered_npc_load_values)
        target_compile_options(test_npc_load_values PRIVATE -UNDEBUG)
        add_test(NAME recovered_npc_load_values COMMAND test_npc_load_values)
        add_executable(test_tree_grow_in_time ../../tools/test_tree_grow_in_time.cpp)
        target_link_libraries(test_tree_grow_in_time PRIVATE blockheads_recovered_tree_grow)
        target_compile_options(test_tree_grow_in_time PRIVATE -UNDEBUG)
        add_test(NAME recovered_tree_grow_in_time COMMAND test_tree_grow_in_time)
        add_executable(test_plant_load_save_dict ../../tools/test_plant_load_save_dict.cpp)
        target_link_libraries(test_plant_load_save_dict PRIVATE blockheads_recovered_plant)
        target_compile_options(test_plant_load_save_dict PRIVATE -UNDEBUG)
        add_test(NAME recovered_plant_load_save_dict COMMAND test_plant_load_save_dict)
        add_executable(test_object_forwarder_init ../../tools/test_object_forwarder_init.cpp)
        target_link_libraries(test_object_forwarder_init PRIVATE blockheads_recovered_forwarder)
        target_compile_options(test_object_forwarder_init PRIVATE -UNDEBUG)
        add_test(NAME recovered_object_forwarder_init COMMAND test_object_forwarder_init)
        add_executable(test_tree_load_save_dict_stage1 ../../tools/test_tree_load_save_dict.cpp)
        target_link_libraries(test_tree_load_save_dict_stage1 PRIVATE blockheads_recovered_tree_stage1)
        target_compile_options(test_tree_load_save_dict_stage1 PRIVATE -UNDEBUG)
        add_test(NAME recovered_tree_load_save_dict_stage1 COMMAND test_tree_load_save_dict_stage1)
        add_executable(test_tree_load_records ../../tools/test_tree_load_records.cpp)
        target_link_libraries(test_tree_load_records PRIVATE blockheads_recovered_tree_records)
        target_compile_options(test_tree_load_records PRIVATE -UNDEBUG)
        add_test(NAME recovered_tree_load_records COMMAND test_tree_load_records)
        add_executable(test_freight_car_init ../../tools/test_freight_car_init.cpp)
        target_link_libraries(test_freight_car_init PRIVATE blockheads_recovered_freight_car)
        target_compile_options(test_freight_car_init PRIVATE -UNDEBUG)
        add_test(NAME recovered_freight_car_init COMMAND test_freight_car_init)
        add_executable(test_trade_portal_price_offsets ../../tools/test_trade_portal_price_offsets.cpp)
        target_link_libraries(test_trade_portal_price_offsets PRIVATE blockheads_recovered_trade_portal_offsets)
        target_compile_options(test_trade_portal_price_offsets PRIVATE -UNDEBUG)
        add_test(NAME recovered_trade_portal_price_offsets COMMAND test_trade_portal_price_offsets)
        add_executable(test_trading_post_init_slots ../../tools/test_trading_post_init_slots.cpp)
        target_link_libraries(test_trading_post_init_slots PRIVATE blockheads_recovered_trading_post_slots)
        target_compile_options(test_trading_post_init_slots PRIVATE -UNDEBUG)
        add_test(NAME recovered_trading_post_init_slots COMMAND test_trading_post_init_slots)
        add_executable(test_dynamic_object_init_derived ../../tools/test_dynamic_object_init_derived_stuff.cpp)
        target_link_libraries(test_dynamic_object_init_derived PRIVATE blockheads_recovered_dynamic_object_derived)
        target_compile_options(test_dynamic_object_init_derived PRIVATE -UNDEBUG)
        add_test(NAME recovered_dynamic_object_init_derived COMMAND test_dynamic_object_init_derived)
        add_executable(test_chest_init_with_world ../../tools/test_chest_init_with_world.cpp)
        target_link_libraries(test_chest_init_with_world PRIVATE blockheads_recovered_chest)
        target_compile_options(test_chest_init_with_world PRIVATE -UNDEBUG)
        add_test(NAME recovered_chest_init_with_world COMMAND test_chest_init_with_world)
        add_executable(test_kelp_plant_init ../../tools/test_kelp_plant_init.cpp)
        target_link_libraries(test_kelp_plant_init PRIVATE blockheads_recovered_kelp)
        target_compile_options(test_kelp_plant_init PRIVATE -UNDEBUG)
        add_test(NAME recovered_kelp_plant_init COMMAND test_kelp_plant_init)
        add_executable(test_vine_plant_init ../../tools/test_vine_plant_init.cpp)
        target_link_libraries(test_vine_plant_init PRIVATE blockheads_recovered_vine)
        target_compile_options(test_vine_plant_init PRIVATE -UNDEBUG)
        add_test(NAME recovered_vine_plant_init COMMAND test_vine_plant_init)

        add_executable(test_freeblock_init ../../tools/test_freeblock_init.cpp)
        target_link_libraries(test_freeblock_init PRIVATE blockheads_recovered_freeblock)
        target_compile_options(test_freeblock_init PRIVATE -UNDEBUG)
        add_test(NAME recovered_freeblock_init COMMAND test_freeblock_init)
        add_executable(test_gameview_update ../../tools/test_gameview_update.cpp)
        target_link_libraries(test_gameview_update PRIVATE blockheads_recovered_view)
        add_test(NAME gameview_update COMMAND test_gameview_update)
        add_executable(test_projection_update ../../tools/test_projection_update.cpp)
        target_link_libraries(test_projection_update PRIVATE blockheads_recovered_view)
        add_test(NAME projection_update COMMAND test_projection_update)
        add_executable(test_world_view_contracts ../../tools/test_world_view_contracts.cpp)
        target_link_libraries(test_world_view_contracts PRIVATE blockheads_recovered_view)
        add_test(NAME world_view_contracts COMMAND test_world_view_contracts)
        add_executable(test_world_translation ../../tools/test_world_translation.cpp)
        target_link_libraries(test_world_translation PRIVATE blockheads_recovered_view)
        add_test(NAME world_translation COMMAND test_world_translation)
        add_executable(test_sound_manager ../../tools/test_sound_manager.cpp)
        target_link_libraries(test_sound_manager PRIVATE blockheads_recovered_view)
        add_test(NAME sound_manager COMMAND test_sound_manager)
        add_executable(test_gameview_input gameview_input_test.cpp)
        target_compile_options(test_gameview_input PRIVATE -UNDEBUG)
        target_link_libraries(test_gameview_input PRIVATE blockheads_recovered_view)
        add_test(NAME gameview_input COMMAND test_gameview_input)
        add_executable(test_gameview_starttouch ../../tools/test_gameview_starttouch.cpp)
        target_link_libraries(test_gameview_starttouch PRIVATE blockheads_recovered_view)
        add_test(NAME gameview_starttouch COMMAND test_gameview_starttouch)
        # Standalone numerical recoveries also remain independently executable.
        foreach(slice scroll_inertia pinch_return pinch_inertia translation_return zoom_settle zoom_initial_cap)
            add_executable(test_${slice} ../../tools/test_${slice}.cpp ${slice}.cpp)
            target_include_directories(test_${slice} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
            target_compile_features(test_${slice} PRIVATE cxx_std_17)
            target_compile_options(test_${slice} PRIVATE -UNDEBUG -fno-fast-math -ffp-contract=off)
            add_test(NAME ${slice} COMMAND test_${slice})
        endforeach()
        find_package(ZLIB REQUIRED)
        add_library(original_save_decoder STATIC ../../app/src/main/cpp/original_save_format.cpp)
        target_include_directories(original_save_decoder PUBLIC ../../app/src/main/cpp)
        target_compile_features(original_save_decoder PUBLIC cxx_std_17)
        target_link_libraries(original_save_decoder PUBLIC ZLIB::ZLIB)
        add_executable(decode_original_block ../../tools/decode_original_block.cpp)
        target_link_libraries(decode_original_block PRIVATE original_save_decoder)
        add_executable(test_original_save_format ../../tools/test_original_save_format.cpp)
        target_link_libraries(test_original_save_format PRIVATE original_save_decoder)
        add_test(NAME original_save_format COMMAND test_original_save_format)
        # Real replacement-gameplay contracts are separate from recovered-method
        # evidence, but run in the same O0/O2 CI batch and preserve assertions.
        add_subdirectory(../../tools/gameplay ${CMAKE_CURRENT_BINARY_DIR}/gameplay)
        add_library(original_client_world STATIC original_client_world.cpp)
        target_include_directories(original_client_world PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
        target_compile_features(original_client_world PUBLIC cxx_std_17)
        add_executable(test_original_client_world ../../tools/test_original_client_world.cpp)
        target_link_libraries(test_original_client_world PRIVATE original_client_world)
        target_compile_options(test_original_client_world PRIVATE -UNDEBUG)
        add_test(NAME original_client_world COMMAND test_original_client_world)
        # Client assembly app skeleton (batch b5a): the app-side original-save
        # load path — block domain, dynamic index, SaveDict stub layer and the
        # 1..64 dynamic object registry whose entries start as stubs. The
        # sources live in app/src/main/cpp so the production APK builds the same
        # files; this host target is what CI compiles and tests.
        add_library(original_client_app STATIC
            ../../app/src/main/cpp/original_save_dict.cpp
            ../../app/src/main/cpp/dynamic_object_registry.cpp
            ../../app/src/main/cpp/original_client_app.cpp
            original_client_world.cpp)
        target_include_directories(original_client_app PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}
            ../../app/src/main/cpp)
        target_compile_features(original_client_app PUBLIC cxx_std_17)
        add_executable(test_original_client_app ../../tools/test_original_client_app.cpp)
        target_link_libraries(test_original_client_app PRIVATE original_client_app)
        target_compile_options(test_original_client_app PRIVATE -UNDEBUG)
        add_test(NAME original_client_app COMMAND test_original_client_app)
        add_executable(client_app_skeleton_cli ../../tools/client_app_skeleton_cli.cpp)
        target_link_libraries(client_app_skeleton_cli PRIVATE original_client_app)
        # Tests using assert must still exercise their contracts in Release.
        foreach(test_target test_gameview_update test_projection_update test_world_view_contracts test_world_translation test_sound_manager test_original_save_format test_gameview_starttouch test_original_client_world)
            target_compile_options(${test_target} PRIVATE -UNDEBUG)
        endforeach()
    endif()
endif()
