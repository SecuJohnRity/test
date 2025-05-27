# src/engine/source/common/protocol/CMakeLists.txt
# Add sources to the parent library (engine_common)
target_sources(engine_common PRIVATE
    datagramParser.cpp
)
# Ensure parent's include directory can see datagramParser.hpp
target_include_directories(engine_common INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}
)

# Add tests if ENGINE_BUILD_TEST is enabled (typically set in the root CMakeLists.txt)
if(ENGINE_BUILD_TEST)
    add_subdirectory(test)
endif()
