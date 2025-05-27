# src/engine/source/common/CMakeLists.txt
add_library(engine_common INTERFACE) # Or a static/shared library
target_include_directories(engine_common INTERFACE
    ${CMAKE_CURRENT_LIST_DIR} # if headers are directly in common/
)
# Add protocol subdirectory
add_subdirectory(protocol)
