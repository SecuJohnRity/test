# CMakeLists.txt for src/engine/source/fim_handler/
# Wazuh Engine - FIM Handler Module

# Define the library target
add_library(engine_fim_handler STATIC
    src/wazuh_db_fim_interface.cpp
    src/fim_engine_processor.cpp
)

# Public include directories (for headers in this module that other modules might need)
target_include_directories(engine_fim_handler PUBLIC
    # Path relative to this CMakeLists.txt, assuming headers are in include/fim_handler
    include
)

# Private include directories (for dependencies of this module's .cpp files)
target_include_directories(engine_fim_handler PRIVATE
    # For engine's base library headers (e.g., base/logging.hpp, base/json.hpp, base/event.hpp)
    # This path is relative to this CMakeLists.txt, going up to src/engine/source/ and then to base/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../base/include

    # For headers from other engine modules if needed (e.g., input_adapters for CleanedMessageData)
    ${CMAKE_CURRENT_SOURCE_DIR}/../input_adapters/include

    # For Wazuh C headers (e.g., shared/defs.h, os_net/os_net.h for socket operations)
    # This path assumes this CMakeLists.txt is at src/engine/source/fim_handler/
    # And Wazuh C headers are at src/headers/
    # The variable CMAKE_SOURCE_DIR in this context refers to the top-level CMakeLists.txt of the *engine*
    # If the engine is part of a larger Wazuh build, this might need to be ${WAZUH_ROOT_SOURCE_DIR}/src/headers
    # For now, assuming it's relative to the engine's root source directory.
    # If the engine's root CMakeLists.txt is at src/engine/, then CMAKE_SOURCE_DIR is src/engine/.
    # Thus, to get to /app/src/headers, it would be ${CMAKE_SOURCE_DIR}/../headers
    "${CMAKE_SOURCE_DIR}/../headers"  # Path to Wazuh C headers (e.g. /app/src/headers/)
)

# Link libraries
target_link_libraries(engine_fim_handler PRIVATE
    # Link against the engine's base library (where logging, json, event might be defined)
    base                 # From src/engine/source/base

    # Link against the input_adapters library (for CleanedMessageData struct, if not header-only)
    # If input_adapters is header-only for the struct definitions, this might not be strictly needed
    # but good to declare dependency if its headers are used.
    engine_input_adapters # From src/engine/source/input_adapters

    # Wazuh C library for socket operations (StartMQ, OS_SendUnix, etc. are in libwazuh.a)
    # The path to libwazuh.a needs to be correctly specified.
    # Assuming the engine's root CMakeLists.txt is at src/engine/
    # and libwazuh.a is at /app/src/libwazuh.a
    "${CMAKE_SOURCE_DIR}/../libwazuh.a" # Path to libwazuh.a (e.g. /app/src/libwazuh.a)
)

# Set folder property for IDE organization (optional)
set_target_properties(engine_fim_handler PROPERTIES FOLDER "Engine/Source/FIMHandler")

# Optional: Add compile definitions specific to this module if needed
# target_compile_definitions(engine_fim_handler PRIVATE -DSOME_FIM_SPECIFIC_DEFINE)

# Note: This CMakeLists.txt assumes it will be added via add_subdirectory() 
# from a parent CMakeLists.txt (e.g., src/engine/source/CMakeLists.txt).
# The parent CMakeLists.txt would typically handle setting CMAKE_CXX_STANDARD, etc.
# and the overall build type (Debug/Release).
#
# Ensure that the Wazuh C headers directory and libwazuh.a path are correctly resolved
# in the main CMake build configuration. The paths used here are conceptual based on
# a typical Wazuh source layout where the new engine is a subdirectory within 'src'.
#
# If ENGINE_ADAPT_TO_WAZUH_QUEUES is used to conditionally build this FIM module
# (because it depends on input_adapters which might be conditional), that logic
# would typically be in the parent CMakeLists.txt that includes this subdirectory.
# Example in parent:
# if(ENGINE_ADAPT_TO_WAZUH_QUEUES)
#   add_subdirectory(fim_handler)
# endif()
