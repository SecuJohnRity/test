# CMakeLists.txt for src/engine/source/syscollector_handler/
# Wazuh Engine - Syscollector Handler Module

# Define the library target
add_library(engine_syscollector_handler STATIC
    src/wazuh_db_syscollector_interface.cpp
    src/syscollector_engine_processor.cpp
)

# Public include directories (for headers in this module that other modules might need)
target_include_directories(engine_syscollector_handler PUBLIC
    # Path relative to this CMakeLists.txt, assuming headers are in include/syscollector_handler
    include
)

# Private include directories (for dependencies of this module's .cpp files)
target_include_directories(engine_syscollector_handler PRIVATE
    # For engine's base library headers (e.g., base/logging.hpp, base/json.hpp)
    ${CMAKE_CURRENT_SOURCE_DIR}/../base/include

    # For headers from other engine modules if needed (e.g., input_adapters for CleanedMessageData)
    ${CMAKE_CURRENT_SOURCE_DIR}/../input_adapters/include

    # For Wazuh C headers (e.g., shared/defs.h, os_net/os_net.h for socket operations)
    # Path relative to the engine's root CMakeLists.txt (src/engine/CMakeLists.txt)
    "${CMAKE_SOURCE_DIR}/../headers" 
)

# Link libraries
target_link_libraries(engine_syscollector_handler PRIVATE
    # Link against the engine's base library (where logging, json might be defined)
    base                 # From src/engine/source/base

    # Link against the input_adapters library (for CleanedMessageData struct, if not header-only)
    engine_input_adapters # From src/engine/source/input_adapters

    # Wazuh C library for socket operations (StartMQ, OS_SendUnix, etc. are in libwazuh.a)
    # Path relative to the engine's root CMakeLists.txt
    "${CMAKE_SOURCE_DIR}/../libwazuh.a" 
)

# Set folder property for IDE organization (optional)
set_target_properties(engine_syscollector_handler PROPERTIES FOLDER "Engine/Source/SyscollectorHandler")

# Note: This CMakeLists.txt assumes it will be added via add_subdirectory() 
# from a parent CMakeLists.txt (e.g., src/engine/source/CMakeLists.txt).
# The parent CMakeLists.txt would typically handle setting CMAKE_CXX_STANDARD, etc.
# and the overall build type (Debug/Release).
#
# Conditional build (e.g. based on ENGINE_ADAPT_TO_WAZUH_QUEUES or a specific FIM/Syscollector flag)
# should be handled in the parent CMakeLists.txt.
# Example in parent:
# if(ENGINE_PROCESS_SYSCOLLECTOR_DATA) # or similar flag
#   add_subdirectory(syscollector_handler)
# endif()
