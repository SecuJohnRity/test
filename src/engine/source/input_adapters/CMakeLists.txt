# CMakeLists.txt for src/engine/source/input_adapters/
# Wazuh Engine - Input Adapters Module

add_library(engine_input_adapters STATIC
    src/wazuh_queue_reader.cpp
    src/wazuh_message_cleaner.cpp
)

target_include_directories(engine_input_adapters PUBLIC
    # For headers within this module (e.g., wazuh_queue_reader.hpp)
    # Assuming they are in an 'include/input_adapters' subdirectory relative to this CMakeLists.txt
    # or directly under 'include' if the .hpp files are placed there.
    # Adjust if headers are directly in src/
    include 
)

target_include_directories(engine_input_adapters PRIVATE
    # For engine's base library headers (e.g., base/logging.hpp, base/event.hpp)
    ${CMAKE_CURRENT_SOURCE_DIR}/../base/include

    # For Wazuh C headers (e.g., shared/defs.h, shared/mq_op.h, os_net/os_net.h)
    # Path relative to the engine's root CMakeLists.txt (src/engine/CMakeLists.txt)
    "${CMAKE_SOURCE_DIR}/../src/headers"
)

target_link_libraries(engine_input_adapters PRIVATE 
    base # Engine's base C++ library

    # Wazuh C library for MQ and Net ops
    # Path relative to the engine's root CMakeLists.txt
    "${CMAKE_SOURCE_DIR}/../src/libwazuh.a"
)

set_target_properties(engine_input_adapters PROPERTIES FOLDER "Engine/Source/InputAdapters")

# Ensure this module is built if ENGINE_ADAPT_TO_WAZUH_QUEUES is defined (or similar PoC flag)
# This can be handled by ensuring the main CMakeLists.txt only adds this subdirectory if that flag is set,
# or by adding a conditional build here, though the former is cleaner.
# For now, assume it's always built if this CMakeLists.txt is processed.
