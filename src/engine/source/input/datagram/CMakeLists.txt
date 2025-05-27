# src/engine/source/input/datagram/CMakeLists.txt

# Add the datagram_server.cpp source file to the engine_input library
# The engine_input library is expected to be defined in the parent CMakeLists.txt (source/input/CMakeLists.txt)
target_sources(engine_input PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/datagram_server.cpp
)

# The include directory for datagram_server.hpp should be made available
# to targets that link against engine_input. This is typically handled
# by setting INTERFACE_INCLUDE_DIRECTORIES on the engine_input target
# in its defining CMakeLists.txt (source/input/CMakeLists.txt).
# However, since datagram_server.hpp is in this directory,
# we can also ensure this directory is an include path for engine_input itself.
target_include_directories(engine_input INTERFACE
    ${CMAKE_CURRENT_LIST_DIR}
)
