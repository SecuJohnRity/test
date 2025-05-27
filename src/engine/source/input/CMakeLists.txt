# src/engine/source/input/CMakeLists.txt

# Define a new library for input modules
add_library(engine_input STATIC) # Or SHARED if appropriate

# Add the datagram subdirectory. The CMakeLists.txt there
# (src/engine/source/input/datagram/CMakeLists.txt)
# will add datagram_server.cpp to the engine_input target
# and set up include directories for engine_input.
add_subdirectory(datagram)

# Link engine_input with its dependencies.
# Common dependencies might include:
# - engine_common (for the datagramParser)
# - router_api (for IRouterAPI) - This might be an interface library or a concrete one
# - base_logging (for LOG_*) - This might be part of a 'base' library
# - Threads (for std::thread)
# Assuming engine_common, router_api, and base are available targets.
# router_api might be an interface library. Let's assume 'router' is the target name for the router library.
# base::logging might be part of a 'base' library.

target_link_libraries(engine_input PUBLIC
    engine_common # For datagramParser
    router        # For IRouterAPI (assuming 'router' is the library target for router components)
    base          # For logging and other base utilities
    Threads::Threads # For std::thread
)

# Public include directory for engine_input itself, if it has public headers directly in source/input
# target_include_directories(engine_input PUBLIC
#    ${CMAKE_CURRENT_LIST_DIR} 
# )
# The datagram/CMakeLists.txt should already make datagram_server.hpp available via engine_input's INTERFACE_INCLUDE_DIRECTORIES.
