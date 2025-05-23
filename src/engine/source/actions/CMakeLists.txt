# CMakeLists.txt for src/engine/source/actions/

# Add ar_action.cpp as a static library
add_library(ar_action STATIC 
    src/ar_action.cpp
)

# Public include directory for ar_action.hpp (e.g., if ar_action.hpp is in actions/include/actions)
target_include_directories(ar_action PUBLIC
    include 
)

# Private include directories needed to compile ar_action.cpp
target_include_directories(ar_action PRIVATE
    # Path to base::Event, base::Json, etc. (engine's own base library)
    ${CMAKE_CURRENT_SOURCE_DIR}/../base/include

    # Corrected path to Wazuh C headers relative to engine's root CMakeLists.txt
    # CMAKE_SOURCE_DIR for the engine is /app/src/engine
    "${CMAKE_SOURCE_DIR}/../src/headers"         # Accesses /app/src/headers
)

# Link ar_action against other engine libraries if needed (e.g., base for json::Json)
target_link_libraries(ar_action PRIVATE 
    base                                         # Engine's base library
    
    # Corrected path to libwazuh.a, built by the main Makefile in /app/src/
    # This assumes libwazuh.a is built and available at this location when CMake configures the engine.
    "${CMAKE_SOURCE_DIR}/../src/libwazuh.a"      # Accesses /app/src/libwazuh.a
)

# Add this library to a folder in IDEs (optional visual grouping)
set_target_properties(ar_action PROPERTIES FOLDER "Engine/Source/Actions")
