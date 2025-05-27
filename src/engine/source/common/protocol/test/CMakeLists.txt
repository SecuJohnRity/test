# src/engine/source/common/protocol/test/CMakeLists.txt

# This CMakeLists.txt is processed if tests are enabled.
# The condition to enable tests is typically managed in the parent CMakeLists.txt files
# (e.g., src/engine/CMakeLists.txt checks for ENGINE_BUILD_TEST)

if(ENGINE_BUILD_TEST)
    message(STATUS "Configuring datagram_parser_test...")

    # Find Google Test. GTest_FOUND will be true if found.
    # The main CMakeLists.txt should already handle find_package(GTest REQUIRED)
    # if ENGINE_BUILD_TEST is ON.
    if (NOT GTest_FOUND)
        message(FATAL_ERROR "Google Test (GTest) not found, but required for datagram_parser_test.")
    endif()

    add_executable(datagram_parser_test datagramParser_test.cpp)

    target_link_libraries(datagram_parser_test PRIVATE
        GTest::gtest_main # Links gtest and gtest_main
        engine_common     # Library containing datagramParser. Defined in source/common/CMakeLists.txt
        base              # For json::Json, base::Event, logging. Defined in source/base/CMakeLists.txt
                          # Add other direct dependencies of datagramParser.cpp or its headers if any.
    )

    # Include directories needed by datagramParser_test.cpp:
    # 1. To find "common/protocol/datagramParser.hpp" (SUT)
    #    engine_common should already make its interface includes available,
    #    which includes the path to datagramParser.hpp.
    # 2. To find "base/json.hpp", "base/logging.hpp" etc.
    #    The 'base' library target should make its interface includes available.
    #
    # If engine_common and base correctly declare their INTERFACE_INCLUDE_DIRECTORIES,
    # linking against them (as done above) should be sufficient for the compiler
    # to find their headers. Explicit target_include_directories here might not be
    # strictly necessary if dependencies are well-configured.
    # However, it can be added for clarity or if issues arise:
    # target_include_directories(datagram_parser_test PRIVATE
    #     ${CMAKE_SOURCE_DIR}/source/common/protocol # For datagramParser.hpp (if not covered by engine_common includes)
    #     ${CMAKE_SOURCE_DIR}/source/base/include    # For base headers (if not covered by base includes)
    # )
    # Note: ${CMAKE_CURRENT_SOURCE_DIR}/../../include was in the prompt, which would be source/common/include.
    # The datagramParser.hpp is in source/common/protocol/. engine_common's CMakeLists.txt
    # (source/common/protocol/CMakeLists.txt) adds CMAKE_CURRENT_LIST_DIR (i.e. protocol/)
    # to engine_common's INTERFACE_INCLUDE_DIRECTORIES. This should be sufficient.

    # Discover and add tests from the executable
    include(GoogleTest)
    gtest_discover_tests(datagram_parser_test)

    message(STATUS "datagram_parser_test configured.")
else()
    message(STATUS "Skipping datagram_parser_test configuration as ENGINE_BUILD_TEST is OFF.")
endif()
