# CMakeLists.txt for the datagram module

# Define the sources for the datagram library
set(DATAGRAM_SOURCES
    datagram_socket.cpp
    legacy_message_parser.cpp
    overflow_handler.cpp
)

# Define the headers for the datagram library
set(DATAGRAM_HEADERS
    datagram_socket.h
    legacy_message_parser.h
    overflow_handler.h
)

# Add a library for the datagram module
add_library(datagram ${DATAGRAM_SOURCES} ${DATAGRAM_HEADERS})

# Specify include directories for the datagram library
target_include_directories(datagram PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# TODO: Add dependencies on other libraries if needed
# For example:
# target_link_libraries(datagram PRIVATE some_other_library)

# TODO: Add install rules if this library needs to be installed
# For example:
# install(TARGETS datagram DESTINATION lib)
# install(FILES ${DATAGRAM_HEADERS} DESTINATION include/datagram)

# Unit tests
if(ENGINE_BUILD_TEST)
    enable_testing()

    # Test sources
    set(DATAGRAM_TEST_SOURCES
        test/src/test_datagram_socket.cpp
        test/src/test_legacy_message_parser.cpp
        test/src/test_overflow_handler.cpp
    )

    # Create the test executable
    add_executable(datagram_test ${DATAGRAM_TEST_SOURCES})

    # Link the test executable against the datagram library and Google Test
    target_link_libraries(datagram_test PRIVATE datagram GTest::gtest GTest::gmock GTest::gtest_main)

    # Add the test to CTest
    add_test(NAME datagram_unit_tests COMMAND datagram_test)
endif()
