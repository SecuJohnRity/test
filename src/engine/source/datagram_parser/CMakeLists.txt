cmake_minimum_required(VERSION 3.10)
project(DatagramParser)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_library(datagram_parser
    datagram_parser.cpp
    datagram_parser.hpp
)

target_include_directories(datagram_parser 
    PUBLIC 
        ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE
        # For base/json.hpp and other base includes
        ${CMAKE_SOURCE_DIR}/base/include 
)

target_link_libraries(datagram_parser 
    PRIVATE 
        base # Links jsoncpp transitively
)

# Optional: Add install rule
# install(TARGETS datagram_parser DESTINATION lib)
# install(FILES datagram_parser.hpp DESTINATION include/datagram_parser)

if(ENGINE_BUILD_TEST)
    enable_testing()
    find_package(GTest REQUIRED) # Makes GTest::gtest and GTest::gtest_main available

    add_executable(datagram_parser_test test/datagram_parser_test.cpp)

    target_link_libraries(datagram_parser_test 
        PRIVATE 
            datagram_parser 
            base # For json.hpp, timeUtils.hpp directly used in tests
            GTest::gtest 
            GTest::gtest_main
    )
    
    include(GoogleTest) # For gtest_discover_tests
    gtest_discover_tests(datagram_parser_test)
endif()
