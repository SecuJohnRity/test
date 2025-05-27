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
