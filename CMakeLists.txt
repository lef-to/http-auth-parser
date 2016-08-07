cmake_minimum_required (VERSION 2.6)

project (http_auth_parser C)

set (http_auth_parser_VERSION_MAJOR 0)
set (http_auth_parser_VERSION_MINOR 1)
set (http_auth_parser_VERSION_PATCH 0)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release")
endif ()
set (CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE} CACHE STRING "")

add_library (http_auth_parser STATIC
    http_auth_parser.c
    )

add_executable (http_auth_parser_example
    example.c
    )

target_link_libraries (http_auth_parser_example
    http_auth_parser
    )
