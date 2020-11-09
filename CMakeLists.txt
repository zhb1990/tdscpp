cmake_minimum_required(VERSION 3.10.1)

project(tdscpp VERSION 1.0)

option(WITH_JSON           "Include JSON support" ON)
option(BUILD_SAMPLE        "Build sample program" ON)

if(WITH_JSON)
find_package(nlohmann_json REQUIRED)
endif()

find_package(fmt REQUIRED)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

add_definitions(-DTDSCPP_EXPORT)

# ----------------------------------------

set(NEW_SRC_FILES src/tdscpp.cpp
	src/tdscpp-test.cpp)

add_executable(tdscpp ${NEW_SRC_FILES})

if(WIN32)
	add_definitions(-DNOMINMAX)
endif()

find_package(fmt REQUIRED)
target_link_libraries(tdscpp fmt::fmt-header-only)

target_compile_options(tdscpp PRIVATE
     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
          -Wall>
     $<$<CXX_COMPILER_ID:MSVC>:
          /W4>)

if(NOT MSVC)
    target_link_options(tdscpp PUBLIC -static-libgcc)
endif()

if(NOT MSVC)
	target_compile_options(tdscpp PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion)
endif()

if(WIN32)
	target_link_libraries(tdscpp ws2_32 secur32)
else()
	target_link_libraries(tdscpp gssapi_krb5)
endif()
