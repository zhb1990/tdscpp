cmake_minimum_required(VERSION 3.10.1)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

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

set(SRC_FILES src/tdscpp.cpp)

add_library(tdscpp SHARED ${SRC_FILES})

if(WIN32)
	add_definitions(-DNOMINMAX)
endif()

target_link_libraries(tdscpp fmt::fmt-header-only)

target_compile_options(tdscpp PRIVATE
     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
          -Wall>
     $<$<CXX_COMPILER_ID:MSVC>:
          /W4>)

set_target_properties(tdscpp PROPERTIES PUBLIC_HEADER src/tdscpp.h)

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

install(TARGETS tdscpp
    EXPORT tdscpp-targets
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    PRIVATE_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(EXPORT tdscpp-targets DESTINATION lib/cmake/tdscpp)

configure_package_config_file(
    "tdscppConfig.cmake.in" "${CMAKE_CURRENT_BINARY_DIR}/tdscppConfig.cmake"
    INSTALL_DESTINATION "lib/cmake/tdscpp"
)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/tdscppConfig.cmake" DESTINATION "lib/cmake/tdscpp")

# ----------------------------------------

if(BUILD_SAMPLE)
    set(TEST_SRC_FILES src/tdscpp-test.cpp)

    add_executable(tdscpp-test ${TEST_SRC_FILES})
    target_link_libraries(tdscpp-test tdscpp)
    install(TARGETS tdscpp-test DESTINATION "${CMAKE_INSTALL_BINDIR}")
endif()
