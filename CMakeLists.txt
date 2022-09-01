cmake_minimum_required(VERSION 3.15)

project(tdscpp VERSION 1.0)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(BUILD_SAMPLE        "Build sample program" ON)
option(WITH_OPENSSL        "Use OpenSSL for encryption" ON)

if(NOT WIN32)
    option(ENABLE_KRB5         "Enable Kerberos support" ON)
endif()

find_package(nlohmann_json REQUIRED)

if(ENABLE_KRB5)
    set(HAVE_GSSAPI 1)
endif()

if(NOT WIN32)
    find_package(ICU COMPONENTS uc REQUIRED)
endif()

find_package(fmt REQUIRED)

if(WITH_OPENSSL)
    find_package(OpenSSL REQUIRED)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)

add_definitions(-DTDSCPP_EXPORT)

# ----------------------------------------

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(SRC_FILES src/tdscpp.cpp
    src/bcp.cpp
    src/value.cpp
    src/ssl.cpp
    src/ringbuf.cpp
    src/rpc.cpp
    src/batch.cpp
    src/collation.cpp
    src/ver80coll.cpp
    src/ver90coll.cpp
    src/ver100coll.cpp
    src/ver140coll.cpp
    src/tests.cpp)

add_library(tdscpp SHARED ${SRC_FILES})

if(WIN32)
	add_definitions(-DNOMINMAX)
endif()

target_link_libraries(tdscpp fmt::fmt-header-only)
target_link_libraries(tdscpp nlohmann_json::nlohmann_json)

if(WITH_OPENSSL)
    target_link_libraries(tdscpp OpenSSL::Crypto OpenSSL::SSL)
endif()

if(NOT WIN32)
    target_link_libraries(tdscpp ICU::uc)
endif()

target_compile_options(tdscpp PRIVATE
     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
          -Wall>
     $<$<CXX_COMPILER_ID:MSVC>:
          /W4>)

set_target_properties(tdscpp PROPERTIES PUBLIC_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/src/tdscpp.h)

if(WIN32)
    set_target_properties(tdscpp PROPERTIES PREFIX "")
endif()

if(NOT MSVC)
    target_link_options(tdscpp PUBLIC -static-libgcc)
endif()

if(NOT MSVC)
	target_compile_options(tdscpp PUBLIC -Wall -Werror=cast-function-type -Wno-expansion-to-defined -Wunused-parameter -Wtype-limits -Wextra -Wconversion -fstrict-aliasing)
endif()

if(WIN32)
	target_link_libraries(tdscpp ws2_32 secur32 crypt32)
elseif(ENABLE_KRB5)
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

    add_executable(colltest src/colltest.cpp)
    target_link_libraries(colltest tdscpp fmt::fmt-header-only)
endif()
