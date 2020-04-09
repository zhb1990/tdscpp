cmake_minimum_required(VERSION 3.10.1)

include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckStructHasMember)
include(CheckCXXSourceCompiles)
include(GNUInstallDirs)

project(tdscpp VERSION 1.0)

option(WITH_OPENSSL        "Link in OpenSSL if found" ON)
option(ENABLE_ODBC_WIDE    "Enable ODBC wide character support" ON)
option(ENABLE_KRB5         "Enable Kerberos support" OFF)
option(ENABLE_ODBC_MARS    "Enable MARS" ON)
option(ENABLE_EXTRA_CHECKS "Enable internal extra checks, DO NOT USE in production" OFF)

if(WITH_OPENSSL)
find_package(OpenSSL)
endif(WITH_OPENSSL)

find_package(Threads)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DTDSCPP_EXPORT)

if(NOT WIN32)
set(UNIXODBC 1)
endif()

check_include_files(arpa/inet.h HAVE_ARPA_INET_H)
check_include_files(dirent.h HAVE_DIRENT_H)
check_include_files(errno.h HAVE_ERRNO_H)
check_include_files(fcntl.h HAVE_FCNTL_H)
check_include_files(getopt.h HAVE_GETOPT_H)
check_include_files(gnutls/abstract.h HAVE_GNUTLS_ABSTRACT_H)
check_include_files(inttypes.h HAVE_INTTYPES_H)
check_include_files(iodbcinst.h HAVE_IODBCINST_H)
check_include_files(langinfo.h HAVE_LANGINFO_H)
check_include_files(libgen.h HAVE_LIBGEN_H)
check_include_files(limits.h HAVE_LIMITS_H)
check_include_files(locale.h HAVE_LOCALE_H)
check_include_files(malloc.h HAVE_MALLOC_H)
check_include_files(netdb.h HAVE_NETDB_H)
check_include_files(netinet/in.h HAVE_NETINET_IN_H)
check_include_files(netinet/tcp.h HAVE_NETINET_TCP_H)
check_include_files(poll.h HAVE_POLL_H)
check_include_files(roken.h HAVE_ROKEN_H)
check_include_files(stdbool.h HAVE_STDBOOL_H)
check_include_files(stddef.h HAVE_STDDEF_H)
check_include_files(stdlib.h HAVE_STDLIB_H)
check_include_files(strings.h HAVE_STRINGS_H)
check_include_files(string.h HAVE_STRING_H)
check_include_files(sys/eventfd.h HAVE_SYS_EVENTFD_H)
check_include_files(sys/ioctl.h HAVE_SYS_IOCTL_H)
check_include_files(sys/select.h HAVE_SYS_SELECT_H)
check_include_files(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_files(sys/stat.h HAVE_SYS_STAT_H)
check_include_files(sys/time.h HAVE_SYS_TIME_H)
check_include_files(sys/types.h HAVE_SYS_TYPES_H)
check_include_files(unistd.h HAVE_UNISTD_H)
check_include_files(valgrind/memcheck.h HAVE_VALGRIND_MEMCHECK_H)
check_include_files(wchar.h HAVE_WCHAR_H)

if(OPENSSL_FOUND)
set(CMAKE_REQUIRED_LIBRARIES "-lcrypto")
check_symbol_exists(ASN1_STRING_get0_data openssl/asn1.h HAVE_ASN1_STRING_GET0_DATA)
check_symbol_exists(RSA_get0_key openssl/rsa.h HAVE_RSA_GET0_KEY)
check_symbol_exists(BIO_get_data openssl/bio.h HAVE_BIO_GET_DATA)
set(HAVE_OPENSSL 1)
endif(OPENSSL_FOUND)

set(CMAKE_REQUIRED_LIBRARIES "-lpthread")
check_symbol_exists(pthread_condattr_setclock pthread.h HAVE_PTHREAD_CONDATTR_SETCLOCK)

set(CMAKE_REQUIRED_LIBRARIES "")
check_function_exists(asprintf HAVE_ASPRINTF)
check_function_exists(basename HAVE_BASENAME)
check_function_exists(clock_gettime HAVE_CLOCK_GETTIME)
check_function_exists(daemon HAVE_DAEMON)
check_function_exists(eventfd HAVE_EVENTFD)
check_function_exists(gethrtime HAVE_GETHRTIME)
check_function_exists(getopt HAVE_GETOPT)
check_function_exists(getpwuid HAVE_GETPWUID)
check_function_exists(getpwuid_r HAVE_GETPWUID_R)
check_function_exists(gettimeofday HAVE_GETTIMEOFDAY)
check_function_exists(getuid HAVE_GETUID)
check_function_exists(gnutls_certificate_set_verify_function HAVE_GNUTLS_CERTIFICATE_SET_VERIFY_FUNCTION)
check_function_exists(gnutls_record_disable_padding HAVE_GNUTLS_RECORD_DISABLE_PADDING)
check_function_exists(gnutls_rnd HAVE_GNUTLS_RND)
check_function_exists(iconv HAVE_ICONV)
check_function_exists(nl_langinfo HAVE_NL_LANGINFO)
check_function_exists(poll HAVE_POLL)
check_function_exists(pthread_cond_timedwait HAVE_PTHREAD_COND_TIMEDWAIT)
check_function_exists(pthread_cond_timedwait_relative_np HAVE_PTHREAD_COND_TIMEDWAIT_RELATIVE_NP)
check_function_exists(readdir_r HAVE_READDIR_R)
check_function_exists(readpassphrase HAVE_READPASSPHRASE)
check_function_exists(socketpair HAVE_SOCKETPAIR)
check_function_exists(strlcat HAVE_STRLCAT)
check_function_exists(strlcpy HAVE_STRLCPY)
check_function_exists(strsep HAVE_STRSEP)
check_function_exists(strtok_r HAVE_STRTOK_R)
check_function_exists(strtok_s HAVE_STRTOK_S)
check_function_exists(vasprintf HAVE_VASPRINTF)
check_function_exists(_lock_file HAVE__LOCK_FILE)
check_function_exists(_unlock_file HAVE__UNLOCK_FILE)
check_function_exists(_xpg_accept HAVE__XPG_ACCEPT)
check_function_exists(_xpg_getpeername HAVE__XPG_GETPEERNAME)
check_function_exists(_xpg_getsockname HAVE__XPG_GETSOCKNAME)
check_function_exists(_xpg_getsockopt HAVE__XPG_GETSOCKOPT)
check_function_exists(_xpg_recvfrom HAVE__XPG_RECVFROM)
check_function_exists(__accept HAVE___ACCEPT)
check_function_exists(__getpeername HAVE___GETPEERNAME)
check_function_exists(__getsockname HAVE___GETSOCKNAME)
check_function_exists(__getsockopt HAVE___GETSOCKOPT)
check_function_exists(__recvfrom HAVE___RECVFROM)

if(NOT WIN32)
set(TIME_WITH_SYS_TIME 1)
endif()

if(CMAKE_USE_PTHREADS_INIT)
set(HAVE_PTHREAD 1)
set(TDS_HAVE_PTHREAD_MUTEX 1)
endif()

check_cxx_source_compiles("static void __attribute__((destructor)) my_uninit(void) {} int main() { return 0; }" TDS_ATTRIBUTE_DESTRUCTOR)

check_struct_has_member("struct tm" "tm_zone" "time.h" HAVE_STRUCT_TM_TM_ZONE)
check_struct_has_member("struct tm" "__tm_zone" "time.h" HAVE_STRUCT_TM___TM_ZONE)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(SRC_FILES tdscpp.cpp
    asprintf.c
    bjoern-utf8.c
    bulk.c
    challenge.c
    config.c
    convert.c
    data.c
    des.c
    getmac.c
    gettimeofday.c
    hmac_md5.c
    iconv.c
    locale.c
    log.c
    login.c
    md4.c
    md5.c
    mem.c
    net.c
    numeric.c
    odbc_data.c
    packet.c
    poll.c
    query.c
    random.c
    read.c
    replacement_iconv.c
    sec_negotiate.c
    socketpair.c
    stream.c
    strlcpy.c
    tds_cond.c
    tdsstring.c
    threadsafe.c
    tls.c
    token.c
    util.c
    vasprintf.c
    win_mutex.c
    write.c)

add_library(tdscpp SHARED ${SRC_FILES})

if(OPENSSL_FOUND)
target_link_libraries(tdscpp OpenSSL::SSL)
target_link_libraries(tdscpp OpenSSL::Crypto)
endif(OPENSSL_FOUND)

if(WIN32)
target_link_libraries(tdscpp wsock32 ws2_32)
endif()

target_compile_options(tdscpp PRIVATE
     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
          -Wall>
     $<$<CXX_COMPILER_ID:MSVC>:
          /W4>)

install(TARGETS tdscpp DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})
install(FILES tdscpp.h DESTINATION include)
