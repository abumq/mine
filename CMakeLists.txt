cmake_minimum_required(VERSION 2.8.12)

project(Mine)

option (test_main_header "Test main header (mine.h)" OFF)
option (test_wstring_conversions "Test std::wstring (wchar_t*) conversions for encodings" ON)

set (MINE_VERSION "1.0.0")
set (MINE_SOVERSION "1.0.0")

add_definitions (-DMINE_VERSION="${MINE_VERSION}")

set (CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake")

set(MINE_INCLUDE_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/include" CACHE PATH "The directory the headers are installed in")

include_directories (${CMAKE_BINARY_DIR})
include_directories (${CMAKE_SOURCE_DIR})

include(FindPackageHandleStandardArgs)

# We need C++11
macro(require_cpp11)
        if (${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION} GREATER 3.0)
                # CMake 3.1 has built-in CXX standard checks.
                message("-- Setting C++11")
                set(CMAKE_CXX_STANDARD 11)
                set(CMAKE_CXX_STANDARD_REQUIRED on)
        else()
                if (CMAKE_CXX_COMPILER_ID MATCHES "GCC")
                    message ("-- GNU CXX (-std=c++11)")
                    list(APPEND CMAKE_CXX_FLAGS "-std=c++11")
                elseif (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
                    message ("-- CLang CXX (-std=c++11)")
                    list(APPEND CMAKE_CXX_FLAGS "-std=c++11")
                elseif (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
                    message ("-- GNU CXX (-std=c++11)")
                    list(APPEND CMAKE_CXX_FLAGS "-std=c++11")
                else()
                    message ("-- Requires C++11. Your compiler does not support it.")
                endif()
        endif()
endmacro()

# http://www.cmake.org/Wiki/CMake_RPATH_handling#Mac_OS_X_and_the_RPATH
if (APPLE)
    set(CMAKE_MACOSX_RPATH ON)
    set(CMAKE_SKIP_BUILD_RPATH FALSE)
    set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
    set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
    set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
    list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/lib" isSystemDir)
    if("${isSystemDir}" STREQUAL "-1")
        set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
    endif()
endif()

list (APPEND CMAKE_CXX_FLAGS " -Wall -Wextra -Wunused ")

require_cpp11()

# Check for cryptopp (static)
set(CryptoPP_USE_STATIC_LIBS ON)
find_package(CryptoPP REQUIRED)
message ("-- Crypto++ binary: " ${CRYPTOPP_LIBRARY})
include_directories (${CRYPTOPP_INCLUDE_DIRS})

# Check for include files and stdlib properties.
include (CheckIncludeFileCXX)
check_include_file_cxx (attr/xattr.h HAVE_ATTR_XATTR_H)
check_include_file_cxx (sys/xattr.h HAVE_SYS_XATTR_H)

# Check if xattr functions take extra arguments, as they do on OSX.
# Output error is misleading, so do this test quietly.
include (CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_QUIET_SAVE ${CMAKE_REQUIRED_QUIET})
set (CMAKE_REQUIRED_QUIET True)
check_cxx_source_compiles ("#include <sys/types.h>
#include <sys/xattr.h>
int main() { getxattr(0,0,0,0,0,0); return 1; }
" XATTR_ADD_OPT)
set (CMAKE_REQUIRED_QUIET ${CMAKE_REQUIRED_QUIET_SAVE})

# Reference all headers, to make certain IDEs happy.
file (GLOB_RECURSE all_headers ${CMAKE_SOURCE_DIR}/*.h)
add_custom_target (all_placeholder SOURCES ${all_headers})

#find_package(OPENSSL REQUIRED)
#if (OPENSSL_FOUND)
#    include_directories(${OPENSSL_INCLUDE_DIR})
#endif(OPENSSL_FOUND)

find_package(ZLIB REQUIRED)
if (ZLIB_FOUND)
    include_directories(${ZLIB_INCLUDE_DIRS})
endif(ZLIB_FOUND)

##########################################   CLI Tool  ###################################

add_executable (mine-cli cli/mine.cc
     src/base64.cc
     src/base16.cc
     src/aes.cc
     src/zlib.cc)

set_target_properties (mine-cli PROPERTIES
    OUTPUT_NAME "mine"
    VERSION ${MINE_VERSION}
)

target_link_libraries(mine-cli
    ${ZLIB_LIBRARIES}
    #${OPENSSL_CRYPTO_LIBRARY}
)

install (TARGETS mine-cli DESTINATION bin)

########################################## Unit Testing ###################################

# Check for Easylogging++
find_package(EASYLOGGINGPP REQUIRED)
include_directories (${EASYLOGGINGPP_INCLUDE_DIR})

find_package (gtest REQUIRED)

include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

enable_testing()

if (test_main_header)
    add_executable(mine-unit-tests
        test/main.cc
        package/mine.cc
        ${EASYLOGGINGPP_INCLUDE_DIR}/easylogging++.cc
    )

    target_compile_definitions (mine-unit-tests PUBLIC
        MINE_SINGLE_HEADER_TEST
    )
else()
    add_executable(mine-unit-tests
        test/main.cc
        src/rsa.cc
        src/aes.cc
        src/base16.cc
        src/base64.cc
        src/zlib.cc
        ${EASYLOGGINGPP_INCLUDE_DIR}/easylogging++.cc
    )
endif()

target_link_libraries(mine-unit-tests
    ${ZLIB_LIBRARIES}
)

if (test_wstring_conversions)
    target_compile_definitions (mine-unit-tests PUBLIC
        MINE_BASE64_WSTRING_CONVERSION
    )
endif()

target_compile_definitions (mine-unit-tests PUBLIC
    ELPP_STL_LOGGING
)

# Standard linking to gtest stuff.
target_link_libraries(mine-unit-tests gtest gtest_main)

# Extra linking for the project.
target_link_libraries(mine-unit-tests ${CRYPTOPP_LIBRARIES})

add_test(NAME mineUnitTests COMMAND mine-unit-tests)
