#
# CMake module for Mine (minimal crypto library) 
#
# Defines ${MINE_CRYPTO_INCLUDE_DIR}
#
# If ${MINE_CRYPTO_USE_STATIC_LIBS} is ON then static libs are searched.
# In these cases ${MINE_CRYPTO_LIBRARY} is also defined
#
# (c) 2017 Amrayn Web Services
#
# https://github.com/amrayn/mine
# https://muflihun.com
#

message ("-- Mine: Searching...")
set(MINE_PATHS ${MINE_CRYPTO_ROOT} $ENV{MINE_CRYPTO_ROOT})

find_path(MINE_CRYPTO_INCLUDE_DIR
        mine.h
        PATH_SUFFIXES include
        PATHS ${MINE_CRYPTO_PATHS}
)

if (MINE_CRYPTO_USE_STATIC_LIBS)
    message ("-- Mine: Searching static libraries")
    find_library(MINE_CRYPTO_LIBRARY
        NAMES libmine.a libmine.lib
        HINTS "${CMAKE_PREFIX_PATH}/lib"
    )
elseif (MINE_CRYPTO_USE_SHARED_LIBS)
    message ("-- Mine: Searching shared libraries")
    find_library(MINE_CRYPTO_LIBRARY
        NAMES libmine.dylib libmine.so libmine.dll
        HINTS "${CMAKE_PREFIX_PATH}/lib"
    )
endif()

find_package_handle_standard_args(MINE_CRYPTO REQUIRED_VARS MINE_CRYPTO_INCLUDE_DIR)
