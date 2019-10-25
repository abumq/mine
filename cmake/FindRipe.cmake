#
# CMake module for Ripe cryptography wrapper
#
# Creates ${RIPE_INCLUDE_DIR} and ${RIPE_LIBRARY}
#
# If ${RIPE_USE_STATIC_LIBS} is ON then static libs are preferred over shared
#
# (c) 2017 Amrayn Web Services
#
# https://github.com/amrayn/ripe
# https://muflihun.com
#

message ("-- Ripe: Searching...")
set(RIPE_PATHS ${RIPE_ROOT} $ENV{RIPE_ROOT})

find_path(RIPE_INCLUDE_DIR
    Ripe.h
    PATH_SUFFIXES include
    PATHS ${RIPE_PATHS}
)

if (Ripe_USE_STATIC_LIBS)
    message ("-- Ripe: Static linking")
    find_library(RIPE_LIBRARY
        NAMES libripe.dylib libripe ripe
        HINTS "${CMAKE_PREFIX_PATH}/lib"
    )
else()
    message ("-- Ripe: Dynamic linking")
    find_library(RIPE_LIBRARY
        NAMES ripe libripe libripe.dylib
        HINTS "${CMAKE_PREFIX_PATH}/lib"
    )
endif()

message ("-- Ripe: Include: " ${RIPE_INCLUDE_DIR} ", Binary: " ${RIPE_LIBRARY})

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Ripe REQUIRED_VARS RIPE_INCLUDE_DIR RIPE_LIBRARY)
