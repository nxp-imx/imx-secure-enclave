#
# Check zlib is present or build it to install it in the ZLIB_EXPORT
#
if(NOT DEFINED CMAKE_FIND_LIBRARY_PREFIXES)
   set(CMAKE_FIND_LIBRARY_PREFIXES "lib")
endif()

if(NOT DEFINED CMAKE_FIND_LIBRARY_SUFFIXES)
   set(CMAKE_FIND_LIBRARY_SUFFIXES ".so")
endif()

if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
   message(FATAL_ERROR "-DCMAKE_TOOLCHAIN_FILE=<toolchain file> missing")
endif()

if(NOT DEFINED ZLIB_ROOT)
    message(FATAL_ERROR "-DZLIB_ROOT=<zlib export path> missing")
endif()

if(NOT IS_ABSOLUTE ${ZLIB_ROOT})
    set(ZLIB_ROOT "${CMAKE_SOURCE_DIR}/${ZLIB_ROOT}")
endif()

include(${CMAKE_TOOLCHAIN_FILE})

set(ZLIB_NAME "zlib")
set(ZLIB_VERSION "1.2.11" CACHE STRING "Default zlib Version")
set(ZLIB_HASH "SHA256=c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1")
set(ZLIB_URL "http://www.zlib.net/fossils")
set(ZLIB_AR_DIR "${ZLIB_NAME}-${ZLIB_VERSION}")
set(ZLIB_ARCHIVE "${ZLIB_AR_DIR}.tar.gz")

list(APPEND CMAKE_MODULE_PATH PATHS ./cmake)
include(GNUInstallDirs)
find_package(ZLIBLight)

if(ZLIB_FOUND)
    message(STATUS "zlib already installed")
    return()
endif()

if(NOT DEFINED ZLIB_SRC_PATH)
    message(FATAL_ERROR "-DZLIB_SRC_PATH=<seco source path> missing")
endif()
if(NOT IS_ABSOLUTE ${ZLIB_SRC_PATH})
    set(ZLIB_SRC_PATH"${CMAKE_SOURCE_DIR}/${ZLIB_SRC_PATH}")
endif()

set(ZLIB_SRC "${ZLIB_SRC_PATH}/${ZLIB_AR_DIR}")

if(NOT EXISTS ${ZLIB_SRC})
    find_file(ZLIB_ARCHIVE_PATH ${ZLIB_ARCHIVE} ${ZLIB_SRC_PATH})
    if(NOT ZLIB_ARCHIVE_PATH)
        message(STATUS "Downloading ${ZLIB_ARCHIVE} from ${ZLIB_URL}")
        file(DOWNLOAD
             "${ZLIB_URL}/${ZLIB_ARCHIVE}"
             "${ZLIB_SRC_PATH}/${ZLIB_ARCHIVE}"
             EXPECTED_HASH ${ZLIB_HASH})
    endif()

    message(STATUS "Extracting ${ZLIB_ARCHIVE}")
    execute_process(COMMAND ${CMAKE_COMMAND} -E tar xf ${ZLIB_ARCHIVE}
                    WORKING_DIRECTORY ${ZLIB_SRC_PATH}
                    RESULT_VARIABLE res)

    if(NOT ${res} EQUAL 0)
        message(FATAL_ERROR "Cannot extract zlib :${res}")
    endif()
endif()

#
# Build library
#
set(ENV{CC} ${CMAKE_C_COMPILER})
set(ENV{AR} ${CMAKE_AR})

message(STATUS "Configuring ${ZLIB_AR_DIR}")
set(ZLIB_CONFIGURE "./configure")
set(ZLIB_CONFIGURE_ARGS "--prefix=${ZLIB_ROOT}" "--enable-shared")
message(STATUS "Executing ${ZLIB_CONFIGURE} ${ZLIB_CONFIGURE_ARGS}")
execute_process(COMMAND ${ZLIB_CONFIGURE} ${ZLIB_CONFIGURE_ARGS}
                WORKING_DIRECTORY ${ZLIB_SRC}
                RESULT_VARIABLE res)

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "Cannot configure zlib ${res}")
endif()

message(STATUS "Installing ${ZLIB_AR_DIR}")
set(ZLIB_MAKE_ARGS clean all install)
execute_process(COMMAND make ${ZLIB_MAKE_ARGS}
                WORKING_DIRECTORY ${ZLIB_SRC}
                RESULT_VARIABLE res)

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "Cannot install zlib ${res}")
endif()
