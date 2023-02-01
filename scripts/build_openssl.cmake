#
# Check openssl is present or build it to install it in the OPENSSL_EXPORT
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

if(NOT DEFINED OPENSSL_ROOT)
    message(FATAL_ERROR "-DOPENSSL_ROOT=<openssl export path> missing")
endif()

if(NOT IS_ABSOLUTE ${OPENSSL_ROOT})
    set(OPENSSL_ROOT "${CMAKE_SOURCE_DIR}/${OPENSSL_ROOT}")
endif()

include(${CMAKE_TOOLCHAIN_FILE})

set(OPENSSL_NAME "openssl")
#set(OPENSSL_VERSION "31.2.11" CACHE STRING "Default openssl Version")
#set(OPENSSL_HASH "SHA256=c3e5e9fdd5004dcb542feda5ee4f0ff0744628baf8ed2dd5d66f8ca1197cb1a1")
#set(OPENSSL_URL "http://www.openssl.net/fossils")
#set(OPENSSL_AR_DIR "${OPENSSL_NAME}-${OPENSSL_VERSION}")
#set(OPENSSL_ARCHIVE "${OPENSSL_AR_DIR}.tar.gz")

list(APPEND CMAKE_MODULE_PATH PATHS ./cmake)
include(GNUInstallDirs)
find_package(OPENSSL_PKG)

if(OPENSSL_FOUND)
    message(STATUS "openssl already installed")
    return()
endif()

if(NOT DEFINED OPENSSL_SRC_PATH)
    message(FATAL_ERROR "-DOPENSSL_SRC_PATH=<seco source path> missing")
endif()
if(NOT IS_ABSOLUTE ${OPENSSL_SRC_PATH})
	set(OPENSSL_SRC_PATH"${CMAKE_SOURCE_DIR}/${OPENSSL_SRC_PATH}")
endif()

set(OPENSSL_SRC "${OPENSSL_SRC_PATH}/${OPENSSL_AR_DIR}")

if(NOT EXISTS ${OPENSSL_SRC})
    find_file(OPENSSL_ARCHIVE_PATH ${OPENSSL_ARCHIVE} ${OPENSSL_SRC_PATH})
    if(NOT OPENSSL_ARCHIVE_PATH)
        message(STATUS "Downloading ${OPENSSL_ARCHIVE} from ${OPENSSL_URL}")
        file(DOWNLOAD
             "${OPENSSL_URL}/${OPENSSL_ARCHIVE}"
             "${OPENSSL_SRC_PATH}/${OPENSSL_ARCHIVE}"
             EXPECTED_HASH ${OPENSSL_HASH})
    endif()

    message(STATUS "Extracting ${OPENSSL_ARCHIVE}")
    execute_process(COMMAND ${CMAKE_COMMAND} -E tar xf ${OPENSSL_ARCHIVE}
                    WORKING_DIRECTORY ${OPENSSL_SRC_PATH}
                    RESULT_VARIABLE res)

    if(NOT ${res} EQUAL 0)
        message(FATAL_ERROR "Cannot extract openssl :${res}")
    endif()
endif()

#
# Build library
#
set(ENV{CC} ${CMAKE_C_COMPILER})
set(ENV{AR} ${CMAKE_AR})

message(STATUS "Configuring ${OPENSSL_AR_DIR}")
set(OPENSSL_CONFIGURE "./configure")
set(OPENSSL_CONFIGURE_ARGS "--prefix=${OPENSSL_ROOT}" "--enable-shared")
message(STATUS "Executing ${OPENSSL_CONFIGURE} ${OPENSSL_CONFIGURE_ARGS}")
execute_process(COMMAND ${OPENSSL_CONFIGURE} ${OPENSSL_CONFIGURE_ARGS}
                WORKING_DIRECTORY ${OPENSSL_SRC}
                RESULT_VARIABLE res)

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "Cannot configure openssl ${res}")
endif()

message(STATUS "Installing ${OPENSSL_AR_DIR}")
set(OPENSSL_MAKE_ARGS clean all install)
execute_process(COMMAND make ${OPENSSL_MAKE_ARGS}
                WORKING_DIRECTORY ${OPENSSL_SRC}
                RESULT_VARIABLE res)

if(NOT ${res} EQUAL 0)
    message(FATAL_ERROR "Cannot install openssl ${res}")
endif()
