
#
# If Toolchain name and version are defined, create the
# Toolchain archive subdir where should be the toolchain
#
if(TOOLCHAIN_NAME AND TOOLCHAIN_VERSION)
    set(TOOLCHAIN_AR_DIR "gcc-arm-${TOOLCHAIN_VERSION}-x86_64-${TOOLCHAIN_NAME}")
    set(TOOLCHAIN_SUBPATH ${TOOLCHAIN_AR_DIR}/bin)
endif()

find_program(GCC_BINTOOL NAMES ${TOOLCHAIN_NAME}-gcc PATHS ${TOOLCHAIN_PATH}
             PATH_SUFFIXES ${TOOLCHAIN_SUBPATH})

if(NOT GCC_BINTOOL AND FORCE_TOOLCHAIN_INSTALL)
    include(${CMAKE_SOURCE_DIR}/scripts/install_toolchain.cmake)
    find_program(GCC_BINTOOL NAMES ${TOOLCHAIN_NAME}-gcc PATHS ${TOOLCHAIN_PATH}
                 PATH_SUFFIXES ${TOOLCHAIN_SUBPATH})
endif()

if(NOT GCC_BINTOOL)
    if(DEFINED TOOLCHAIN_PATH)
        message(FATAL_ERROR "\nToolchain ${TOOLCHAIN_NAME} not found in "
                "directory ${TOOLCHAIN_PATH}, fix path\n")
    else()
        message(FATAL_ERROR "\nToolchain ${TOOLCHAIN_NAME} not found. "
                "Either specified path on command line with `-DTOOLCHAIN_PATH=`,"
                " or add the toolchain path in the system environmnent PATH\n")
    endif()
endif()

set(TOOLCHAIN_PREFIX ${TOOLCHAIN_NAME}-)

get_filename_component(TOOLCHAIN_BIN_PATH ${GCC_BINTOOL} DIRECTORY CACHE)

set(CMAKE_C_COMPILER ${TOOLCHAIN_BIN_PATH}/${TOOLCHAIN_PREFIX}gcc)
set(CMAKE_ASM_COMPILER ${CMAKE_C_COMPILER})
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_BIN_PATH}/${TOOLCHAIN_PREFIX}g++)

set(CMAKE_AR ${TOOLCHAIN_BIN_PATH}/${TOOLCHAIN_PREFIX}ar
    CACHE INTERNAL "archiving tool")
set(CMAKE_OBJCOPY ${TOOLCHAIN_BIN_PATH}/${TOOLCHAIN_PREFIX}objcopy
    CACHE INTERNAL "objcopy tool")
set(CMAKE_SIZE_UTIL ${TOOLCHAIN_BIN_PATH}/${TOOLCHAIN_PREFIX}size
    CACHE INTERNAL "size tool")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

unset(GCC_BINTOOL CACHE)
