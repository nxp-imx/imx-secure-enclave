#
# Check Secure Enclave libraries present or build them to install it in the
# PRIME_ROOT
#
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
   message(FATAL_ERROR "-DCMAKE_TOOLCHAIN_FILE=<toolchain file> missing")
endif()

set(CMAKE_FIND_LIBRARY_PREFIXES "lib")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".so")
include(${CMAKE_TOOLCHAIN_FILE})

list(APPEND CMAKE_MODULE_PATH PATHS ./cmake)
include(GNUInstallDirs)
find_package(Prime)
#find_package(OpenSSL)

if(PRIME_FOUND AND OPENSSL_FOUND)
    message(STATUS "PRIME libraries already installed")
    return()
endif()

if(NOT OPENSSL_FOUND)
#    include(${CMAKE_SOURCE_DIR}/scripts/build_openssl.cmake)
#    find_package(OPENSSL REQUIRED)
endif()

if(NOT PRIME_FOUND)
    #
    # Check if the Secure Enclave sources are present to build
    #
    if(NOT DEFINED PRIME_SRC_PATH)
        message(FATAL_ERROR "-DPRIME_SRC_PATH=<secure enclave source path> missing")
    endif()

    if(NOT IS_ABSOLUTE ${PRIME_SRC_PATH})
        set(PRIME_SRC_PATH"${CMAKE_SOURCE_DIR}/${PRIME_SRC_PATH}")
    endif()

    find_file(PRIME_MAKEFILE Makefile ${PRIME_SRC_PATH})
    if(PRIME_MAKEFILE)
	#get_filename_component(ZLIB_LIBRARY_DIR ${ZLIB_LIBRARY} DIRECTORY)

        set(ENV{CC} ${CMAKE_C_COMPILER})
        set(ENV{AR} ${CMAKE_AR})
	# set(ENV{CPATH} $ENV{CPATH}:${OPENSSL_INCLUDE_DIR})

        if(NOT ${PRIME_MAKE_FOR_COVERITY} EQUAL 0)
                message(STATUS "Building Secure Enclave - PRIME libs")
		set(PRIME_MAKE_ARGS clean libs PLAT=prime DESTDIR=${PRIME_ROOT} COMPATIBLE_MACHINE=${COMPATIBLE_MACHINE})
        else()
                message(STATUS "Building Secure Enclave - PRIME libs & tests")
		set(PRIME_MAKE_ARGS clean all install_tests PLAT=prime DESTDIR=${PRIME_ROOT} COMPATIBLE_MACHINE=${COMPATIBLE_MACHINE})
        endif()

        execute_process(COMMAND make ${PRIME_MAKE_ARGS}
                        WORKING_DIRECTORY ${PRIME_SRC_PATH}
                        RESULT_VARIABLE res)

        if(NOT ${res} EQUAL 0)
            message(FATAL_ERROR "\nFailed to build Secure Enclave - PRIME libs "
                    "from ${PRIME_SRC_PATH}\n")
        endif()
    else()
         message(FATAL_ERROR "\nSecure Enclave - PRIME libs can't be built, "
                 "Makefile not found in ${PRIME_SRC_PATH}.\n")
    endif()
endif()
