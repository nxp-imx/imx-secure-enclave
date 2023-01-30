#[=======================================================================[.rst:
FindOPENSSL
-------------

Find the OPENSSL includes and library (version light of the Find module).
Support to run in script mode.

Result Variables
^^^^^^^^^^^^^^^^
This will define the following variables:

``OPENSSL_FOUND``
True if the system has the OPENSSL library.
``OPENSSL_INCLUDE_DIR``
Include directories needed to use OPENSSL Library.
``OPENSSL_LIBRARY``
Library needed to link to OPENSSL library.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``OPENSSL_LIBRARY``
  The directory containing ``openssl.h``.
``OPENSSL_INCLUDE_DIR``
The path to the OPENSSL library.

#]=======================================================================]
if(NOT DEFINED OPENSSL_ROOT)
    message("OPENSSL_ROOT not defined")
endif()

if(DEFINED OPENSSL_ROOT AND NOT IS_ABSOLUTE ${OPENSSL_ROOT})
    set(OPENSSL_ROOT "${CMAKE_SOURCE_DIR}/${OPENSSL_ROOT}")
endif()

find_library(OPENSSL_LIBRARY z
             PATHS ${OPENSSL_ROOT}
             PATH_SUFFIXES usr/${CMAKE_INSTALL_LIBDIR} ${CMAKE_INSTALL_LIBDIR}
             CMAKE_FIND_ROOT_PATH_BOTH)
find_path(OPENSSL_INCLUDE_DIR openssl.h
          PATHS ${OPENSSL_ROOT}
          PATH_SUFFIXES usr/${CMAKE_INSTALL_INCLUDEDIR} ${CMAKE_INSTALL_INCLUDEDIR}
          CMAKE_FIND_ROOT_PATH_BOTH)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(${CMAKE_FIND_PACKAGE_NAME} REQUIRED_VARS
				  OPENSSL_LIBRARY OPENSSL_INCLUDE_DIR)

#
# To be coherent with other OPENSSL variables, OPENSSL_FOUND is used instead of
# OPENSSL_FOUND.
#
set(OPENSSL_FOUND ${${CMAKE_FIND_PACKAGE_NAME}_FOUND})

mark_as_advanced(OPENSSL_LIBRARY OPENSSL_INCLUDE_DIR OPENSSL_FOUND)
