#[=======================================================================[.rst:
FindTeec
-------

Finds the TEE Client library.

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``TEEC_FOUND``
  True if the system has the TEE Client library.
``TEEC_INCLUDE_DIR``
  Include directory needed to use TEE Client.
``TEEC_LIBRARY``
  Library needed to link to TEE Client.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``TEEC_INCLUDE_DIR``
  The directory containing ``tee_client_api.h``.
``TEEC_LIBRARY``
  The path to the TEE Client library.

#]=======================================================================]
if(NOT DEFINED TEEC_ROOT)
    message("TECC_ROOT not defined")
endif()

if(DEFINED TEEC_ROOT AND NOT IS_ABSOLUTE ${TEEC_ROOT})
    set(TEEC_ROOT "${CMAKE_SOURCE_DIR}/${TEEC_ROOT}")
endif()

find_library(TEEC_LIBRARY teec
             PATHS ${TEEC_ROOT}
             PATH_SUFFIXES usr/${CMAKE_INSTALL_LIBDIR} ${CMAKE_INSTALL_LIBDIR}
             CMAKE_FIND_ROOT_PATH_BOTH)
find_path(TEEC_INCLUDE_DIR tee_client_api.h
          PATHS ${TEEC_ROOT}
          PATH_SUFFIXES usr/${CMAKE_INSTALL_INCLUDEDIR} ${CMAKE_INSTALL_INCLUDEDIR}
          CMAKE_FIND_ROOT_PATH_BOTH)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(${CMAKE_FIND_PACKAGE_NAME} REQUIRED_VARS
                                  TEEC_LIBRARY TEEC_INCLUDE_DIR)

mark_as_advanced(TEEC_INCLUDE_DIR TEEC_LIBRARY)
