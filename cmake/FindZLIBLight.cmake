#[=======================================================================[.rst:
FindZLIBLight
-------------

Find the ZLIB includes and library (version light of the Find module).
Support to run in script mode.

Result Variables
^^^^^^^^^^^^^^^^
This will define the following variables:

``ZLIBLight_FOUND``
``ZLIB_FOUND``
True if the system has the ZLIB library.
``ZLIB_INCLUDE_DIR``
Include directories needed to use ZLIB Library.
``ZLIB_LIBRARY``
Library needed to link to ZLIB library.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``ZLIB_LIBRARY``
  The directory containing ``zlib.h``.
``ZLIB_INCLUDE_DIR``
The path to the ZLIB library.

#]=======================================================================]
if(NOT DEFINED ZLIB_ROOT)
    message("ZLIB_ROOT not defined")
endif()

if(DEFINED ZLIB_ROOT AND NOT IS_ABSOLUTE ${ZLIB_ROOT})
    set(ZLIB_ROOT "${CMAKE_SOURCE_DIR}/${ZLIB_ROOT}")
endif()

find_library(ZLIB_LIBRARY z
             PATHS ${ZLIB_ROOT}
             PATH_SUFFIXES usr/${CMAKE_INSTALL_LIBDIR} ${CMAKE_INSTALL_LIBDIR}
             CMAKE_FIND_ROOT_PATH_BOTH)
find_path(ZLIB_INCLUDE_DIR zlib.h
          PATHS ${ZLIB_ROOT}
          PATH_SUFFIXES usr/${CMAKE_INSTALL_INCLUDEDIR} ${CMAKE_INSTALL_INCLUDEDIR}
          CMAKE_FIND_ROOT_PATH_BOTH)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(${CMAKE_FIND_PACKAGE_NAME} REQUIRED_VARS
                                  ZLIB_LIBRARY ZLIB_INCLUDE_DIR)

#
# To be coherent with other ZLIB variables, ZLIB_FOUND is used instead of
# ZLIBLight_FOUND.
#
set(ZLIB_FOUND ${${CMAKE_FIND_PACKAGE_NAME}_FOUND})

mark_as_advanced(ZLIB_LIBRARY ZLIB_INCLUDE_DIR ZLIB_FOUND)
