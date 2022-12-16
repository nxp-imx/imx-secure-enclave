#[=======================================================================[.rst:
FindEle
-------

Finds the EdgeLock Enclave (ELE) libraries.

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``ELE_FOUND``
  True if the system has the EdgeLock Enclave libraries.
``ELE_INCLUDE_DIRS``
  Include directories needed to use EdgeLock Enclave libraries.
``ELE_LIBRARIES``
  Libraries fullname needed to link to EdgeLock Enclave libraries.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``ELE_HSM_INCLUDE_DIR``
  the directory containing ``hsm_api.h``.
``ELE_HSM_LIBRARY``
  the path to the EdgeLock Enclave hsm library.

#]=======================================================================]
if(NOT DEFINED ELE_ROOT)
    message("ELE_ROOT not defined")
endif()

if(DEFINED ELE_ROOT AND NOT IS_ABSOLUTE ${ELE_ROOT})
    set(ELE_ROOT "${CMAKE_SOURCE_DIR}/${ELE_ROOT}")
endif()

find_library(ELE_HSM_LIBRARY ele_hsm
          PATHS ${ELE_ROOT} ${ELE_ROOT}/usr
          PATH_SUFFIXES ${CMAKE_INSTALL_LIBDIR}
          CMAKE_FIND_ROOT_PATH_BOTH)
find_path(ELE_HSM_INCLUDE_DIR hsm_api.h
          PATHS ${ELE_ROOT} ${ELE_ROOT}/usr
          PATH_SUFFIXES ${CMAKE_INSTALL_INCLUDEDIR} ${CMAKE_INSTALL_INCLUDEDIR}/hsm
          CMAKE_FIND_ROOT_PATH_BOTH)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(${CMAKE_FIND_PACKAGE_NAME} REQUIRED_VARS
                                  ELE_HSM_LIBRARY ELE_HSM_INCLUDE_DIR)

if(${CMAKE_FIND_PACKAGE_NAME}_FOUND)
    set(ELE_LIBRARIES ${ELE_HSM_LIBRARY})
    set(ELE_INCLUDE_DIRS ${ELE_HSM_INCLUDE_DIR})
endif()

mark_as_advanced(ELE_HSM_LIBRARY ELE_HSM_INCLUDE_DIR)
