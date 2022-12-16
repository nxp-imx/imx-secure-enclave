#[=======================================================================[.rst:
FindSeco
-------

Finds the Seco NVM and HSM library.

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``SECO_FOUND``
  True if the system has the Seco NVM and HSM libraries.
``SECO_INCLUDE_DIRS``
  Include directories needed to use Seco NVM and HSM.
``SECO_LIBRARIES``
  Libraries needed to link to Seco NVM and HSM libraries.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``SECO_NVM_INCLUDE_DIR``
  the directory containing ``seco_nvm.h``.
``SECO_NVM_LIBRARY``
  the path to the seco nvm manager library.
``SECO_HSM_INCLUDE_DIR``
  the directory containing ``hsm_api.h``.
``SECO_HSM_LIBRARY``
  the path to the seco hsm library.

#]=======================================================================]
if(NOT DEFINED SECO_ROOT)
    message("SECO_ROOT not defined")
endif()

if(DEFINED SECO_ROOT AND NOT IS_ABSOLUTE ${SECO_ROOT})
    set(SECO_ROOT "${CMAKE_SOURCE_DIR}/${SECO_ROOT}")
endif()

find_file(SECO_NVM_LIBRARY seco_nvm_manager.a
          PATHS ${SECO_ROOT}
          PATH_SUFFIXES usr/${CMAKE_INSTALL_LIBDIR} ${CMAKE_INSTALL_LIBDIR})
find_path(SECO_NVM_INCLUDE_DIR seco_nvm.h
          PATHS ${SECO_ROOT}
          PATH_SUFFIXES usr/${CMAKE_INSTALL_INCLUDEDIR} ${CMAKE_INSTALL_INCLUDEDIR})
find_file(SECO_HSM_LIBRARY hsm_lib.a
          PATHS ${SECO_ROOT}
          PATH_SUFFIXES usr/${CMAKE_INSTALL_LIBDIR} ${CMAKE_INSTALL_LIBDIR})
find_path(SECO_HSM_INCLUDE_DIR hsm_api.h
          PATHS ${SECO_ROOT}
          PATH_SUFFIXES usr/${CMAKE_INSTALL_INCLUDEDIR}/hsm ${CMAKE_INSTALL_INCLUDEDIR}/hsm)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(${CMAKE_FIND_PACKAGE_NAME} REQUIRED_VARS
                                  SECO_NVM_LIBRARY SECO_NVM_INCLUDE_DIR
                                  SECO_HSM_LIBRARY SECO_HSM_INCLUDE_DIR)

if(${CMAKE_FIND_PACKAGE_NAME}_FOUND)
    set(SECO_LIBRARIES ${SECO_NVM_LIBRARY} ${SECO_HSM_LIBRARY})
    set(SECO_INCLUDE_DIRS ${SECO_NVM_INCLUDE_DIR} ${SECO_HSM_INCLUDE_DIR})
endif()

mark_as_advanced(SECO_NVM_LIBRARY SECO_NVM_INCLUDE_DIR
    SECO_HSM_LIBRARY SECO_HSM_INCLUDE_DIR)
