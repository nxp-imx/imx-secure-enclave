#[=======================================================================[.rst:
FindTA_dev_kit
-------

Finds the TEE TA Development kit.

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``TA_DEV_KIT_FOUND``
  True if the system has the TEE TA Development kit.
``TA_DEV_KIT_DIR``
  Include directory needed to use TEE TA Development kit.
``TA_DEV_KIT_INCLUDE_DIR``
  The directory containing TEE TA includes.
``TA_HOST_INCLUDE_DIR``
  The directory containing TEE Host includes.

 Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``TA_DEV_KIT_INCLUDE_DIR``
  The directory containing ``tee_internal_api.h``.
``TA_DEV_KIT_MK_DIR``
  The path to the ``ta_dev_kit.mk``.
``TA_HOST_INCLUDE_DIR``
  The path to the TEE Host ``tee_api_defines.h``.

#]=======================================================================]
if(NOT DEFINED TA_DEV_KIT_ROOT)
    message("TA_DEV_KIT_ROOT not defined")
endif()

if(DEFINED TA_DEV_KIT_ROOT AND NOT IS_ABSOLUTE ${TA_DEV_KIT_ROOT})
    set(TA_DEV_KIT_ROOT "${CMAKE_SOURCE_DIR}/${TA_DEV_KIT_ROOT}")
endif()

find_path(TA_DEV_KIT_INCLUDE_DIR tee_internal_api.h
          PATHS ${TA_DEV_KIT_ROOT}
          PATH_SUFFIXES usr/${CMAKE_INSTALL_INCLUDEDIR} ${CMAKE_INSTALL_INCLUDEDIR})
find_path(TA_DEV_KIT_MK_DIR ta_dev_kit.mk
          PATHS ${TA_DEV_KIT_ROOT}
          PATH_SUFFIXES mk)
find_path(TA_HOST_INCLUDE_DIR tee_api_defines.h
          PATHS ${TA_DEV_KIT_ROOT}
          PATH_SUFFIXES host_include)

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(${CMAKE_FIND_PACKAGE_NAME} REQUIRED_VARS
                                  TA_DEV_KIT_INCLUDE_DIR TA_DEV_KIT_MK_DIR)

set(TA_DEV_KIT_DIR ${TA_DEV_KIT_ROOT})
mark_as_advanced(TA_DEV_KIT_INCLUDE_DIR TA_DEV_KIT_MK_DIR TA_HOST_INCLUDE_DIR)
