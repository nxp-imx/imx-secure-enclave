#[=======================================================================[.rst:
FindKerneldoc
-------------

Find the kernel-doc executable.

Result Variables
^^^^^^^^^^^^^^^^
This will define the following variables:

``KERNELDOC_FOUND``
True if the system has the kernel-doc executable.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``KERNELDOC_EXECUTABLE``
The name of the kernel-doc executable

#]=======================================================================]
find_program(KERNELDOC_EXECUTABLE
             NAMES kernel-doc
             PATHS usr/${CMAKE_INSTALL_BINDIR} ${CMAKE_INSTALL_BINDIR}
             DOC "kernel-doc executable")

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(${CMAKE_FIND_PACKAGE_NAME} REQUIRED_VARS
                                  KERNELDOC_EXECUTABLE)

mark_as_advanced(KERNELDOC_EXECUTABLE)
