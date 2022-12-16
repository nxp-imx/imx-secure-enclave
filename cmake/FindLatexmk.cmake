#[=======================================================================[.rst:
FindLatexmk
-------------

Find the latexmk executable.

Result Variables
^^^^^^^^^^^^^^^^
This will define the following variables:

``LATEXMK_FOUND``
True if the system has the latexmk executable.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``LATEXMK_EXECUTABLE``
The name of the latexmk executable

#]=======================================================================]
find_program(LATEXMK_EXECUTABLE
             NAMES latexmk
             PATHS usr/${CMAKE_INSTALL_BINDIR} ${CMAKE_INSTALL_BINDIR}
             DOC "latexmk executable")

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(${CMAKE_FIND_PACKAGE_NAME} REQUIRED_VARS
                                  LATEXMK_EXECUTABLE)

mark_as_advanced(LATEXMK_EXECUTABLE)
