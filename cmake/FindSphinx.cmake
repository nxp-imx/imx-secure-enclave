#[=======================================================================[.rst:
FindSphinx
-------------

Find the Sphinx executable.

Result Variables
^^^^^^^^^^^^^^^^
This will define the following variables:

``SPHINX_FOUND``
True if the system has the Sphinx executable.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``SPHINX_EXECUTABLE``
The name of the Sphinx executable

#]=======================================================================]
find_program(SPHINX_EXECUTABLE
             NAMES sphinx-build
             PATHS usr/${CMAKE_INSTALL_BINDIR} ${CMAKE_INSTALL_BINDIR}
             DOC "Sphinx documentation generator")

include(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(${CMAKE_FIND_PACKAGE_NAME} REQUIRED_VARS
                                  SPHINX_EXECUTABLE)

mark_as_advanced(SPHINX_EXECUTABLE)
