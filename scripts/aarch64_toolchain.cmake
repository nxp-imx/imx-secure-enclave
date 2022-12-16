set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_SIZEOF_VOID_P 64)

# Check the process is try the compilation
# if yes, compiler already defined so return
get_property(_IN_TC GLOBAL PROPERTY IN_TRY_COMPILE)
if(_IN_TC)
    return()
endif()

# https://developer.arm.com/tools-and-software/open-source-software/developer-tools/gnu-toolchain/gnu-a/downloads

# Set the default aarch64 Cross-compiler toolchain
if(NOT TOOLCHAIN_NAME)
    set(TOOLCHAIN_NAME "aarch64-none-linux-gnu")
    set(TOOLCHAIN_VERSION "10.3-2021.07" CACHE STRING "Default Toolchain Version")
    set(TOOLCHAIN_HASH "SHA256=1e33d53dea59c8de823bbdfe0798280bdcd138636c7060da9d77a97ded095a84")
    set(TOOLCHAIN_SERVER "https://developer.arm.com/-/media/Files/downloads/gnu-a/")
    set(TOOLCHAIN_URL ${TOOLCHAIN_SERVER}${TOOLCHAIN_VERSION}/binrel/)
endif()

# Define the toolchain name
include(${CMAKE_SOURCE_DIR}/scripts/common_toolchain.cmake)
