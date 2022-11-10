# the name of the target operating system
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x64)
set(TOOLCHAIN_PREFIX x86_64-w64-mingw32)

# which compilers to use for C and C++
#set(CMAKE_C_COMPILER   clang)
#set(CMAKE_CXX_COMPILER clang++)
#set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}-gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}-g++)
set(CMAKE_RC_COMPILER ${TOOLCHAIN_PREFIX}-windres)

set(CMAKE_C_COMPILER_TARGET x86_64-pc-windows-gnu)
set(CMAKE_CXX_COMPILER_TARGET x86_64-pc-windows-gnu)

set(CMAKE_CXX_STANDARD_DEFAULT 20)

# where is the target environment located
set(CMAKE_FIND_ROOT_PATH /usr/${TOOLCHAIN_PREFIX} /usr/lib/gcc/${TOOLCHAIN_PREFIX}/7.3-posix)

# adjust the default behavior of the FIND_XXX() commands:
# search programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)

# search headers and libraries in the target environment
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)