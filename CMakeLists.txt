cmake_minimum_required(VERSION 3.23)
project(MemScanner)

set(CMAKE_CXX_STANDARD 20)
enable_testing()

if (NOT (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC"))
    add_compile_options(-fms-extensions -mxsave -mavx -mavx2 -mbmi)
endif()

find_package(Threads REQUIRED)

add_library(MemScanner src/MemScanner.cpp include/MemScanner/MemScanner.h src/Mem.cpp include/MemScanner/Mem.h)
target_include_directories(MemScanner PUBLIC include/)

if(DEFINED MEM_SCANNER_RUNTIME_LIBRARY)
set_property(TARGET MemScanner PROPERTY
        MSVC_RUNTIME_LIBRARY ${MEM_SCANNER_RUNTIME_LIBRARY})
endif()

# message(${CMAKE_CXX_COMPILER_ID})

# Tests
add_executable(PatternTest test/PatternTest.cpp src/MemScanner.cpp include/MemScanner/MemScanner.h src/Mem.cpp include/MemScanner/Mem.h)
add_test(NAME PatternTest COMMAND PatternTest nobenchmark)
target_include_directories(PatternTest PRIVATE include/)
target_link_libraries(PatternTest Threads::Threads)

if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(PatternTest PRIVATE /Zi)
    target_link_options(PatternTest PRIVATE /DEBUG:FULL)
endif()