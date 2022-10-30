cmake_minimum_required(VERSION 3.23)
project(MemScanner)

set(CMAKE_CXX_STANDARD 20)

add_library(MemScanner src/MemScanner.cpp include/MemScanner/MemScanner.h src/Mem.cpp include/MemScanner/Mem.h)
target_include_directories(MemScanner PUBLIC include/)

# Tests
add_executable(PatternTest test/PatternTest.cpp src/MemScanner.cpp include/MemScanner/MemScanner.h src/Mem.cpp include/MemScanner/Mem.h)
add_test(NAME PatternTest COMMAND PatternTest)
target_include_directories(PatternTest PRIVATE include/)