cmake_minimum_required(VERSION 3.23)
project(MemScanner)

set(CMAKE_CXX_STANDARD 20)

add_library(MemScanner src/MemScanner.cpp src/MemScanner.h src/Mem.cpp src/Mem.h)
target_include_directories(MemScanner INTERFACE src/)