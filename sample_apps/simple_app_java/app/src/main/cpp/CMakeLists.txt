cmake_minimum_required(VERSION 3.18)
project(certifier_android LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(certifier_native SHARED
    native-lib.cpp
    simple_core_android.cc
)

find_library(log-lib log)
target_link_libraries(certifier_native ${log-lib})
target_compile_options(certifier_native PRIVATE -fexceptions -frtti)
