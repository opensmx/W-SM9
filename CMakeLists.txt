cmake_minimum_required(VERSION 3.0)
project(wildcarded_sm9)

set(CMAKE_CXX_STANDARD 17)

include_directories(include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -pthread -mavx2 -O3")
add_compile_options(-Wunknown-pragmas)

FIND_PACKAGE(OpenMP REQUIRED)
if (OPENMP_FOUND)
    message("OPENMP FOUND")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif ()

if (ENABLE_OMP)
    message("OpenMP enabled")
    add_definitions("-DParallel")
endif (ENABLE_OMP)

if (LOCAL_DEBUG)
    message("LOCAL_DEBUG enabled")
    add_definitions("-DDEBUG")
endif (LOCAL_DEBUG)

add_executable(wildcarded_sm9_test src/schemes/wildcarded_sm9.cpp
        src/ibe/swibe.cpp
        src/components/key.cpp
        src/components/ciphertext.cpp
        unit_test/wildcarded_sm9_test.cpp)
target_link_libraries(wildcarded_sm9_test pbc
        "/lib/x86_64-linux-gnu/libgmpxx.a"
        "/lib/x86_64-linux-gnu/libgmp.a"
        "/lib/x86_64-linux-gnu/libblake3.so")
