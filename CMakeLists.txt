cmake_minimum_required(VERSION 3.0)
cmake_policy(SET CMP0054 NEW)
project(neon_bcrypt)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY .)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG .)

if ("${CMAKE_C_COMPILER_ID}" STREQUAL "MSVC")
    add_compile_options(/EHsc /W2 /WX /FS /wd4324)
elseif ("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
    add_compile_options(-Wall -Wextra -Wbad-function-cast -Wcast-align -Wcast-qual -Wshadow -Wundef -Wpointer-arith -O2 -fomit-frame-pointer -funroll-loops)
endif ()

set(CMAKE_C_STANDARD 99)

add_library(neon_bcrypt SHARED
    crypt_blowfish.c
    crypt_gensalt.c
    wrapper.c
    bcrypt.c
)
