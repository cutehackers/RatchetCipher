
# Sets the minimum version of CMake required to build your native library.
# This ensures that a certain set of CMake features is available to
# your build.

cmake_minimum_required(VERSION 3.4.1)

set(SODIUM ${CMAKE_CURRENT_SOURCE_DIR}/sodium/)

# add sodium library
add_library(sodium SHARED IMPORTED)
set_target_properties(
        # Specifies the target library.
        sodium

        # Specifies the parameter you want to define.
        PROPERTIES IMPORTED_LOCATION

        # Provides the path to the library you want to import.
        ${SODIUM}/lib/${ANDROID_ABI}/libsodium.so
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -Wall")

add_library(
        # Specifies the name of the library.
        ratchet

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        ratchet_jni.c
        ratchet.c
)

target_include_directories(ratchet PRIVATE
        ${SODIUM}/include)

target_link_libraries(ratchet
        sodium
        android
        log)
