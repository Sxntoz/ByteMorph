cmake_minimum_required(VERSION 3.20)

project(ByteMorph
    VERSION 0.3.0
    DESCRIPTION "Cross-platform modular binary analysis and software protection engine"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Export compile commands for tooling
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BYTEMORPH_BUILD_TESTS "Build ByteMorph unit, integration, and regression tests" ON)
option(BYTEMORPH_BUILD_BENCHMARKS "Build ByteMorph reproducible benchmarks" ON)
option(BYTEMORPH_BUILD_FUZZERS "Build libFuzzer targets (requires Clang)" OFF)
option(BYTEMORPH_ENABLE_SANITIZERS "Enable ASan/UBSan when supported" OFF)
option(BYTEMORPH_ENABLE_ASMJIT "Enable optional AsmJit x86-64 prototype backend" ON)
option(BYTEMORPH_ENABLE_WARNINGS "Enable strict compiler warnings" ON)

if(BYTEMORPH_ENABLE_SANITIZERS)
    if(MSVC)
        add_compile_options(/fsanitize=address)
    else()
        add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address,undefined)
    endif()
endif()

if(BYTEMORPH_ENABLE_WARNINGS)
    if(MSVC)
        add_compile_options(/W4 /permissive- /EHsc)
    else()
        add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
    endif()
endif()

include(FetchContent)

# ------------------------------------------------------------------------------
# Dependencies: LIEF, Zydis, GoogleTest
# ------------------------------------------------------------------------------
set(LIEF_DOC OFF CACHE BOOL "" FORCE)
set(LIEF_PYTHON_API OFF CACHE BOOL "" FORCE)
set(LIEF_C_API OFF CACHE BOOL "" FORCE)
set(LIEF_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LIEF_TESTS OFF CACHE BOOL "" FORCE)
set(LIEF_DEX OFF CACHE BOOL "" FORCE)
set(LIEF_ART OFF CACHE BOOL "" FORCE)
set(LIEF_OAT OFF CACHE BOOL "" FORCE)
set(LIEF_VDEX OFF CACHE BOOL "" FORCE)
set(LIEF_PE ON CACHE BOOL "" FORCE)
set(LIEF_ELF ON CACHE BOOL "" FORCE)
set(LIEF_MACHO ON CACHE BOOL "" FORCE)

FetchContent_Declare(
    LIEF
    GIT_REPOSITORY https://github.com/lief-project/LIEF.git
    GIT_TAG 0.16.4
    GIT_SHALLOW TRUE
)

set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
    Zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG v4.1.0
    GIT_SHALLOW TRUE
)

set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "" FORCE)

FetchContent_Declare(
    capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
    GIT_TAG 5.0.3
    GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(LIEF Zydis capstone)

if(BYTEMORPH_ENABLE_ASMJIT)
    set(ASMJIT_STATIC ON CACHE BOOL "" FORCE)
    FetchContent_Declare(
        asmjit
        GIT_REPOSITORY https://github.com/asmjit/asmjit.git
        GIT_TAG master
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(asmjit)
endif()

# ------------------------------------------------------------------------------
# Modules
# ------------------------------------------------------------------------------
add_subdirectory(core)
add_subdirectory(formats)
add_subdirectory(architectures)
add_subdirectory(obfuscation)
add_subdirectory(virtualization)
add_subdirectory(cli)

if(BYTEMORPH_BUILD_TESTS)
    enable_testing()
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.15.2
        GIT_SHALLOW TRUE
    )
    FetchContent_MakeAvailable(googletest)
    add_subdirectory(tests)
endif()

if(BYTEMORPH_BUILD_BENCHMARKS)
    add_subdirectory(benchmarks)
endif()
