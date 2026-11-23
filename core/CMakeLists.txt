add_library(bytemorph_core STATIC
    diagnostics/src/error.cpp
    diagnostics/src/logger.cpp
    binary/src/loader.cpp
    ir/src/ir.cpp
    ir/src/ir_serializer.cpp
    ir/src/ir_interpreter.cpp
    analysis/src/analyzer.cpp
)

add_library(ByteMorph::Core ALIAS bytemorph_core)

target_include_directories(bytemorph_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/diagnostics/include
        ${CMAKE_CURRENT_SOURCE_DIR}/binary/include
        ${CMAKE_CURRENT_SOURCE_DIR}/ir/include
        ${CMAKE_CURRENT_SOURCE_DIR}/analysis/include
)

target_compile_features(bytemorph_core PUBLIC cxx_std_20)
