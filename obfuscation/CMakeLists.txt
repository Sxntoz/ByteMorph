add_library(bytemorph_obf STATIC
    src/obfuscation_engine.cpp
)

add_library(ByteMorph::Obf ALIAS bytemorph_obf)

target_include_directories(bytemorph_obf
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(bytemorph_obf
    PUBLIC
        ByteMorph::Core
)

target_compile_features(bytemorph_obf PUBLIC cxx_std_20)
