add_library(bytemorph_formats STATIC
    pe/src/pe_parser.cpp
    elf/src/elf_parser.cpp
    macho/src/macho_parser.cpp
)

add_library(ByteMorph::Formats ALIAS bytemorph_formats)

target_include_directories(bytemorph_formats
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/pe/include
        ${CMAKE_CURRENT_SOURCE_DIR}/elf/include
        ${CMAKE_CURRENT_SOURCE_DIR}/macho/include
)

target_link_libraries(bytemorph_formats
    PUBLIC
        ByteMorph::Core
    PRIVATE
        LIEF::LIEF
)

target_compile_features(bytemorph_formats PUBLIC cxx_std_20)
