add_library(bytemorph_prot STATIC
    ${monocypher_SOURCE_DIR}/src/monocypher.c
    src/crypto_aead.cpp
    src/native_vm_emitter.cpp
    src/pe_rewriter.cpp
    src/elf_rewriter.cpp
    src/macho_rewriter.cpp
    src/protection_pipeline.cpp
)

set_source_files_properties(${monocypher_SOURCE_DIR}/src/monocypher.c PROPERTIES LANGUAGE CXX)

add_library(ByteMorph::Prot ALIAS bytemorph_prot)

target_include_directories(bytemorph_prot
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${monocypher_SOURCE_DIR}/src
)

target_link_libraries(bytemorph_prot
    PUBLIC
        ByteMorph::Core
        ByteMorph::Formats
        ByteMorph::Arch
        ByteMorph::Obf
        ByteMorph::Virt
    PRIVATE
        LIEF::LIEF
        Zydis
)

if(BYTEMORPH_ENABLE_ASMJIT)
    target_link_libraries(bytemorph_prot PRIVATE asmjit::asmjit)
endif()

target_compile_features(bytemorph_prot PUBLIC cxx_std_20)
