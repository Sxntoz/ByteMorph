add_executable(bytemorph
    src/main.cpp
)

target_link_libraries(bytemorph
    PRIVATE
        ByteMorph::Core
        ByteMorph::Formats
        ByteMorph::Arch
        ByteMorph::Obf
        ByteMorph::Virt
        ByteMorph::Prot
)

target_compile_features(bytemorph PRIVATE cxx_std_20)
