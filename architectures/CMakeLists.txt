add_library(bytemorph_arch STATIC
    x86_64/src/x86_64_disasm.cpp
    x86_64/src/x86_64_lifter.cpp
    aarch64/src/aarch64_disasm.cpp
    aarch64/src/aarch64_lifter.cpp
)

add_library(ByteMorph::Arch ALIAS bytemorph_arch)

target_include_directories(bytemorph_arch
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/x86_64/include
        ${CMAKE_CURRENT_SOURCE_DIR}/aarch64/include
)

target_link_libraries(bytemorph_arch
    PUBLIC
        ByteMorph::Core
    PRIVATE
        Zydis
        capstone
)

target_compile_features(bytemorph_arch PUBLIC cxx_std_20)
