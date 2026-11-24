add_executable(lab_pe_target
    lab/lab_pe_target.cpp
)
target_compile_features(lab_pe_target PRIVATE cxx_std_20)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(lab_pe_target PRIVATE -O2 -fomit-frame-pointer -fno-sanitize=all)
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(lab_pe_target PRIVATE -fno-ipa-ra)
endif()

add_library(lab_c_lib STATIC
    lab/lab_c_lib.c
)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(lab_c_lib PRIVATE -O2 -fomit-frame-pointer -fno-sanitize=all)
endif()

add_executable(lab_c_app
    lab/lab_c_app.c
)
target_link_libraries(lab_c_app PRIVATE lab_c_lib)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(lab_c_app PRIVATE -O2 -fomit-frame-pointer -fno-sanitize=all)
endif()

add_executable(lab_cpp_app
    lab/lab_cpp_app.cpp
)
target_compile_features(lab_cpp_app PRIVATE cxx_std_20)
target_link_libraries(lab_cpp_app PRIVATE lab_c_lib)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(lab_cpp_app PRIVATE -O2 -fomit-frame-pointer -fno-sanitize=all)
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(lab_cpp_app PRIVATE -fno-ipa-ra)
endif()

add_executable(lab_sdk_app
    lab/lab_sdk_app.cpp
)
target_compile_features(lab_sdk_app PRIVATE cxx_std_20)
target_link_libraries(lab_sdk_app PRIVATE ByteMorph::SDK)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(lab_sdk_app PRIVATE -O2 -fomit-frame-pointer -fno-sanitize=all)
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(lab_sdk_app PRIVATE -fno-ipa-ra)
endif()

add_library(lab_shared_lib SHARED
    lab/lab_shared_lib.cpp
)
target_compile_features(lab_shared_lib PRIVATE cxx_std_20)
if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    target_compile_options(lab_shared_lib PRIVATE -O2 -fomit-frame-pointer -fno-sanitize=all)
endif()
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(lab_shared_lib PRIVATE -fno-ipa-ra)
endif()

add_executable(bytemorph_tests
    unit/test_diagnostics.cpp
    unit/test_ir.cpp
    unit/test_format_detection.cpp
    unit/test_x86_64_disasm.cpp
    unit/test_aarch64_disasm.cpp
    unit/test_obfuscation.cpp
    unit/test_vm.cpp
    integration/test_pe_elf_analysis.cpp
    integration/test_macho_and_cfg2.cpp
    integration/test_ir_to_vm_diff.cpp
    integration/test_pe_protection.cpp
    integration/test_cross_platform_protection.cpp
    regression/test_malformed_inputs.cpp
)

target_include_directories(bytemorph_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_definitions(bytemorph_tests
    PRIVATE
        BYTEMORPH_LAB_PE_TARGET_PATH="$<TARGET_FILE:lab_pe_target>"
        BYTEMORPH_LAB_C_APP_PATH="$<TARGET_FILE:lab_c_app>"
        BYTEMORPH_LAB_CPP_APP_PATH="$<TARGET_FILE:lab_cpp_app>"
        BYTEMORPH_LAB_SDK_APP_PATH="$<TARGET_FILE:lab_sdk_app>"
        BYTEMORPH_LAB_SHARED_LIB_PATH="$<TARGET_FILE:lab_shared_lib>"
)

add_dependencies(bytemorph_tests lab_pe_target lab_c_app lab_cpp_app lab_sdk_app lab_shared_lib)

target_link_libraries(bytemorph_tests
    PRIVATE
        ByteMorph::Core
        ByteMorph::Formats
        ByteMorph::Arch
        ByteMorph::Obf
        ByteMorph::Virt
        ByteMorph::Prot
        ByteMorph::SDK
        GTest::gtest_main
)

target_compile_features(bytemorph_tests PRIVATE cxx_std_20)

include(GoogleTest)
gtest_discover_tests(bytemorph_tests)

if(BYTEMORPH_BUILD_FUZZERS)
    foreach(fuzz_target fuzz_loader fuzz_pe_parser fuzz_elf_parser fuzz_macho_parser)
        add_executable(${fuzz_target} fuzz/${fuzz_target}.cpp)
        target_link_libraries(${fuzz_target} PRIVATE ByteMorph::Core ByteMorph::Formats)
        target_compile_options(${fuzz_target} PRIVATE -fsanitize=fuzzer,address,undefined)
        target_link_options(${fuzz_target} PRIVATE -fsanitize=fuzzer,address,undefined)
        target_compile_features(${fuzz_target} PRIVATE cxx_std_20)
    endforeach()
endif()
