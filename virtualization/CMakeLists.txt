add_library(bytemorph_virt STATIC
    bytecode/src/bvm_format.cpp
    vm/src/vm_interpreter.cpp
    vm/src/asmjit_prototype.cpp
    translator/src/ir_to_vm.cpp
)

add_library(ByteMorph::Virt ALIAS bytemorph_virt)

target_include_directories(bytemorph_virt
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/bytecode/include
        ${CMAKE_CURRENT_SOURCE_DIR}/vm/include
        ${CMAKE_CURRENT_SOURCE_DIR}/translator/include
)

target_link_libraries(bytemorph_virt
    PUBLIC
        ByteMorph::Core
)

if(BYTEMORPH_ENABLE_ASMJIT)
    target_link_libraries(bytemorph_virt PRIVATE asmjit::asmjit)
    target_compile_definitions(bytemorph_virt PUBLIC BYTEMORPH_HAS_ASMJIT=1)
endif()

target_compile_features(bytemorph_virt PUBLIC cxx_std_20)
