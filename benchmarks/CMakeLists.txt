add_executable(bytemorph_bench
    bench_analysis.cpp
)

target_link_libraries(bytemorph_bench
    PRIVATE
        ByteMorph::Core
        ByteMorph::Formats
        ByteMorph::Arch
)

target_include_directories(bytemorph_bench
    PRIVATE
        ${CMAKE_SOURCE_DIR}/tests
)

target_compile_features(bytemorph_bench PRIVATE cxx_std_20)
