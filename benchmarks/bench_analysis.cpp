#include "bytemorph/arch/aarch64/aarch64_disasm.hpp"
#include "bytemorph/arch/x86_64/x86_64_disasm.hpp"
#include "bytemorph/core/analysis/analyzer.hpp"
#include "bytemorph/core/binary/loader.hpp"
#include "bytemorph/formats/elf/elf_parser.hpp"
#include "bytemorph/formats/macho/macho_parser.hpp"
#include "bytemorph/formats/pe/pe_parser.hpp"
#include "sample_builder.hpp"

#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <memory>
#include <vector>

using namespace bytemorph::core::binary;
using namespace bytemorph::core::analysis;

int main(int argc, char* argv[]) {
    int iterations = 100;
    if (argc >= 2) {
        try {
            iterations = std::stoi(argv[1]);
        } catch (...) {
            iterations = 100;
        }
    }

    BinaryLoader loader;
    loader.register_parser(std::make_unique<bytemorph::formats::pe::PeParser>());
    loader.register_parser(std::make_unique<bytemorph::formats::elf::ElfParser>());
    loader.register_parser(std::make_unique<bytemorph::formats::macho::MachOParser>());

    // Build synthetic 4KB x86-64 and ARM64 code buffers
    std::vector<std::uint8_t> x86_code;
    const auto x86_unit = bytemorph::tests::sample_x86_64_code();
    while (x86_code.size() < 4096) {
        x86_code.insert(x86_code.end(), x86_unit.begin(), x86_unit.end());
    }
    const auto pe_buf = bytemorph::tests::build_minimal_pe64_x86_64(x86_code);
    const auto elf_buf = bytemorph::tests::build_minimal_elf64_x86_64(x86_code);

    bytemorph::arch::x86_64::X86_64Disassembler x86_disasm;
    BinaryAnalyzer analyzer;

    auto bench = [&](const char* label, const std::vector<std::uint8_t>& buf) {
        const auto t0 = std::chrono::steady_clock::now();
        std::size_t total_insns = 0;
        for (int i = 0; i < iterations; ++i) {
            auto bin = loader.load_buffer(buf);
            if (!bin) return;
            auto res = analyzer.analyze(*bin.value(), x86_disasm);
            if (res) {
                total_insns += res.value().total_instructions;
            }
        }
        const auto t1 = std::chrono::steady_clock::now();
        const double ms = std::chrono::duration<double, std::milli>(t1 - t0).count();
        std::cout << std::left << std::setw(26) << label
                  << " iters=" << iterations
                  << " total_ms=" << std::fixed << std::setprecision(2) << ms
                  << " avg_ms=" << std::setprecision(4) << (ms / iterations)
                  << " insns=" << total_insns << '\n';
    };

    std::cout << "=== ByteMorph v0.2 Reproducible Analysis Benchmark ===\n";
    bench("PE32+ x86-64 (4KB .text)", pe_buf);
    bench("ELF64 x86-64 (4KB .text)", elf_buf);
    return 0;
}
