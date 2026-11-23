#include "bytemorph/arch/aarch64/aarch64_disasm.hpp"
#include "bytemorph/arch/x86_64/x86_64_disasm.hpp"
#include "bytemorph/core/analysis/analyzer.hpp"
#include "bytemorph/core/binary/loader.hpp"
#include "bytemorph/formats/elf/elf_parser.hpp"
#include "bytemorph/formats/macho/macho_parser.hpp"
#include "bytemorph/formats/pe/pe_parser.hpp"
#include "sample_builder.hpp"

#include <gtest/gtest.h>

using namespace bytemorph::core::binary;
using namespace bytemorph::core::analysis;
using namespace bytemorph::tests;

namespace {

BinaryLoader make_all_loader() {
    BinaryLoader loader;
    loader.register_parser(std::make_unique<bytemorph::formats::pe::PeParser>());
    loader.register_parser(std::make_unique<bytemorph::formats::elf::ElfParser>());
    loader.register_parser(std::make_unique<bytemorph::formats::macho::MachOParser>());
    return loader;
}

} // namespace

TEST(IntegrationV02Test, ParsesAndAnalyzesMachOX86_64) {
    auto loader = make_all_loader();
    auto macho = build_minimal_macho64(false, sample_x86_64_code());
    auto bin_res = loader.load_buffer(std::move(macho));
    ASSERT_TRUE(bin_res.has_value()) << bin_res.error().to_string();

    const auto& bin = *bin_res.value();
    EXPECT_EQ(bin.info().format, BinaryFormat::MachO64);
    EXPECT_EQ(bin.info().architecture, Architecture::X86_64);
    EXPECT_EQ(bin.info().target_os, TargetOS::MacOS);
    EXPECT_EQ(bin.info().entry_point, 0x100001000ULL);

    bytemorph::arch::x86_64::X86_64Disassembler disasm;
    BinaryAnalyzer analyzer;
    auto an_res = analyzer.analyze(bin, disasm);
    ASSERT_TRUE(an_res.has_value()) << an_res.error().to_string();
    EXPECT_GE(an_res.value().functions.size(), 2u);
}

TEST(IntegrationV02Test, ParsesAndAnalyzesMachOArm64) {
    auto loader = make_all_loader();
    auto macho = build_minimal_macho64(true, sample_arm64_code());
    auto bin_res = loader.load_buffer(std::move(macho));
    ASSERT_TRUE(bin_res.has_value()) << bin_res.error().to_string();

    const auto& bin = *bin_res.value();
    EXPECT_EQ(bin.info().format, BinaryFormat::MachO64);
    EXPECT_EQ(bin.info().architecture, Architecture::ARM64);

    bytemorph::arch::aarch64::AArch64Disassembler disasm;
    BinaryAnalyzer analyzer;
    auto an_res = analyzer.analyze(bin, disasm);
    ASSERT_TRUE(an_res.has_value()) << an_res.error().to_string();
    EXPECT_GE(an_res.value().functions.size(), 2u);
}

TEST(IntegrationV02Test, ParsesAndAnalyzesElf64Arm64) {
    auto loader = make_all_loader();
    auto elf = build_minimal_elf64_arm64(sample_arm64_code());
    auto bin_res = loader.load_buffer(std::move(elf));
    ASSERT_TRUE(bin_res.has_value()) << bin_res.error().to_string();

    const auto& bin = *bin_res.value();
    EXPECT_EQ(bin.info().format, BinaryFormat::ELF64);
    EXPECT_EQ(bin.info().architecture, Architecture::ARM64);

    bytemorph::arch::aarch64::AArch64Disassembler disasm;
    BinaryAnalyzer analyzer;
    auto an_res = analyzer.analyze(bin, disasm);
    ASSERT_TRUE(an_res.has_value()) << an_res.error().to_string();
    EXPECT_GE(an_res.value().functions.size(), 2u);
}

TEST(IntegrationV02Test, ParsesFatUniversalMachO) {
    auto loader = make_all_loader();
    auto x64_slice = build_minimal_macho64(false, sample_x86_64_code());
    auto arm64_slice = build_minimal_macho64(true, sample_arm64_code());
    auto fat = build_minimal_macho_fat(x64_slice, arm64_slice);

    auto bin_res = loader.load_buffer(std::move(fat));
    ASSERT_TRUE(bin_res.has_value()) << bin_res.error().to_string();

    const auto& bin = *bin_res.value();
    EXPECT_TRUE(bin.info().is_fat_binary);
    ASSERT_EQ(bin.info().fat_architectures.size(), 2u);
}

TEST(IntegrationV02Test, Cfg2DetectsLoopsAndIsDeterministic) {
    auto loader = make_all_loader();
    const auto pe_buf = build_minimal_pe64_x86_64(sample_x86_64_loop_code());

    bytemorph::arch::x86_64::X86_64Disassembler disasm;
    BinaryAnalyzer analyzer;

    auto bin1 = loader.load_buffer(pe_buf);
    auto bin2 = loader.load_buffer(pe_buf);
    ASSERT_TRUE(bin1.has_value() && bin2.has_value());

    auto res1 = analyzer.analyze(*bin1.value(), disasm);
    auto res2 = analyzer.analyze(*bin2.value(), disasm);
    ASSERT_TRUE(res1.has_value() && res2.has_value());

    EXPECT_GE(res1.value().total_loops, 1u);
    EXPECT_EQ(res1.value().functions.size(), res2.value().functions.size());
    EXPECT_EQ(res1.value().total_instructions, res2.value().total_instructions);
    EXPECT_EQ(res1.value().total_loops, res2.value().total_loops);
}
