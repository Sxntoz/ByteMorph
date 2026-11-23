#include "bytemorph/arch/x86_64/x86_64_disasm.hpp"
#include "bytemorph/core/analysis/analyzer.hpp"
#include "bytemorph/core/binary/loader.hpp"
#include "bytemorph/formats/elf/elf_parser.hpp"
#include "bytemorph/formats/pe/pe_parser.hpp"
#include "sample_builder.hpp"

#include <gtest/gtest.h>

using namespace bytemorph::core::binary;
using namespace bytemorph::core::analysis;
using namespace bytemorph::arch::x86_64;
using namespace bytemorph::tests;

namespace {

BinaryLoader make_loader() {
    BinaryLoader loader;
    loader.register_parser(std::make_unique<bytemorph::formats::pe::PeParser>());
    loader.register_parser(std::make_unique<bytemorph::formats::elf::ElfParser>());
    return loader;
}

} // namespace

TEST(IntegrationTest, ParsesAndAnalyzesElf64Sample) {
    auto loader = make_loader();
    auto bin_res = loader.load_buffer(build_minimal_elf64_x86_64(sample_x86_64_code()));
    ASSERT_TRUE(bin_res.has_value()) << bin_res.error().to_string();

    const auto& bin = *bin_res.value();
    EXPECT_EQ(bin.info().format, BinaryFormat::ELF64);
    EXPECT_EQ(bin.info().architecture, Architecture::X86_64);
    EXPECT_EQ(bin.info().entry_point, 0x401000);
    EXPECT_GE(bin.sections().size(), 2u);
    EXPECT_GE(bin.segments().size(), 1u);

    X86_64Disassembler disasm;
    BinaryAnalyzer analyzer;
    auto an_res = analyzer.analyze(bin, disasm);
    ASSERT_TRUE(an_res.has_value()) << an_res.error().to_string();

    // Expect _start + sub_0x40100c discovered from direct call
    EXPECT_GE(an_res.value().functions.size(), 2u);
    EXPECT_FALSE(an_res.value().limitations.empty());
}

TEST(IntegrationTest, ParsesAndAnalyzesPe32PlusSample) {
    auto loader = make_loader();
    auto bin_res = loader.load_buffer(build_minimal_pe64_x86_64(sample_x86_64_code()));
    ASSERT_TRUE(bin_res.has_value()) << bin_res.error().to_string();

    const auto& bin = *bin_res.value();
    EXPECT_EQ(bin.info().format, BinaryFormat::PE32Plus);
    EXPECT_EQ(bin.info().architecture, Architecture::X86_64);
    EXPECT_EQ(bin.info().image_base, 0x140000000ULL);
    EXPECT_EQ(bin.info().entry_point, 0x140001000ULL);
    EXPECT_TRUE(bin.info().is_pie);
    EXPECT_TRUE(bin.info().has_nx);
    ASSERT_EQ(bin.sections().size(), 1u);
    EXPECT_TRUE(bin.sections()[0].executable);

    X86_64Disassembler disasm;
    BinaryAnalyzer analyzer;
    auto an_res = analyzer.analyze(bin, disasm);
    ASSERT_TRUE(an_res.has_value()) << an_res.error().to_string();

    EXPECT_GE(an_res.value().functions.size(), 2u);
    EXPECT_GT(an_res.value().total_instructions, 5u);
}
