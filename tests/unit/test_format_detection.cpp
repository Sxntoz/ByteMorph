#include "bytemorph/core/binary/loader.hpp"
#include "sample_builder.hpp"

#include <gtest/gtest.h>

using namespace bytemorph::core::binary;
using namespace bytemorph::tests;

TEST(FormatDetectionTest, DetectsElf64X86_64) {
    auto elf = build_minimal_elf64_x86_64(sample_x86_64_code());
    auto res = BinaryLoader::detect_signature(elf);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res.value().format, BinaryFormat::ELF64);
    EXPECT_EQ(res.value().architecture, Architecture::X86_64);
    EXPECT_EQ(res.value().endianness, Endianness::Little);
    EXPECT_EQ(res.value().target_os, TargetOS::Linux);
}

TEST(FormatDetectionTest, DetectsPe32PlusX86_64) {
    auto pe = build_minimal_pe64_x86_64(sample_x86_64_code());
    auto res = BinaryLoader::detect_signature(pe);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res.value().format, BinaryFormat::PE32Plus);
    EXPECT_EQ(res.value().architecture, Architecture::X86_64);
    EXPECT_EQ(res.value().endianness, Endianness::Little);
    EXPECT_EQ(res.value().target_os, TargetOS::Windows);
}

TEST(FormatDetectionTest, DetectsMachO64Arm64) {
    // Minimal 32-byte Mach-O 64 LE header with CPU_TYPE_ARM64 (0x0100000C)
    std::vector<std::uint8_t> macho(32, 0);
    macho[0] = 0xCF; macho[1] = 0xFA; macho[2] = 0xED; macho[3] = 0xFE; // MH_MAGIC_64 (LE)
    macho[4] = 0x0C; macho[5] = 0x00; macho[6] = 0x00; macho[7] = 0x01; // CPU_TYPE_ARM64
    auto res = BinaryLoader::detect_signature(macho);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res.value().format, BinaryFormat::MachO64);
    EXPECT_EQ(res.value().architecture, Architecture::ARM64);
    EXPECT_EQ(res.value().target_os, TargetOS::MacOS);
}
