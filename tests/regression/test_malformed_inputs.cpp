#include "bytemorph/core/binary/loader.hpp"
#include "bytemorph/formats/elf/elf_parser.hpp"
#include "bytemorph/formats/macho/macho_parser.hpp"
#include "bytemorph/formats/pe/pe_parser.hpp"

#include <gtest/gtest.h>
#include <random>

using namespace bytemorph::core::binary;
using namespace bytemorph::core::diagnostics;

namespace {

BinaryLoader make_full_loader() {
    BinaryLoader loader;
    loader.register_parser(std::make_unique<bytemorph::formats::pe::PeParser>());
    loader.register_parser(std::make_unique<bytemorph::formats::elf::ElfParser>());
    loader.register_parser(std::make_unique<bytemorph::formats::macho::MachOParser>());
    return loader;
}

} // namespace

TEST(RegressionMalformedTest, RejectsEmptyAndTruncatedBuffers) {
    auto loader = make_full_loader();

    auto empty_res = loader.load_buffer({});
    ASSERT_FALSE(empty_res.has_value());
    EXPECT_EQ(empty_res.error().code, ErrorCode::EmptyInput);

    auto short_res = loader.load_buffer({0x4D, 0x5A});
    ASSERT_FALSE(short_res.has_value());
    EXPECT_EQ(short_res.error().code, ErrorCode::TruncatedData);

    auto elf_trunc = loader.load_buffer({0x7F, 'E', 'L', 'F', 2, 1});
    ASSERT_FALSE(elf_trunc.has_value());
    EXPECT_EQ(elf_trunc.error().code, ErrorCode::TruncatedData);
}

TEST(RegressionMalformedTest, RejectsOutOfBoundsPeLfanew) {
    auto loader = make_full_loader();
    std::vector<std::uint8_t> bad_pe(0x40, 0);
    bad_pe[0] = 'M';
    bad_pe[1] = 'Z';
    bad_pe[0x3C] = 0xFF;
    bad_pe[0x3D] = 0xFF;
    bad_pe[0x3E] = 0xFF;
    bad_pe[0x3F] = 0x7F;

    auto res = loader.load_buffer(std::move(bad_pe));
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, ErrorCode::TruncatedData);
}

TEST(RegressionMalformedTest, RejectsTruncatedAndCorruptedMachO) {
    auto loader = make_full_loader();

    // Truncated 8-byte Mach-O header
    std::vector<std::uint8_t> trunc_macho = {0xCF, 0xFA, 0xED, 0xFE, 0x07, 0x00, 0x00, 0x01};
    auto res1 = loader.load_buffer(std::move(trunc_macho));
    EXPECT_FALSE(res1.has_value());

    // Invalid Fat Mach-O claiming 99999 slices
    std::vector<std::uint8_t> bad_fat = {0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01, 0x86, 0x9F};
    auto res2 = loader.load_buffer(std::move(bad_fat));
    EXPECT_FALSE(res2.has_value());
}

TEST(RegressionMalformedTest, DeterministicFuzzSmokeNeverCrashes) {
    auto loader = make_full_loader();
    std::mt19937 rng(0xB47E0002u);
    std::uniform_int_distribution<int> byte_dist(0, 255);
    std::uniform_int_distribution<std::size_t> len_dist(0, 512);

    const std::vector<std::vector<std::uint8_t>> prefixes = {
        {'M', 'Z'},
        {0x7F, 'E', 'L', 'F'},
        {0xCF, 0xFA, 0xED, 0xFE},
        {0xCA, 0xFE, 0xBA, 0xBE}
    };

    for (int iter = 0; iter < 150; ++iter) {
        const std::size_t len = len_dist(rng);
        std::vector<std::uint8_t> fuzz(len);
        for (auto& b : fuzz) {
            b = static_cast<std::uint8_t>(byte_dist(rng));
        }
        if (len >= 4) {
            const auto& p = prefixes[static_cast<std::size_t>(iter) % prefixes.size()];
            std::copy(p.begin(), p.end(), fuzz.begin());
        }
        auto res = loader.load_buffer(std::move(fuzz));
        if (res) {
            (void)res.value()->read_virtual(0x1000, 64);
        }
    }
}
