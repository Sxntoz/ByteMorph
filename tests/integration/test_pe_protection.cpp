#include "bytemorph/core/binary/loader.hpp"
#include "bytemorph/formats/pe/pe_parser.hpp"
#include "bytemorph/prot/crypto_aead.hpp"
#include "bytemorph/prot/pe_rewriter.hpp"
#include "sample_builder.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

using namespace bytemorph::prot;
using namespace bytemorph::core::binary;

namespace {

std::string run_and_capture(const std::filesystem::path& exe, const std::string& args) {
#if defined(_WIN32)
    const std::string cmd = "\"" + exe.string() + "\" " + args;
    FILE* pipe = _popen(cmd.c_str(), "r");
    if (!pipe) return {};
    std::string out;
    char buf[256];
    while (std::fgets(buf, sizeof(buf), pipe) != nullptr) {
        out += buf;
    }
    _pclose(pipe);
    return out;
#else
    (void)exe;
    (void)args;
    return {};
#endif
}

} // namespace

TEST(ProtectionV04Test, CryptoAeadSealsOpensAndDetectsTampering) {
    const std::string msg = "ByteMorph authenticated payload";
    const std::string aad_str = "BMP4-AAD";
    const auto key = CryptoAead::derive_key_from_seed(0x99887766ULL, "test");
    const auto nonce = CryptoAead::generate_nonce(0x99887766ULL, 1);

    std::span<const std::uint8_t> pt(reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size());
    std::span<const std::uint8_t> aad(reinterpret_cast<const std::uint8_t*>(aad_str.data()), aad_str.size());

    auto sealed = CryptoAead::seal(pt, aad, key, nonce);
    ASSERT_TRUE(sealed.has_value());

    auto opened = CryptoAead::open(sealed.value(), aad, key);
    ASSERT_TRUE(opened.has_value());
    EXPECT_EQ(std::string(opened.value().begin(), opened.value().end()), msg);

    // Tamper ciphertext
    auto tampered = sealed.value();
    tampered.ciphertext[0] ^= 0x01;
    EXPECT_FALSE(CryptoAead::open(tampered, aad, key).has_value());

    // Wrong key
    const auto wrong_key = CryptoAead::derive_key_from_seed(0x11223344ULL, "test");
    EXPECT_FALSE(CryptoAead::open(sealed.value(), aad, wrong_key).has_value());
}

TEST(ProtectionV04Test, RejectsUnsupportedElfArm64AndMalformedInputsCleanly) {
    const auto tmp_dir = std::filesystem::temp_directory_path();
    const auto elf_path = tmp_dir / "bm_test_elf64_arm64.bin";
    const auto out_path = tmp_dir / "bm_test_elf64_arm64_out.bin";

    {
        auto elf = bytemorph::tests::build_minimal_elf64_arm64(bytemorph::tests::sample_arm64_code());
        std::ofstream ofs(elf_path, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(elf.data()), static_cast<std::streamsize>(elf.size()));
    }

    ProtectOptions opts;
    auto res = ProtectionEngine::protect(elf_path, out_path, opts);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, bytemorph::core::diagnostics::ErrorCode::NotImplemented);

    std::error_code ec;
    std::filesystem::remove(elf_path, ec);
    std::filesystem::remove(out_path, ec);
}

#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
TEST(ProtectionV04Test, ProtectsAndExecutesRealWindowsPe64LabBinary) {
#ifdef BYTEMORPH_LAB_PE_TARGET_PATH
    const std::filesystem::path lab_exe(BYTEMORPH_LAB_PE_TARGET_PATH);
#else
    const std::filesystem::path lab_exe("lab_pe_target.exe");
#endif
    ASSERT_TRUE(std::filesystem::exists(lab_exe)) << "Missing lab executable: " << lab_exe;

    const auto tmp_dir = std::filesystem::temp_directory_path();
    const auto prot_bal = tmp_dir / "lab_pe_protected_balanced.exe";
    const auto prot_max = tmp_dir / "lab_pe_protected_max.exe";

    ProtectOptions opts;
    opts.profile = ProtectionProfile::Balanced;
    opts.seed = 0x55AA1234ULL;
    opts.target_function_name = "bm_target_compute";

    auto rep = ProtectionEngine::protect(lab_exe, prot_bal, opts);
    ASSERT_TRUE(rep.has_value()) << rep.error().to_string();
    EXPECT_TRUE(rep.value().aslr_preserved);
    EXPECT_TRUE(rep.value().dep_preserved);
    ASSERT_EQ(rep.value().protected_functions.size(), 1u);

    auto ver = ProtectionEngine::verify(prot_bal);
    ASSERT_TRUE(ver.has_value()) << ver.error().to_string();
    EXPECT_TRUE(ver.value().valid);
    EXPECT_TRUE(ver.value().aead_authenticated);
    EXPECT_TRUE(ver.value().text_integrity_ok);
    EXPECT_TRUE(ver.value().runtime_integrity_ok);

    // Execute original vs protected PE32+ x64 with multiple inputs
    for (const std::string& args : {std::string("42 19"), std::string("100 37"), std::string("0 0")}) {
        const auto orig_out = run_and_capture(lab_exe, args);
        const auto prot_out = run_and_capture(prot_bal, args);
        EXPECT_FALSE(orig_out.empty());
        EXPECT_EQ(orig_out, prot_out) << "Mismatch for args: " << args;
    }

    // Diversification with Maximum profile + different seed
    opts.profile = ProtectionProfile::Maximum;
    opts.seed = 0x99887766ULL;
    auto rep_max = ProtectionEngine::protect(lab_exe, prot_max, opts);
    ASSERT_TRUE(rep_max.has_value()) << rep_max.error().to_string();
    EXPECT_EQ(run_and_capture(lab_exe, "42 19"), run_and_capture(prot_max, "42 19"));

    // Verify tampering detection on protected PE (.text section modification)
    {
        bytemorph::core::binary::BinaryLoader loader;
        loader.register_parser(std::make_unique<bytemorph::formats::pe::PeParser>());
        auto loaded = loader.load_file(prot_bal);
        ASSERT_TRUE(loaded.has_value());
        std::uint64_t text_raw_off = 0;
        for (const auto& s : loaded.value()->sections()) {
            if (s.name == ".text" && s.raw_size > 16) {
                text_raw_off = s.raw_offset + 8;
                break;
            }
        }
        ASSERT_GT(text_raw_off, 0u);
        std::fstream fs(prot_bal, std::ios::in | std::ios::out | std::ios::binary);
        ASSERT_TRUE(fs.is_open());
        fs.seekg(static_cast<std::streamoff>(text_raw_off), std::ios::beg);
        char b = 0;
        fs.read(&b, 1);
        b ^= 0x7F;
        fs.seekp(static_cast<std::streamoff>(text_raw_off), std::ios::beg);
        fs.write(&b, 1);
    }
    auto ver_tampered = ProtectionEngine::verify(prot_bal);
    ASSERT_TRUE(ver_tampered.has_value());
    EXPECT_FALSE(ver_tampered.value().valid);

    std::error_code ec;
    std::filesystem::remove(prot_bal, ec);
    std::filesystem::remove(prot_max, ec);
}
#endif
