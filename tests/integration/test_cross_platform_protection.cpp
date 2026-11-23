#include "bytemorph/core/ir/ir.hpp"
#include "bytemorph/prot/pe_rewriter.hpp"
#include "bytemorph/virt/ir_to_vm.hpp"
#include "bytemorph/virt/vm_interpreter.hpp"
#include "sample_builder.hpp"

#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

using namespace bytemorph::core::ir;
using namespace bytemorph::prot;
using namespace bytemorph::virt;

namespace {

std::string run_posix_and_capture(const std::filesystem::path& exe, const std::string& args) {
#if !defined(_WIN32)
    const std::string cmd = "\"" + exe.string() + "\" " + args;
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) return {};
    std::string out;
    char buf[256];
    while (std::fgets(buf, sizeof(buf), pipe) != nullptr) {
        out += buf;
    }
    pclose(pipe);
    return out;
#else
    (void)exe;
    (void)args;
    return {};
#endif
}

} // namespace

TEST(ProtectionV05Test, ExternalCallsAuthorizedAndRejectedProperly) {
    IrFunction fn;
    fn.name = "caller_fn";
    fn.entry_va = 0x1000;
    fn.blocks = {{0, 0x1000, {
        {0x1000, IrOpcode::Call, {}, {IrOperand::label(0x2000)}, {}, ""},
        {0x1005, IrOpcode::Add, {IrOperand::reg("rax")}, {IrOperand::reg("rax"), IrOperand::immediate(5)}, {}, ""},
        {0x1009, IrOpcode::Ret, {}, {}, {}, ""}
    }, {}}};

    // Unauthorized external call target must fail
    TranslateOptions bad_opts;
    bad_opts.allow_external_calls = true;
    bad_opts.stub_base_va = 0x3000;
    bad_opts.authorized_call_targets.insert(0x9999);
    EXPECT_FALSE(IrToVmTranslator::translate(fn, bad_opts).has_value());

    // Authorized external call target translates and executes via bridge
    TranslateOptions ok_opts;
    ok_opts.allow_external_calls = true;
    ok_opts.stub_base_va = 0x3000;
    ok_opts.authorized_call_targets.insert(0x2000);
    auto bvm_res = IrToVmTranslator::translate(fn, ok_opts);
    ASSERT_TRUE(bvm_res.has_value()) << bvm_res.error().to_string();

    VmExecOptions exec_opts;
    exec_opts.external_call_handler = [](std::int64_t rel_off, const auto&) -> std::optional<std::uint64_t> {
        if (rel_off == -0x1000) return 37ULL;
        return std::nullopt;
    };
    auto exec_res = VmInterpreter::execute(bvm_res.value(), exec_opts);
    ASSERT_TRUE(exec_res.has_value()) << exec_res.error().to_string();
    EXPECT_EQ(exec_res.value().return_value, 42ULL);
}

TEST(ProtectionV05Test, CrossProtectsElf64AndMachO64Containers) {
    const auto tmp_dir = std::filesystem::temp_directory_path();
    const std::vector<std::uint8_t> pure_code = {
        0x48, 0x89, 0xF8,             // mov rax, rdi
        0x48, 0x01, 0xF0,             // add rax, rsi
        0xC3                          // ret
    };

    // 1. Cross-protect ELF64 x86-64 container (works on Windows, Linux, and macOS!)
    {
        const auto elf_in = tmp_dir / "bm_v05_cross_elf.bin";
        const auto elf_out = tmp_dir / "bm_v05_cross_elf_prot.bin";
        auto elf = bytemorph::tests::build_minimal_elf64_x86_64(pure_code);
        {
            std::ofstream ofs(elf_in, std::ios::binary);
            ofs.write(reinterpret_cast<const char*>(elf.data()), static_cast<std::streamsize>(elf.size()));
        }

        ProtectOptions opts;
        opts.target_function_rva = 0x1000; // .text starts at 0x401000, imagebase 0x400000
        opts.profile = ProtectionProfile::Balanced;
        auto rep = ProtectionEngine::protect(elf_in, elf_out, opts);
        ASSERT_TRUE(rep.has_value()) << rep.error().to_string();
        EXPECT_EQ(rep.value().format, bytemorph::core::binary::BinaryFormat::ELF64);

        auto ver = ProtectionEngine::verify(elf_out);
        ASSERT_TRUE(ver.has_value()) << ver.error().to_string();
        EXPECT_TRUE(ver.value().valid);

        std::error_code ec;
        std::filesystem::remove(elf_in, ec);
        std::filesystem::remove(elf_out, ec);
    }

    // 2. Cross-protect Mach-O 64-bit ARM64 container
    {
        const auto macho_in = tmp_dir / "bm_v05_cross_macho.bin";
        const auto macho_out = tmp_dir / "bm_v05_cross_macho_prot.bin";
        const std::vector<std::uint8_t> arm_code = {
            0x00, 0x00, 0x01, 0x8B, // add x0, x0, x1
            0xC0, 0x03, 0x5F, 0xD6  // ret
        };
        auto macho = bytemorph::tests::build_minimal_macho64(true, arm_code);
        {
            std::ofstream ofs(macho_in, std::ios::binary);
            ofs.write(reinterpret_cast<const char*>(macho.data()), static_cast<std::streamsize>(macho.size()));
        }

        ProtectOptions opts;
        opts.target_function_rva = 0x1000;
        opts.profile = ProtectionProfile::Balanced;
        auto rep = ProtectionEngine::protect(macho_in, macho_out, opts);
        ASSERT_TRUE(rep.has_value()) << rep.error().to_string();
        EXPECT_EQ(rep.value().format, bytemorph::core::binary::BinaryFormat::MachO64);

        auto ver = ProtectionEngine::verify(macho_out);
        ASSERT_TRUE(ver.has_value()) << ver.error().to_string();
        EXPECT_TRUE(ver.value().valid);

        std::error_code ec;
        std::filesystem::remove(macho_in, ec);
        std::filesystem::remove(macho_out, ec);
    }
}

#if defined(__linux__) && defined(__x86_64__)
TEST(ProtectionV05Test, ProtectsAndExecutesRealLinuxElf64LabBinary) {
    const std::filesystem::path lab_exe(BYTEMORPH_LAB_PE_TARGET_PATH);
    ASSERT_TRUE(std::filesystem::exists(lab_exe));

    const auto tmp_dir = std::filesystem::temp_directory_path();
    const auto prot_exe = tmp_dir / "lab_elf64_protected";

    ProtectOptions opts;
    opts.profile = ProtectionProfile::Balanced;
    opts.seed = 0xE1F64005ULL;
    opts.target_function_name = "bm_target_compute";

    auto rep = ProtectionEngine::protect(lab_exe, prot_exe, opts);
    ASSERT_TRUE(rep.has_value()) << rep.error().to_string();
    auto ver = ProtectionEngine::verify(prot_exe);
    ASSERT_TRUE(ver.has_value() && ver.value().valid);

    EXPECT_EQ(run_posix_and_capture(lab_exe, "42 19"), run_posix_and_capture(prot_exe, "42 19"));
    EXPECT_EQ(run_posix_and_capture(lab_exe, "100 37"), run_posix_and_capture(prot_exe, "100 37"));

    std::error_code ec;
    std::filesystem::remove(prot_exe, ec);
}
#endif

#if defined(__APPLE__) && (defined(__aarch64__) || defined(__x86_64__))
TEST(ProtectionV05Test, ProtectsAndExecutesRealMacOSMachO64LabBinary) {
    const std::filesystem::path lab_exe(BYTEMORPH_LAB_PE_TARGET_PATH);
    ASSERT_TRUE(std::filesystem::exists(lab_exe));

    const auto tmp_dir = std::filesystem::temp_directory_path();
    const auto prot_exe = tmp_dir / "lab_macho64_protected";

    ProtectOptions opts;
    opts.profile = ProtectionProfile::Balanced;
    opts.seed = 0xAAC00005ULL;
    opts.target_function_name = "bm_target_compute";
    opts.allow_strip_signature = true; // ad-hoc re-signed by MachORewriter via /usr/bin/codesign

    auto rep = ProtectionEngine::protect(lab_exe, prot_exe, opts);
    ASSERT_TRUE(rep.has_value()) << rep.error().to_string();
    auto ver = ProtectionEngine::verify(prot_exe);
    ASSERT_TRUE(ver.has_value() && ver.value().valid);

    EXPECT_EQ(run_posix_and_capture(lab_exe, "42 19"), run_posix_and_capture(prot_exe, "42 19"));
    EXPECT_EQ(run_posix_and_capture(lab_exe, "100 37"), run_posix_and_capture(prot_exe, "100 37"));

    std::error_code ec;
    std::filesystem::remove(prot_exe, ec);
}
#endif
