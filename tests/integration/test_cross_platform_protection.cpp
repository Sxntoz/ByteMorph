#include "bytemorph/arch/aarch64/aarch64_disasm.hpp"
#include "bytemorph/arch/aarch64/aarch64_lifter.hpp"
#include "bytemorph/arch/x86_64/x86_64_disasm.hpp"
#include "bytemorph/arch/x86_64/x86_64_lifter.hpp"
#include "bytemorph/core/analysis/analyzer.hpp"
#include "bytemorph/core/binary/loader.hpp"
#include "bytemorph/formats/pe/pe_parser.hpp"
#include "bytemorph/core/ir/ir.hpp"
#include "bytemorph/core/ir/ir_interpreter.hpp"
#include "bytemorph/core/ir/ir_optimizer.hpp"
#include "bytemorph/obf/obfuscation_engine.hpp"
#include "bytemorph/prot/lazy_bytecode.hpp"
#include "bytemorph/prot/native_vm_emitter.hpp"
#include "bytemorph/prot/pe_rewriter.hpp"
#include "bytemorph/virt/ir_to_vm.hpp"
#include "bytemorph/virt/vm_interpreter.hpp"
#include "sample_builder.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <limits>
#include <string>
#include <thread>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/mman.h>
#endif

using namespace bytemorph::core::analysis;
using namespace bytemorph::core::ir;
using namespace bytemorph::obf;
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

// ============================================================================
// ByteMorph v0.6 Tests: Stack Frames, 8/16/32/64-bit Memory, Control Flow & ARM64
// ============================================================================

TEST(ProtectionV06Test, LoadAndStore8_16_32_64BitAndBoundsChecking) {
    IrFunction fn;
    fn.name = "mem_widths_fn";
    fn.entry_va = 0x1000;

    auto rbp = IrOperand::reg("rbp");
    auto rax = IrOperand::reg("rax");
    auto rcx = IrOperand::reg("rcx");
    auto rdx = IrOperand::reg("rdx");
    auto r8  = IrOperand::reg("r8");

    // Store 8-bit (0x1234 -> 0x34 at [rbp-8]), 16-bit (0xABCD1234 -> 0x1234 at [rbp-16]),
    // 32-bit (0xFFFFFFFFCAFEBABE -> 0xCAFEBABE at [rbp-24]), 64-bit (0x1122334455667788 at [rbp+16])
    fn.blocks = {{0, 0x1000, {
        {0x1000, IrOpcode::Store, {IrOperand::memory_disp("rbp", -8, 8)},  {IrOperand::immediate(0x1234, 64)}, {}, ""},
        {0x1004, IrOpcode::Store, {IrOperand::memory_disp("rbp", -16, 16)}, {IrOperand::immediate(0xABCD1234LL, 64)}, {}, ""},
        {0x1008, IrOpcode::Store, {IrOperand::memory_disp("rbp", -24, 32)}, {IrOperand::immediate(0x1122334455667788LL, 64)}, {}, ""},
        {0x100C, IrOpcode::Store, {IrOperand::memory_disp("rbp", 16, 64)},  {IrOperand::immediate(0x100000000LL, 64)}, {}, ""},
        {0x1010, IrOpcode::Load,  {rax}, {IrOperand::memory_disp("rbp", -8, 8)}, {}, ""},
        {0x1014, IrOpcode::Load,  {rcx}, {IrOperand::memory_disp("rbp", -16, 16)}, {}, ""},
        {0x1018, IrOpcode::Load,  {rdx}, {IrOperand::memory_disp("rbp", -24, 32)}, {}, ""},
        {0x101C, IrOpcode::Load,  {r8},  {IrOperand::memory_disp("rbp", 16, 64)}, {}, ""},
        {0x1020, IrOpcode::Add,   {rax}, {rax, rcx}, {}, ""},
        {0x1024, IrOpcode::Add,   {rax}, {rax, rdx}, {}, ""},
        {0x1028, IrOpcode::Add,   {rax}, {rax, r8}, {}, ""},
        {0x102C, IrOpcode::Ret,   {}, {}, {}, ""}
    }, {}}};

    auto ir_out = IrInterpreter::execute(fn);
    ASSERT_TRUE(ir_out.has_value()) << ir_out.error().to_string();

    auto bvm_res = IrToVmTranslator::translate(fn, 0x6001ULL);
    ASSERT_TRUE(bvm_res.has_value()) << bvm_res.error().to_string();

    auto vm_out = VmInterpreter::execute(bvm_res.value());
    ASSERT_TRUE(vm_out.has_value()) << vm_out.error().to_string();

    const std::uint64_t expected = 0x34ULL + 0x1234ULL + 0x55667788ULL + 0x100000000ULL;
    EXPECT_EQ(ir_out.value().return_value, expected);
    EXPECT_EQ(vm_out.value().return_value, expected);

    // Out-of-bounds memory access detection (negative address and past end of buffer)
    BvmProgram bad_neg;
    bad_neg.instructions = {
        {VmOpcode::MovImm, 1, 0, 0, 0},
        {VmOpcode::Load, 0, 1, 64, -16},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };
    EXPECT_FALSE(VmInterpreter::execute(bad_neg).has_value());

    BvmProgram bad_high;
    bad_high.instructions = {
        {VmOpcode::MovImm, 1, 0, 0, 1000000},
        {VmOpcode::Store, 1, 0, 32, 0},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };
    EXPECT_FALSE(VmInterpreter::execute(bad_high).has_value());
}

TEST(ProtectionV06Test, ComplexStackFramesLocalsArraysAndStructs) {
    // Disassemble & lift a real x86-64 function with prologue, local stack variables,
    // 32-bit array / struct field indexing [rbp - 32 + rcx*4], and epilogue (leave; ret)
    const std::vector<std::uint8_t> code = {
        0x55,                               // push rbp
        0x48, 0x89, 0xE5,                   // mov rbp, rsp
        0x48, 0x83, 0xEC, 0x40,             // sub rsp, 64
        0x48, 0x89, 0x7D, 0xF8,             // mov [rbp-8], rdi (arg0)
        0x48, 0x89, 0x75, 0xF0,             // mov [rbp-16], rsi (arg1)
        0xC7, 0x45, 0xE0, 0x0A, 0x00, 0x00, 0x00, // mov dword ptr [rbp-32], 10 (arr[0])
        0xC7, 0x45, 0xE4, 0x14, 0x00, 0x00, 0x00, // mov dword ptr [rbp-28], 20 (arr[1])
        0x48, 0xC7, 0xC1, 0x01, 0x00, 0x00, 0x00, // mov rcx, 1
        0x8B, 0x44, 0x8D, 0xE0,             // mov eax, dword ptr [rbp+rcx*4-32] (loads arr[1] = 20)
        0x48, 0x03, 0x45, 0xF8,             // add rax, qword ptr [rbp-8]
        0x48, 0x03, 0x45, 0xF0,             // add rax, qword ptr [rbp-16]
        0xC9,                               // leave
        0xC3                                // ret
    };

    bytemorph::arch::x86_64::X86_64Disassembler disasm;
    bytemorph::arch::x86_64::X86_64Lifter lifter;
    auto dis_res = disasm.disassemble(code, 0x401000);
    ASSERT_TRUE(dis_res.has_value());

    FunctionInfo fn_info;
    fn_info.name = "stack_array_fn";
    fn_info.entry_va = 0x401000;
    BasicBlock bb;
    bb.start_va = 0x401000;
    bb.instructions = dis_res.value();
    fn_info.blocks.push_back(bb);

    IrFunction ir_fn = lifter.lift_function(fn_info);

    IrExecOptions ir_opts;
    ir_opts.initial_regs["rdi"] = 42;
    ir_opts.initial_regs["rsi"] = 19;
    auto ir_out = IrInterpreter::execute(ir_fn, ir_opts);
    ASSERT_TRUE(ir_out.has_value()) << ir_out.error().to_string();
    EXPECT_EQ(ir_out.value().return_value, 81ULL); // 20 + 42 + 19

    auto bvm_res = IrToVmTranslator::translate(ir_fn, 0x6002ULL);
    ASSERT_TRUE(bvm_res.has_value()) << bvm_res.error().to_string();

    VmExecOptions vm_opts;
    vm_opts.initial_regs[7] = 42; // rdi
    vm_opts.initial_regs[6] = 19; // rsi
    auto vm_out = VmInterpreter::execute(bvm_res.value(), vm_opts);
    ASSERT_TRUE(vm_out.has_value()) << vm_out.error().to_string();
    EXPECT_EQ(vm_out.value().return_value, 81ULL);

    // Verify both PIC x86-64 and PIC ARM64 native runtimes emit cleanly for Load/Store program
    auto rt_x64 = detail::emit_pic_x64_vm_runtime(bvm_res.value(), detail::AbiKind::SysV_AMD64);
    auto rt_a64 = detail::emit_pic_arm64_vm_runtime(bvm_res.value());
    ASSERT_TRUE(rt_x64.has_value()) << rt_x64.error().to_string();
    ASSERT_TRUE(rt_a64.has_value()) << rt_a64.error().to_string();
    EXPECT_GT(rt_x64.value().size(), 128u);
    EXPECT_GT(rt_a64.value().size(), 128u);
}

TEST(ProtectionV06Test, AuthorizedIndirectCallsAndJumpTables) {
    // 1. Authorized Indirect Call (call rcx)
    IrFunction icall_fn;
    icall_fn.name = "indirect_caller";
    icall_fn.entry_va = 0x1000;
    icall_fn.blocks = {{0, 0x1000, {
        {0x1000, IrOpcode::Call, {}, {IrOperand::reg("rcx")}, {}, ""},
        {0x1004, IrOpcode::Add, {IrOperand::reg("rax")}, {IrOperand::reg("rax"), IrOperand::immediate(10)}, {}, ""},
        {0x1008, IrOpcode::Ret, {}, {}, {}, ""}
    }, {}}};

    // Must fail without authorized_call_targets
    TranslateOptions no_auth;
    no_auth.allow_external_calls = true;
    EXPECT_FALSE(IrToVmTranslator::translate(icall_fn, no_auth).has_value());

    TranslateOptions auth_opts;
    auth_opts.allow_external_calls = true;
    auth_opts.stub_base_va = 0x5000;
    auth_opts.authorized_call_targets = {0x2000, 0x3000};
    auto icall_bvm = IrToVmTranslator::translate(icall_fn, auth_opts);
    ASSERT_TRUE(icall_bvm.has_value()) << icall_bvm.error().to_string();

    VmExecOptions exec_ok;
    exec_ok.initial_regs[1] = 0x3000; // rcx = authorized target 0x3000
    exec_ok.external_call_handler = [](std::int64_t rel_off, const auto&) -> std::optional<std::uint64_t> {
        if (rel_off == -0x3000) return 100ULL;
        if (rel_off == -0x2000) return 200ULL;
        return std::nullopt;
    };
    auto res_ok = VmInterpreter::execute(icall_bvm.value(), exec_ok);
    ASSERT_TRUE(res_ok.has_value()) << res_ok.error().to_string();
    EXPECT_EQ(res_ok.value().return_value, 210ULL);

    // Unauthorized target at runtime (0x9999) must trap with OutOfBounds
    VmExecOptions exec_bad = exec_ok;
    exec_bad.initial_regs[1] = 0x9999;
    EXPECT_FALSE(VmInterpreter::execute(icall_bvm.value(), exec_bad).has_value());

    // 2. Validated Jump Table (switch(rcx) { case 0: return 11; case 1: return 22; case 2: return 33; })
    IrFunction jtbl_fn;
    jtbl_fn.name = "switch_fn";
    jtbl_fn.entry_va = 0x1000;
    jtbl_fn.blocks = {
        {0, 0x1000, {{0x1000, IrOpcode::Jump, {}, {IrOperand::reg("rcx")}, {}, ""}}, {0x1010, 0x1020, 0x1030}},
        {1, 0x1010, {{0x1010, IrOpcode::Mov, {IrOperand::reg("rax")}, {IrOperand::immediate(11)}, {}, ""},
                     {0x1014, IrOpcode::Ret, {}, {}, {}, ""}}, {}},
        {2, 0x1020, {{0x1020, IrOpcode::Mov, {IrOperand::reg("rax")}, {IrOperand::immediate(22)}, {}, ""},
                     {0x1024, IrOpcode::Ret, {}, {}, {}, ""}}, {}},
        {3, 0x1030, {{0x1030, IrOpcode::Mov, {IrOperand::reg("rax")}, {IrOperand::immediate(33)}, {}, ""},
                     {0x1034, IrOpcode::Ret, {}, {}, {}, ""}}, {}}
    };

    // Must fail without jump table targets
    EXPECT_FALSE(IrToVmTranslator::translate(jtbl_fn).has_value());

    // Must fail if jump table points to non-existent basic block
    TranslateOptions bad_jtbl;
    bad_jtbl.jump_table_targets = {0x1010, 0x9999};
    EXPECT_FALSE(IrToVmTranslator::translate(jtbl_fn, bad_jtbl).has_value());

    TranslateOptions ok_jtbl;
    ok_jtbl.jump_table_targets = {0x1010, 0x1020, 0x1030};
    auto jtbl_bvm = IrToVmTranslator::translate(jtbl_fn, ok_jtbl);
    ASSERT_TRUE(jtbl_bvm.has_value()) << jtbl_bvm.error().to_string();

    for (std::uint64_t c = 0; c < 3; ++c) {
        VmExecOptions jopts;
        jopts.initial_regs[1] = c;
        auto jres = VmInterpreter::execute(jtbl_bvm.value(), jopts);
        ASSERT_TRUE(jres.has_value());
        EXPECT_EQ(jres.value().return_value, (c + 1) * 11ULL);
    }

    // Out-of-bounds case index (5) traps cleanly
    VmExecOptions oob_jopts;
    oob_jopts.initial_regs[1] = 5;
    EXPECT_FALSE(VmInterpreter::execute(jtbl_bvm.value(), oob_jopts).has_value());
}

TEST(ProtectionV06Test, NestedLoopsMultipleReturnsChainedCallsAndRecursion) {
    // 1. Nested loop with early return (if rcx == 0 return 999; else sum_{i=1..rcx} sum_{j=1..rdx} (i * j))
    IrFunction nested_fn;
    nested_fn.name = "nested_loops_multi_ret";
    nested_fn.entry_va = 0x1000;
    auto rax = IrOperand::reg("rax");
    auto rcx = IrOperand::reg("rcx");
    auto rdx = IrOperand::reg("rdx");
    auto r8  = IrOperand::reg("r8");  // i
    auto r9  = IrOperand::reg("r9");  // j
    auto r10 = IrOperand::reg("r10"); // tmp

    nested_fn.blocks = {
        {0, 0x1000, {
            {0x1000, IrOpcode::Cmp, {}, {rcx, IrOperand::immediate(0)}, {}, ""},
            {0x1004, IrOpcode::JumpCond, {}, {IrOperand::label(0x1010)}, "jg", ""},
            {0x1008, IrOpcode::Mov, {rax}, {IrOperand::immediate(999)}, {}, ""},
            {0x100C, IrOpcode::Ret, {}, {}, {}, ""}
        }, {0x1010}},
        {1, 0x1010, {
            {0x1010, IrOpcode::Mov, {rax}, {IrOperand::immediate(0)}, {}, ""},
            {0x1014, IrOpcode::Mov, {r8},  {IrOperand::immediate(1)}, {}, ""}
        }, {0x1020}},
        {2, 0x1020, { // outer loop header
            {0x1020, IrOpcode::Mov, {r9},  {IrOperand::immediate(1)}, {}, ""}
        }, {0x1030}},
        {3, 0x1030, { // inner loop body
            {0x1030, IrOpcode::Mul, {r10}, {r8, r9}, {}, ""},
            {0x1034, IrOpcode::Add, {rax}, {rax, r10}, {}, ""},
            {0x1038, IrOpcode::Add, {r9},  {r9, IrOperand::immediate(1)}, {}, ""},
            {0x103C, IrOpcode::Cmp, {},    {r9, rdx}, {}, ""},
            {0x1040, IrOpcode::JumpCond, {}, {IrOperand::label(0x1030)}, "jle", ""}
        }, {0x1030, 0x1050}},
        {4, 0x1050, { // outer loop latch
            {0x1050, IrOpcode::Add, {r8},  {r8, IrOperand::immediate(1)}, {}, ""},
            {0x1054, IrOpcode::Cmp, {},    {r8, rcx}, {}, ""},
            {0x1058, IrOpcode::JumpCond, {}, {IrOperand::label(0x1020)}, "jle", ""},
            {0x105C, IrOpcode::Ret, {}, {}, {}, ""}
        }, {0x1020}}
    };

    auto nested_bvm = IrToVmTranslator::translate(nested_fn, 0x6003ULL);
    ASSERT_TRUE(nested_bvm.has_value()) << nested_bvm.error().to_string();

    // Test early return path (rcx = 0 -> 999)
    {
        IrExecOptions io; io.initial_regs["rcx"] = 0; io.initial_regs["rdx"] = 3;
        VmExecOptions vo; vo.initial_regs[1] = 0; vo.initial_regs[2] = 3;
        EXPECT_EQ(IrInterpreter::execute(nested_fn, io).value().return_value, 999ULL);
        EXPECT_EQ(VmInterpreter::execute(nested_bvm.value(), vo).value().return_value, 999ULL);
    }
    // Test nested loop path (rcx = 3, rdx = 4 -> (1+2+3)*(1+2+3+4) = 6 * 10 = 60)
    {
        IrExecOptions io; io.initial_regs["rcx"] = 3; io.initial_regs["rdx"] = 4;
        VmExecOptions vo; vo.initial_regs[1] = 3; vo.initial_regs[2] = 4;
        EXPECT_EQ(IrInterpreter::execute(nested_fn, io).value().return_value, 60ULL);
        EXPECT_EQ(VmInterpreter::execute(nested_bvm.value(), vo).value().return_value, 60ULL);
    }

    // 2. Bounded recursion in VM (factorial(6) = 720 using VM stack frame [R4] + VmOpcode::Call)
    // PC 0: Call 2; Halt
    // PC 2: Cmp R1, 1 -> Jle 10
    // PC 4: Sub R4, R4, 8; Store [R4], R1 (save n on virtual stack)
    // PC 6: Sub R1, R1, 1; Call 2 (recurse fact(n-1) -> R0)
    // PC 8: Load R2, [R4]; Add R4, R4, 8; Mul R0, R0, R2; Ret
    // PC 12: MovImm R0, 1; Ret
    BvmProgram fact_prog;
    fact_prog.instructions = {
        {VmOpcode::MovImm, 3, 0, 0, 1},     // 0: R3 = 1
        {VmOpcode::MovImm, 5, 0, 0, 8},     // 1: R5 = 8
        {VmOpcode::Call, 0, 0, 0, 4},       // 2: call fact
        {VmOpcode::Halt, 0, 0, 0, 0},       // 3: halt
        {VmOpcode::Cmp, 0, 1, 3, 0},        // 4: cmp R1, 1
        {VmOpcode::Jle, 0, 0, 0, 13},       // 5: if R1 <= 1 goto 13
        {VmOpcode::Sub, 4, 4, 5, 0},        // 6: R4 -= 8
        {VmOpcode::Store, 4, 1, 64, 0},     // 7: [R4] = R1
        {VmOpcode::Sub, 1, 1, 3, 0},        // 8: R1 -= 1
        {VmOpcode::Call, 0, 0, 0, 4},       // 9: call fact(n-1)
        {VmOpcode::Load, 2, 4, 64, 0},      // 10: R2 = [R4]
        {VmOpcode::Add, 4, 4, 5, 0},        // 11: R4 += 8
        {VmOpcode::Mul, 0, 0, 2, 0},        // 12: R0 *= R2; Ret next
        {VmOpcode::Ret, 0, 0, 0, 0},        // 13 (wait: base case needs R0=1 when jumping from 5!)
    };
    // Fix PC 5 target to 14, add Ret at 13, base case at 14:
    fact_prog.instructions[5].imm = 14;
    fact_prog.instructions.push_back({VmOpcode::MovImm, 0, 0, 0, 1}); // 14
    fact_prog.instructions.push_back({VmOpcode::Ret, 0, 0, 0, 0});    // 15

    VmExecOptions fopts;
    fopts.initial_regs[1] = 6; // 6! = 720
    auto fres = VmInterpreter::execute(fact_prog, fopts);
    ASSERT_TRUE(fres.has_value()) << fres.error().to_string();
    EXPECT_EQ(fres.value().return_value, 720ULL);

    // Recursion depth limit enforcement
    VmExecOptions shallow_opts = fopts;
    shallow_opts.max_call_depth = 3;
    EXPECT_FALSE(VmInterpreter::execute(fact_prog, shallow_opts).has_value());
}

TEST(ProtectionV06Test, OptimizationLevelsO0O1O2O3Equivalence) {
    // Compare lifting + VM execution of f(a, b) = (a * 3) + b compiled at:
    // -O0 (frame pointer prologue, stack spills [rbp-8], [rbp-16], memory RMW add [rbp-24], eax, leave, ret)
    const std::vector<std::uint8_t> code_o0 = {
        0x55,                               // push rbp
        0x48, 0x89, 0xE5,                   // mov rbp, rsp
        0x48, 0x89, 0x7D, 0xF8,             // mov [rbp-8], rdi
        0x48, 0x89, 0x75, 0xF0,             // mov [rbp-16], rsi
        0x48, 0x8B, 0x45, 0xF8,             // mov rax, [rbp-8]
        0x48, 0x6B, 0xC0, 0x03,             // imul rax, rax, 3
        0x48, 0x89, 0x45, 0xE8,             // mov [rbp-24], rax
        0x48, 0x8B, 0x55, 0xF0,             // mov rdx, [rbp-16]
        0x48, 0x01, 0x55, 0xE8,             // add [rbp-24], rdx  (Memory-destination RMW!)
        0x48, 0x8B, 0x45, 0xE8,             // mov rax, [rbp-24]
        0x5D,                               // pop rbp
        0xC3                                // ret
    };
    // -O1 (register-based mov + imul + add)
    const std::vector<std::uint8_t> code_o1 = {
        0x48, 0x6B, 0xC7, 0x03,             // imul rax, rdi, 3
        0x48, 0x01, 0xF0,                   // add rax, rsi
        0xC3                                // ret
    };
    // -O2 (lea [rdi + rdi*2] + add)
    const std::vector<std::uint8_t> code_o2 = {
        0x48, 0x8D, 0x04, 0x7F,             // lea rax, [rdi + rdi*2]
        0x48, 0x01, 0xF0,                   // add rax, rsi
        0xC3                                // ret
    };
    // -O3 (endbr64 + lea [rdi + rdi*2] + lea [rax + rsi*1])
    const std::vector<std::uint8_t> code_o3 = {
        0xF3, 0x0F, 0x1E, 0xFA,             // endbr64
        0x48, 0x8D, 0x04, 0x7F,             // lea rax, [rdi + rdi*2]
        0x48, 0x8D, 0x04, 0x30,             // lea rax, [rax + rsi*1]
        0xC3                                // ret
    };

    bytemorph::arch::x86_64::X86_64Disassembler disasm;
    bytemorph::arch::x86_64::X86_64Lifter lifter;

    for (const auto& bytes : {code_o0, code_o1, code_o2, code_o3}) {
        auto d = disasm.disassemble(bytes, 0x401000);
        ASSERT_TRUE(d.has_value());
        FunctionInfo fi;
        fi.name = "opt_fn";
        fi.entry_va = 0x401000;
        BasicBlock bb;
        bb.start_va = 0x401000;
        bb.instructions = d.value();
        fi.blocks.push_back(bb);

        IrFunction ir_fn = lifter.lift_function(fi);
        auto bvm = IrToVmTranslator::translate(ir_fn, 0x6004ULL);
        ASSERT_TRUE(bvm.has_value()) << bvm.error().to_string();

        VmExecOptions vo;
        vo.initial_regs[7] = 42; // rdi
        vo.initial_regs[6] = 19; // rsi
        auto vout = VmInterpreter::execute(bvm.value(), vo);
        ASSERT_TRUE(vout.has_value()) << vout.error().to_string();
        EXPECT_EQ(vout.value().return_value, 145ULL); // 42*3 + 19
    }
}

TEST(ProtectionV06Test, CrossProtectsElf64Arm64AndChecksCompatibility) {
    const auto tmp_dir = std::filesystem::temp_directory_path();
    const auto elf_in = tmp_dir / "bm_v06_elf64_arm64.bin";
    const auto elf_out = tmp_dir / "bm_v06_elf64_arm64_prot.bin";

    // ARM64 function with stack frame (stp/ldp + add lsl #1 + sub + ret)
    const std::vector<std::uint8_t> arm64_fn = {
        0xFD, 0x7B, 0xBE, 0xA9, // stp x29, x30, [sp, #-32]!
        0xFD, 0x03, 0x00, 0x91, // mov x29, sp
        0xE0, 0x0F, 0x00, 0xF9, // str x0, [sp, #24]
        0xE1, 0x0B, 0x00, 0xF9, // str x1, [sp, #16]
        0xE8, 0x0F, 0x40, 0xF9, // ldr x8, [sp, #24]
        0xE9, 0x0B, 0x40, 0xF9, // ldr x9, [sp, #16]
        0x08, 0x05, 0x08, 0x8B, // add x8, x8, x8, lsl #1 (x8 = a * 3)
        0x00, 0x01, 0x09, 0x8B, // add x0, x8, x9
        0xFD, 0x7B, 0xC2, 0xA8, // ldp x29, x30, [sp], #32
        0xC0, 0x03, 0x5F, 0xD6  // ret
    };

    auto elf = bytemorph::tests::build_minimal_elf64_arm64(arm64_fn);
    {
        std::ofstream ofs(elf_in, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(elf.data()), static_cast<std::streamsize>(elf.size()));
    }

    // 1. Check compatibility engine on ELF64 ARM64
    auto comp = ProtectionEngine::check_compatibility(elf_in);
    ASSERT_TRUE(comp.has_value()) << comp.error().to_string();
    EXPECT_TRUE(comp.value().binary_supported);
    EXPECT_EQ(comp.value().format, bytemorph::core::binary::BinaryFormat::ELF64);
    EXPECT_EQ(comp.value().architecture, bytemorph::core::binary::Architecture::ARM64);

    // 2. Cross-protect ELF64 ARM64 binary and verify AEAD + BLAKE2b integrity
    ProtectOptions opts;
    opts.target_function_rva = 0x1000;
    opts.profile = ProtectionProfile::Balanced;
    opts.seed = 0xA64E1F06ULL;
    auto rep = ProtectionEngine::protect(elf_in, elf_out, opts);
    ASSERT_TRUE(rep.has_value()) << rep.error().to_string();
    EXPECT_EQ(rep.value().format, bytemorph::core::binary::BinaryFormat::ELF64);
    EXPECT_EQ(rep.value().architecture, bytemorph::core::binary::Architecture::ARM64);

    auto ver = ProtectionEngine::verify(elf_out);
    ASSERT_TRUE(ver.has_value()) << ver.error().to_string();
    EXPECT_TRUE(ver.value().valid);
    EXPECT_TRUE(ver.value().aead_authenticated);
    EXPECT_TRUE(ver.value().text_integrity_ok);
    EXPECT_TRUE(ver.value().runtime_integrity_ok);

    std::error_code ec;
    std::filesystem::remove(elf_in, ec);
    std::filesystem::remove(elf_out, ec);
}

#if defined(__linux__) && defined(__aarch64__)
TEST(ProtectionV06Test, ProtectsAndExecutesRealLinuxElf64Arm64LabBinary) {
    const std::filesystem::path lab_exe(BYTEMORPH_LAB_PE_TARGET_PATH);
    ASSERT_TRUE(std::filesystem::exists(lab_exe));

    const auto tmp_dir = std::filesystem::temp_directory_path();
    const auto prot_exe = tmp_dir / "lab_elf64_arm64_protected";

    ProtectOptions opts;
    opts.profile = ProtectionProfile::Balanced;
    opts.seed = 0xE1FA6406ULL;
    opts.target_function_name = "bm_target_compute";

    auto rep = ProtectionEngine::protect(lab_exe, prot_exe, opts);
    ASSERT_TRUE(rep.has_value()) << rep.error().to_string();
    auto ver = ProtectionEngine::verify(prot_exe);
    ASSERT_TRUE(ver.has_value() && ver.value().valid);

    EXPECT_EQ(run_posix_and_capture(lab_exe, "42 19 --v06"), run_posix_and_capture(prot_exe, "42 19 --v06"));
    EXPECT_EQ(run_posix_and_capture(lab_exe, "100 37 --v06"), run_posix_and_capture(prot_exe, "100 37 --v06"));

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

TEST(ProtectionV07Test, SharedRuntimeMultiFunctionScaling2_5_10_20) {
    BvmProgram prog;
    prog.instructions = {
        {VmOpcode::MovImm, 1, 0, 0, 10},
        {VmOpcode::MovImm, 2, 0, 0, 32},
        {VmOpcode::Add, 0, 1, 2, 0},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };

    std::size_t prev_x64_size = 0;
    std::size_t prev_a64_size = 0;
    for (const std::size_t count : {2u, 5u, 10u, 20u}) {
        std::vector<BvmProgram> progs(count, prog);
        detail::SharedRuntimeLayout x64_layout;
        detail::SharedRuntimeLayout a64_layout;
        auto x64_rt = detail::emit_shared_pic_x64_vm_runtime(progs, detail::AbiKind::Win64, x64_layout);
        auto a64_rt = detail::emit_shared_pic_arm64_vm_runtime(progs, a64_layout);
        ASSERT_TRUE(x64_rt.has_value()) << x64_rt.error().to_string();
        ASSERT_TRUE(a64_rt.has_value()) << a64_rt.error().to_string();
        EXPECT_EQ(x64_layout.entry_offsets.size(), count);
        EXPECT_EQ(a64_layout.entry_offsets.size(), count);
        EXPECT_GT(x64_layout.core_offset, 0ULL);
        EXPECT_GT(a64_layout.core_offset, 0ULL);

        if (prev_x64_size > 0) {
            EXPECT_GT(x64_rt.value().size(), prev_x64_size);
            EXPECT_GT(a64_rt.value().size(), prev_a64_size);
        }
        prev_x64_size = x64_rt.value().size();
        prev_a64_size = a64_rt.value().size();
    }
    EXPECT_LT(prev_x64_size, 8192u);
    EXPECT_LT(prev_a64_size, 8192u);
}

TEST(ProtectionV07Test, Pe32PlusArm64CrossProtectionAndVerification) {
    const auto tmp_dir = std::filesystem::temp_directory_path();
    const auto pe_in = tmp_dir / "bytemorph_test_pe_arm64_in.exe";
    const auto pe_out = tmp_dir / "bytemorph_test_pe_arm64_out.exe";

    const std::vector<std::uint8_t> arm64_fn = {
        0xFD, 0x7B, 0xBE, 0xA9, // stp x29, x30, [sp, #-32]!
        0xFD, 0x03, 0x00, 0x91, // mov x29, sp
        0xE0, 0x0F, 0x00, 0xF9, // str x0, [sp, #24]
        0xE1, 0x0B, 0x00, 0xF9, // str x1, [sp, #16]
        0xE8, 0x0F, 0x40, 0xF9, // ldr x8, [sp, #24]
        0xE9, 0x0B, 0x40, 0xF9, // ldr x9, [sp, #16]
        0x08, 0x05, 0x08, 0x8B, // add x8, x8, x8, lsl #1
        0x00, 0x01, 0x09, 0x8B, // add x0, x8, x9
        0xFD, 0x7B, 0xC2, 0xA8, // ldp x29, x30, [sp], #32
        0xC0, 0x03, 0x5F, 0xD6  // ret
    };

    auto pe = bytemorph::tests::build_minimal_pe64_x86_64(arm64_fn);
    pe[0x84] = 0x64;
    pe[0x85] = 0xAA;

    {
        std::ofstream ofs(pe_in, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(pe.data()), static_cast<std::streamsize>(pe.size()));
    }

    auto comp = ProtectionEngine::check_compatibility(pe_in);
    ASSERT_TRUE(comp.has_value()) << comp.error().to_string();
    EXPECT_TRUE(comp.value().binary_supported);
    EXPECT_EQ(comp.value().format, bytemorph::core::binary::BinaryFormat::PE32Plus);
    EXPECT_EQ(comp.value().architecture, bytemorph::core::binary::Architecture::ARM64);

    ProtectOptions opts;
    opts.target_function_rva = 0x1000;
    opts.profile = ProtectionProfile::Balanced;
    opts.seed = 0xA64FE07ULL;

    auto rep = ProtectionEngine::protect(pe_in, pe_out, opts);
    ASSERT_TRUE(rep.has_value()) << rep.error().to_string();
    EXPECT_EQ(rep.value().format, bytemorph::core::binary::BinaryFormat::PE32Plus);
    EXPECT_EQ(rep.value().architecture, bytemorph::core::binary::Architecture::ARM64);
    EXPECT_TRUE(rep.value().shared_runtime_used);
    EXPECT_EQ(rep.value().protected_functions.size(), 1u);

    auto ver = ProtectionEngine::verify(pe_out);
    ASSERT_TRUE(ver.has_value()) << ver.error().to_string();
    EXPECT_TRUE(ver.value().valid);
    EXPECT_TRUE(ver.value().aead_authenticated);
    EXPECT_TRUE(ver.value().text_integrity_ok);
    EXPECT_TRUE(ver.value().runtime_integrity_ok);

    std::error_code ec;
    std::filesystem::remove(pe_in, ec);
    std::filesystem::remove(pe_out, ec);
}

TEST(ProtectionV07Test, MachOUniversalMultiSliceProtectionAndVerification) {
    const auto tmp_dir = std::filesystem::temp_directory_path();
    const auto uni_in = tmp_dir / "bytemorph_test_uni_in.macho";
    const auto uni_out = tmp_dir / "bytemorph_test_uni_out.macho";

    const std::vector<std::uint8_t> x64_fn = {
        0x55,                         // push rbp
        0x48, 0x89, 0xE5,             // mov rbp, rsp
        0x48, 0x8D, 0x04, 0x37,       // lea rax, [rdi + rsi]
        0x5D,                         // pop rbp
        0xC3                          // ret
    };
    const std::vector<std::uint8_t> arm64_fn = {
        0xFD, 0x7B, 0xBE, 0xA9,       // stp x29, x30, [sp, #-32]!
        0xFD, 0x03, 0x00, 0x91,       // mov x29, sp
        0x00, 0x00, 0x01, 0x8B,       // add x0, x0, x1
        0xFD, 0x7B, 0xC2, 0xA8,       // ldp x29, x30, [sp], #32
        0xC0, 0x03, 0x5F, 0xD6        // ret
    };

    auto x64_slice = bytemorph::tests::build_minimal_macho64(false, x64_fn);
    auto arm64_slice = bytemorph::tests::build_minimal_macho64(true, arm64_fn);
    auto fat = bytemorph::tests::build_minimal_macho_fat(x64_slice, arm64_slice);

    {
        std::ofstream ofs(uni_in, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(fat.data()), static_cast<std::streamsize>(fat.size()));
    }

    ProtectOptions opts;
    opts.target_function_rva = 0x1000;
    opts.profile = ProtectionProfile::Balanced;
    opts.seed = 0xFA700007ULL;
    opts.allow_strip_signature = true;

    auto rep = ProtectionEngine::protect(uni_in, uni_out, opts);
    ASSERT_TRUE(rep.has_value()) << rep.error().to_string();
    EXPECT_EQ(rep.value().format, bytemorph::core::binary::BinaryFormat::MachO64);
    EXPECT_TRUE(rep.value().shared_runtime_used);
    EXPECT_EQ(rep.value().protected_functions.size(), 2u);

    auto ver = ProtectionEngine::verify(uni_out);
    ASSERT_TRUE(ver.has_value()) << ver.error().to_string();
    EXPECT_TRUE(ver.value().valid);
    EXPECT_TRUE(ver.value().aead_authenticated);
    EXPECT_TRUE(ver.value().text_integrity_ok);
    EXPECT_TRUE(ver.value().runtime_integrity_ok);
    EXPECT_EQ(ver.value().metadata.functions.size(), 2u);

    std::error_code ec;
    std::filesystem::remove(uni_in, ec);
    std::filesystem::remove(uni_out, ec);
}

TEST(ProtectionV07Test, TransactionalRollbackRejectsMissingAndOverlappingTargets) {
    const std::filesystem::path lab_exe(BYTEMORPH_LAB_PE_TARGET_PATH);
    ASSERT_TRUE(std::filesystem::exists(lab_exe));

    const auto tmp_dir = std::filesystem::temp_directory_path();
    const auto bad_out = tmp_dir / "bytemorph_v07_rollback_should_not_exist";
    std::error_code ec;
    std::filesystem::remove(bad_out, ec);

    ProtectOptions opts;
    opts.target_function_names = {"bm_target_compute", "nonexistent_symbol_v07"};
    opts.rollback_on_failure = true;
    auto rep1 = ProtectionEngine::protect(lab_exe, bad_out, opts);
    EXPECT_FALSE(rep1.has_value());
    EXPECT_FALSE(std::filesystem::exists(bad_out));

    ProtectOptions opts2;
    opts2.target_function_rvas = {0x1000, 0x1002};
    auto rep2 = ProtectionEngine::protect(lab_exe, bad_out, opts2);
    EXPECT_FALSE(rep2.has_value());
    EXPECT_FALSE(std::filesystem::exists(bad_out));
}

#if defined(_WIN32)
TEST(ProtectionV07Test, ProtectsAndExecutesMultiFunctionRealWindowsPeX64) {
    const std::filesystem::path lab_exe(BYTEMORPH_LAB_PE_TARGET_PATH);
    ASSERT_TRUE(std::filesystem::exists(lab_exe));

    const auto tmp_dir = std::filesystem::temp_directory_path();
    const auto prot_exe = tmp_dir / "lab_pe_v07_multi_protected.exe";

    ProtectOptions opts;
    opts.profile = ProtectionProfile::Balanced;
    opts.seed = 0x571D0707ULL;
    opts.allow_external_calls = true;
    opts.target_function_names = {
        "bm_target_compute",
        "bm_target_multi_args",
        "bm_target_helper",
        "bm_target_caller"
    };

    auto rep = ProtectionEngine::protect(lab_exe, prot_exe, opts);
    ASSERT_TRUE(rep.has_value()) << rep.error().to_string();
    EXPECT_TRUE(rep.value().shared_runtime_used);
    EXPECT_EQ(rep.value().protected_functions.size(), 4u);

    auto ver = ProtectionEngine::verify(prot_exe);
    ASSERT_TRUE(ver.has_value() && ver.value().valid);
    EXPECT_EQ(ver.value().metadata.functions.size(), 4u);

    auto run_win = [](const std::filesystem::path& exe, const std::string& args) -> std::string {
        const std::string cmd = "\"" + exe.string() + "\" " + args;
        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) return {};
        std::string out;
        char buf[256];
        while (std::fgets(buf, sizeof(buf), pipe) != nullptr) out += buf;
        _pclose(pipe);
        return out;
    };

    EXPECT_EQ(run_win(lab_exe, "42 19 --v07"), run_win(prot_exe, "42 19 --v07"));
    EXPECT_EQ(run_win(lab_exe, "100 37 --v07"), run_win(prot_exe, "100 37 --v07"));

    std::error_code ec;
    std::filesystem::remove(prot_exe, ec);
}
#endif

#if !defined(_WIN32)
TEST(ProtectionV07Test, ProtectsAndExecutesMultiFunctionRealPosixBinary) {
    const std::filesystem::path lab_exe(BYTEMORPH_LAB_PE_TARGET_PATH);
    ASSERT_TRUE(std::filesystem::exists(lab_exe));

    const auto tmp_dir = std::filesystem::temp_directory_path();
    const auto prot_exe = tmp_dir / "lab_posix_v07_multi_protected";

    ProtectOptions opts;
    opts.profile = ProtectionProfile::Balanced;
    opts.seed = 0x50510707ULL;
    opts.allow_strip_signature = true;
#if defined(__APPLE__)
    opts.allow_external_calls = true;
    opts.target_function_names = {
        "bm_target_compute",
        "bm_target_multi_args",
        "bm_target_helper",
        "bm_target_caller"
    };
#else
    opts.target_function_names = {
        "bm_target_compute",
        "bm_target_multi_args"
    };
#endif

    auto rep = ProtectionEngine::protect(lab_exe, prot_exe, opts);
    ASSERT_TRUE(rep.has_value()) << rep.error().to_string();
    EXPECT_TRUE(rep.value().shared_runtime_used);
    EXPECT_EQ(rep.value().protected_functions.size(), opts.target_function_names.size());

    auto ver = ProtectionEngine::verify(prot_exe);
    ASSERT_TRUE(ver.has_value() && ver.value().valid);
    EXPECT_EQ(ver.value().metadata.functions.size(), opts.target_function_names.size());

    EXPECT_EQ(run_posix_and_capture(lab_exe, "42 19 --v07"), run_posix_and_capture(prot_exe, "42 19 --v07"));
    EXPECT_EQ(run_posix_and_capture(lab_exe, "100 37 --v07"), run_posix_and_capture(prot_exe, "100 37 --v07"));

    std::error_code ec;
    std::filesystem::remove(prot_exe, ec);
}
#endif

// ============================================================================
// ByteMorph v0.8 Tests: Smart Eligibility, Thunk Filter, Lifters & Fuzzing
// ============================================================================

TEST(ProtectionV08Test, RejectsIatPltThunksAndRipRelativeGlobalAccess) {
    const auto tmp_dir = std::filesystem::temp_directory_path();
    const auto pe_thunk = tmp_dir / "bytemorph_v08_iat_thunk.exe";

    // x86-64 IAT thunk: jmp qword ptr [rip + 0x1000] (FF 25 00 10 00 00)
    const std::vector<std::uint8_t> iat_thunk_code = {
        0xFF, 0x25, 0x00, 0x10, 0x00, 0x00
    };
    auto pe = bytemorph::tests::build_minimal_pe64_x86_64(iat_thunk_code);
    {
        std::ofstream ofs(pe_thunk, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(pe.data()), static_cast<std::streamsize>(pe.size()));
    }

    auto comp = ProtectionEngine::check_compatibility(pe_thunk);
    ASSERT_TRUE(comp.has_value()) << comp.error().to_string();
    EXPECT_TRUE(comp.value().eligible_functions.empty());
    ASSERT_FALSE(comp.value().rejected_functions.empty());
    // Rejected either as crt_entrypoint (entry point) or iat_plt_thunk
    const auto& cat = comp.value().rejected_functions.front().category;
    EXPECT_TRUE(cat == "crt_entrypoint" || cat == "iat_plt_thunk");

    // Direct test of detect_thunk via non-entry FunctionInfo
    bytemorph::core::binary::BinaryLoader loader;
    loader.register_parser(std::make_unique<bytemorph::formats::pe::PeParser>());
    auto bin_res = loader.load_file(pe_thunk);
    ASSERT_TRUE(bin_res.has_value());

    FunctionInfo non_ep_thunk;
    non_ep_thunk.name = "sub_iat_stub";
    non_ep_thunk.entry_va = 0x140001000ULL;
    non_ep_thunk.size_bytes = 6;
    non_ep_thunk.from_entry_point = false;
    non_ep_thunk.confidence = AnalysisConfidence::High;
    BasicBlock bb;
    bb.start_va = non_ep_thunk.entry_va;
    bb.end_va = non_ep_thunk.entry_va + 6;
    bb.instructions.push_back(DisassembledInstruction{
        non_ep_thunk.entry_va, iat_thunk_code, "jmp", "qword ptr [rip+0x1000]",
        "jmp qword ptr [rip+0x1000]", ControlFlowKind::UnconditionalJump, std::nullopt
    });
    non_ep_thunk.blocks.push_back(std::move(bb));

    AnalysisResult dummy_an;
    dummy_an.functions.push_back(non_ep_thunk);
    auto elig = detail::evaluate_function_eligibility(
        *bin_res.value(), dummy_an, non_ep_thunk, {}, false, false);
    EXPECT_FALSE(elig.eligible);
    EXPECT_EQ(elig.category, "iat_plt_thunk");

    std::error_code ec;
    std::filesystem::remove(pe_thunk, ec);
}

#if defined(_WIN32)
TEST(ProtectionV08Test, AllEligibleProtectsAndExecutesRealWindowsBinary) {
    const std::filesystem::path lab_exe(BYTEMORPH_LAB_PE_TARGET_PATH);
    ASSERT_TRUE(std::filesystem::exists(lab_exe));

    const auto tmp_dir = std::filesystem::temp_directory_path();
    const auto prot_exe = tmp_dir / "lab_pe_v08_all_eligible.exe";

    ProtectOptions opts;
    opts.profile = ProtectionProfile::Balanced;
    opts.seed = 0xA11E0808ULL;
    opts.protect_all_eligible = true;
    opts.allow_external_calls = true;

    auto rep = ProtectionEngine::protect(lab_exe, prot_exe, opts);
    ASSERT_TRUE(rep.has_value()) << rep.error().to_string();
    EXPECT_TRUE(rep.value().shared_runtime_used);
    EXPECT_GE(rep.value().protected_functions.size(), 4u);
    EXPECT_GT(rep.value().rejected_functions.size(), 0u);

    auto ver = ProtectionEngine::verify(prot_exe);
    ASSERT_TRUE(ver.has_value() && ver.value().valid);

    auto run_win = [](const std::filesystem::path& exe, const std::string& args) -> std::string {
        const std::string cmd = "\"" + exe.string() + "\" " + args;
        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) return {};
        std::string out;
        char buf[256];
        while (std::fgets(buf, sizeof(buf), pipe) != nullptr) out += buf;
        _pclose(pipe);
        return out;
    };

    EXPECT_EQ(run_win(lab_exe, "42 19 --v07"), run_win(prot_exe, "42 19 --v07"));
    EXPECT_EQ(run_win(lab_exe, "100 37 --v07"), run_win(prot_exe, "100 37 --v07"));

    std::error_code ec;
    std::filesystem::remove(prot_exe, ec);
}
#endif

TEST(ProtectionV08Test, DifferentialAndPropertyBasedIrObfuscationAndVmEquivalence) {
    IrFunction fn;
    fn.name = "prop_fn";
    fn.entry_va = 0x1000;
    fn.blocks = {{0, 0x1000, {
        {0x1000, IrOpcode::Add, {IrOperand::reg("r10")}, {IrOperand::reg("rdi"), IrOperand::reg("rsi")}, {}, ""},
        {0x1004, IrOpcode::Sub, {IrOperand::reg("r11")}, {IrOperand::reg("rdi"), IrOperand::reg("rsi")}, {}, ""},
        {0x1008, IrOpcode::Xor, {IrOperand::reg("r12")}, {IrOperand::reg("r10"), IrOperand::reg("r11")}, {}, ""},
        {0x100C, IrOpcode::Mul, {IrOperand::reg("r13")}, {IrOperand::reg("rdi"), IrOperand::immediate(5)}, {}, ""},
        {0x1010, IrOpcode::Add, {IrOperand::reg("rax")}, {IrOperand::reg("r12"), IrOperand::reg("r13")}, {}, ""},
        {0x1014, IrOpcode::Ret, {}, {}, {}, ""}
    }, {}}};

    IrFunction obf_fn = fn;
    ObfuscationConfig cfg;
    cfg.seed = 0xBEEF0808ULL;
    cfg.enable_substitution = true;
    cfg.enable_mba = true;
    auto obf_res = ObfuscationPipeline::obfuscate_function(obf_fn, cfg);
    ASSERT_TRUE(obf_res.has_value());

    auto bvm_res = IrToVmTranslator::translate(obf_fn, 0xBEEF0808ULL);
    ASSERT_TRUE(bvm_res.has_value()) << bvm_res.error().to_string();

    for (std::int64_t i = -25; i < 25; ++i) {
        const std::int64_t a = i * 17 + 3;
        const std::int64_t b = (i % 7) * 11 - 5;
        const std::uint64_t expected = static_cast<std::uint64_t>(((a + b) ^ (a - b)) + (a * 5));

        IrExecOptions ir_in;
        ir_in.initial_regs["rdi"] = static_cast<std::uint64_t>(a);
        ir_in.initial_regs["rsi"] = static_cast<std::uint64_t>(b);
        auto orig_out = IrInterpreter::execute(fn, ir_in);
        auto obf_out = IrInterpreter::execute(obf_fn, ir_in);
        ASSERT_TRUE(orig_out.has_value() && obf_out.has_value());
        EXPECT_EQ(orig_out.value().return_value, expected);
        EXPECT_EQ(obf_out.value().return_value, expected);

        VmExecOptions vm_opts;
        vm_opts.initial_regs[7] = static_cast<std::uint64_t>(a); // rdi -> R7
        vm_opts.initial_regs[6] = static_cast<std::uint64_t>(b); // rsi -> R6
        auto vm_out = VmInterpreter::execute(bvm_res.value(), vm_opts);
        ASSERT_TRUE(vm_out.has_value()) << vm_out.error().to_string();
        EXPECT_EQ(vm_out.value().return_value, expected);
    }
}

TEST(ProtectionV08Test, LiftersExpandNotXchgMvnUxtbMnegAndRejectUnknownWithoutNop) {
    bytemorph::arch::x86_64::X86_64Lifter x64_lifter;
    FunctionInfo x64_fn;
    x64_fn.name = "x64_ext";
    x64_fn.entry_va = 0x1000;
    x64_fn.blocks.push_back(BasicBlock{0x1000, 0x1010, {
        {0x1000, {0x48, 0xF7, 0xD0}, "not", "rax", "not rax", ControlFlowKind::Sequential, std::nullopt},
        {0x1003, {0x48, 0x91}, "xchg", "rax, rcx", "xchg rax, rcx", ControlFlowKind::Sequential, std::nullopt},
        {0x1005, {0x0F, 0xA2}, "cpuid", "", "cpuid", ControlFlowKind::Sequential, std::nullopt},
        {0x1007, {0xC3}, "ret", "", "ret", ControlFlowKind::Return, std::nullopt}
    }, {}});
    auto lifted_x64 = x64_lifter.lift_function(x64_fn);
    ASSERT_EQ(lifted_x64.blocks.size(), 1u);
    const auto& x64_insns = lifted_x64.blocks[0].instructions;
    EXPECT_EQ(x64_insns[0].opcode, IrOpcode::Xor);     // not -> xor -1
    EXPECT_EQ(x64_insns[1].opcode, IrOpcode::Mov);     // xchg step 0
    EXPECT_EQ(x64_insns[4].opcode, IrOpcode::Unknown); // cpuid must NOT become Nop

    bytemorph::arch::aarch64::AArch64Lifter a64_lifter;
    FunctionInfo a64_fn;
    a64_fn.name = "a64_ext";
    a64_fn.entry_va = 0x2000;
    a64_fn.blocks.push_back(BasicBlock{0x2000, 0x2014, {
        {0x2000, {0,0,0,0}, "mvn", "x0, x1", "mvn x0, x1", ControlFlowKind::Sequential, std::nullopt},
        {0x2004, {0,0,0,0}, "uxtb", "w0, w0", "uxtb w0, w0", ControlFlowKind::Sequential, std::nullopt},
        {0x2008, {0,0,0,0}, "mneg", "x0, x1, x2", "mneg x0, x1, x2", ControlFlowKind::Sequential, std::nullopt},
        {0x200C, {0,0,0,0}, "mrs", "x0, nzcv", "mrs x0, nzcv", ControlFlowKind::Sequential, std::nullopt},
        {0x2010, {0,0,0,0}, "ret", "", "ret", ControlFlowKind::Return, std::nullopt}
    }, {}});
    auto lifted_a64 = a64_lifter.lift_function(a64_fn);
    ASSERT_EQ(lifted_a64.blocks.size(), 1u);
    const auto& a64_insns = lifted_a64.blocks[0].instructions;
    EXPECT_EQ(a64_insns[0].opcode, IrOpcode::Xor);     // mvn -> xor -1
    EXPECT_EQ(a64_insns[1].opcode, IrOpcode::And);     // uxtb -> and 0xFF
    EXPECT_EQ(a64_insns[2].opcode, IrOpcode::Mul);     // mneg mul
    EXPECT_EQ(a64_insns[3].opcode, IrOpcode::Sub);     // mneg sub
    EXPECT_EQ(a64_insns[4].opcode, IrOpcode::Unknown); // mrs must NOT become Nop
}

TEST(ProtectionV08Test, BytecodeFuzzAndMemoryBoundsSafety) {
    std::uint64_t rng = 0x88881234ULL;
    auto next_u64 = [&]() -> std::uint64_t {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        return rng;
    };

    for (int iter = 0; iter < 200; ++iter) {
        std::vector<std::uint8_t> raw(static_cast<std::size_t>(next_u64() % 128));
        for (auto& b : raw) b = static_cast<std::uint8_t>(next_u64() & 0xFF);
        auto dec = BvmCodec::decode(raw);
        if (dec.has_value()) {
            VmExecOptions opts;
            opts.max_steps = 256;
            (void)VmInterpreter::execute(dec.value(), opts);
        }

        // Also fuzz direct BvmProgram with out-of-bounds registers/targets/memory
        BvmProgram p;
        p.instructions.push_back({
            static_cast<VmOpcode>(next_u64() % 28),
            static_cast<std::uint8_t>(next_u64() & 0x3F),
            static_cast<std::uint8_t>(next_u64() & 0x3F),
            static_cast<std::uint8_t>(next_u64() & 0xFF),
            static_cast<std::int64_t>(next_u64())
        });
        VmExecOptions opts;
        opts.max_steps = 64;
        (void)VmInterpreter::execute(p, opts);
    }
    SUCCEED();
}

TEST(ProtectionV09Test, X64RipRelativeGlobalLiftingAndPicTranslation) {
    using namespace bytemorph::core::ir;
    using namespace bytemorph::virt;

    bytemorph::core::analysis::FunctionInfo fn;
    fn.name = "rip_global_fn";
    fn.entry_va = 0x140001000ULL;
    bytemorph::core::analysis::BasicBlock bb;
    bb.start_va = 0x140001000ULL;
    bb.end_va = 0x140001020ULL;
    bb.instructions = {
        {0x140001000ULL, {0x48,0x8D,0x05,0x00,0x20,0x00,0x00}, "lea", "rax, [rip + 0x2000]", "lea rax, [rip + 0x2000]", ControlFlowKind::Sequential, std::nullopt},
        {0x140001007ULL, {0x8B,0x0D,0x00,0x30,0x00,0x00}, "mov", "ecx, dword ptr [rip + 0x3000]", "mov ecx, dword ptr [rip + 0x3000]", ControlFlowKind::Sequential, std::nullopt},
        {0x14000100DULL, {0x89,0x05,0x00,0x30,0x00,0x00}, "mov", "dword ptr [rip + 0x3000], eax", "mov dword ptr [rip + 0x3000], eax", ControlFlowKind::Sequential, std::nullopt},
        {0x140001013ULL, {0xC3}, "ret", "", "ret", ControlFlowKind::Return, std::nullopt}
    };
    fn.blocks.push_back(bb);

    auto ir_fn = bytemorph::arch::x86_64::X86_64Lifter().lift_function(fn);
    ASSERT_FALSE(ir_fn.blocks.empty());
    std::size_t lea_count = 0;
    for (const auto& insn : ir_fn.blocks[0].instructions) {
        if (insn.opcode == IrOpcode::LeaGlobal) ++lea_count;
    }
    EXPECT_EQ(lea_count, 3u);

    TranslateOptions topts;
    topts.stub_base_va = 0x140001000ULL;
    auto bvm_res = IrToVmTranslator::translate(ir_fn, topts);
    ASSERT_TRUE(bvm_res.has_value()) << bvm_res.error().to_string();

    bool found_leapic = false;
    for (const auto& vi : bvm_res.value().instructions) {
        if (vi.opcode == VmOpcode::LeaPic) {
            found_leapic = true;
            break;
        }
    }
    EXPECT_TRUE(found_leapic);

    // Verify ASLR relocation of LeaPic via pic_base_va
    BvmProgram pic_only;
    pic_only.instructions = {
        {VmOpcode::LeaPic, 0, 0, 0, 0x2007},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };
    VmExecOptions o1;
    o1.pic_base_va = 0x140001000ULL;
    auto r1 = VmInterpreter::execute(pic_only, o1);
    ASSERT_TRUE(r1.has_value());
    EXPECT_EQ(r1.value().return_value, 0x140003007ULL);

    VmExecOptions o2;
    o2.pic_base_va = 0x7FF600001000ULL;
    auto r2 = VmInterpreter::execute(pic_only, o2);
    ASSERT_TRUE(r2.has_value());
    EXPECT_EQ(r2.value().return_value, 0x7FF600003007ULL);
}

TEST(ProtectionV09Test, Arm64AdrpAddAndAdrpLdrFusion) {
    using namespace bytemorph::core::ir;
    using namespace bytemorph::virt;

    bytemorph::core::analysis::FunctionInfo fn;
    fn.name = "arm64_adrp_fn";
    fn.entry_va = 0x100004000ULL;
    bytemorph::core::analysis::BasicBlock bb;
    bb.start_va = 0x100004000ULL;
    bb.end_va = 0x100004014ULL;
    bb.instructions = {
        {0x100004000ULL, {0,0,0,0}, "adrp", "x0, #0x100008000", "adrp x0, #0x100008000", ControlFlowKind::Sequential, std::nullopt},
        {0x100004004ULL, {0,0,0,0}, "add", "x0, x0, #0x120", "add x0, x0, #0x120", ControlFlowKind::Sequential, std::nullopt},
        {0x100004008ULL, {0,0,0,0}, "adrp", "x1, #0x100009000", "adrp x1, #0x100009000", ControlFlowKind::Sequential, std::nullopt},
        {0x10000400CULL, {0,0,0,0}, "ldr", "x2, [x1, #0x40]", "ldr x2, [x1, #0x40]", ControlFlowKind::Sequential, std::nullopt},
        {0x100004010ULL, {0,0,0,0}, "ret", "", "ret", ControlFlowKind::Return, std::nullopt}
    };
    fn.blocks.push_back(bb);

    auto ir_fn = bytemorph::arch::aarch64::AArch64Lifter().lift_function(fn);
    ASSERT_FALSE(ir_fn.blocks.empty());
    const auto& insns = ir_fn.blocks[0].instructions;
    ASSERT_GE(insns.size(), 4u);
    EXPECT_EQ(insns[0].opcode, IrOpcode::LeaGlobal);
    EXPECT_EQ(static_cast<std::uint64_t>(insns[0].srcs[0].imm), 0x100008120ULL);
    EXPECT_EQ(insns[1].opcode, IrOpcode::LeaGlobal);
    EXPECT_EQ(static_cast<std::uint64_t>(insns[1].srcs[0].imm), 0x100009040ULL);
    EXPECT_EQ(insns[2].opcode, IrOpcode::Load);

    TranslateOptions topts;
    topts.stub_base_va = 0x100004000ULL;
    auto bvm = IrToVmTranslator::translate(ir_fn, topts);
    ASSERT_TRUE(bvm.has_value()) << bvm.error().to_string();
    EXPECT_EQ(bvm.value().instructions[0].opcode, VmOpcode::LeaPic);
    EXPECT_EQ(bvm.value().instructions[0].imm, 0x4120);
}

TEST(ProtectionV09Test, X64CmovccSetccAdcSbbDifferential) {
    using namespace bytemorph::core::ir;
    using namespace bytemorph::virt;

    bytemorph::core::analysis::FunctionInfo fn;
    fn.name = "cmov_adc_fn";
    fn.entry_va = 0x1000;
    bytemorph::core::analysis::BasicBlock bb;
    bb.start_va = 0x1000;
    bb.end_va = 0x1020;
    bb.instructions = {
        {0x1000, {0,0,0}, "mov", "rax, rcx", "mov rax, rcx", ControlFlowKind::Sequential, std::nullopt},
        {0x1003, {0,0,0}, "cmp", "rcx, rdx", "cmp rcx, rdx", ControlFlowKind::Sequential, std::nullopt},
        {0x1006, {0,0,0,0}, "cmovg", "rax, rdx", "cmovg rax, rdx", ControlFlowKind::Sequential, std::nullopt},
        {0x100A, {0,0,0}, "setb", "r8b", "setb r8b", ControlFlowKind::Sequential, std::nullopt},
        {0x100D, {0,0,0}, "adc", "rax, r8", "adc rax, r8", ControlFlowKind::Sequential, std::nullopt},
        {0x1010, {0xC3}, "ret", "", "ret", ControlFlowKind::Return, std::nullopt}
    };
    fn.blocks.push_back(bb);

    auto ir_fn = bytemorph::arch::x86_64::X86_64Lifter().lift_function(fn);
    auto bvm = IrToVmTranslator::translate(ir_fn, TranslateOptions{});
    ASSERT_TRUE(bvm.has_value()) << bvm.error().to_string();

    for (const auto& [a, b] : std::vector<std::pair<std::uint64_t, std::uint64_t>>{
             {10ULL, 20ULL}, {30ULL, 5ULL}, {static_cast<std::uint64_t>(-5LL), 2ULL}}) {
        IrExecOptions ir_opts;
        ir_opts.initial_regs["rcx"] = a;
        ir_opts.initial_regs["rdx"] = b;
        ir_opts.initial_regs["r8"] = 0;
        auto ir_res = IrInterpreter::execute(ir_fn, ir_opts);
        ASSERT_TRUE(ir_res.has_value()) << ir_res.error().to_string();

        VmExecOptions vm_opts;
        vm_opts.initial_regs[1] = a; // rcx
        vm_opts.initial_regs[2] = b; // rdx
        vm_opts.initial_regs[8] = 0; // r8
        auto vm_res = VmInterpreter::execute(bvm.value(), vm_opts);
        ASSERT_TRUE(vm_res.has_value()) << vm_res.error().to_string();

        EXPECT_EQ(vm_res.value().return_value, ir_res.value().return_value);
    }
}

TEST(ProtectionV09Test, Arm64CselVariantsAndCsetDifferential) {
    using namespace bytemorph::core::ir;
    using namespace bytemorph::virt;

    bytemorph::core::analysis::FunctionInfo fn;
    fn.name = "arm64_csel_fn";
    fn.entry_va = 0x2000;
    bytemorph::core::analysis::BasicBlock bb;
    bb.start_va = 0x2000;
    bb.end_va = 0x2020;
    bb.instructions = {
        {0x2000, {0,0,0,0}, "cmp", "x0, x1", "cmp x0, x1", ControlFlowKind::Sequential, std::nullopt},
        {0x2004, {0,0,0,0}, "csel", "x2, x0, x1, lt", "csel x2, x0, x1, lt", ControlFlowKind::Sequential, std::nullopt},
        {0x2008, {0,0,0,0}, "csinc", "x3, x0, x1, eq", "csinc x3, x0, x1, eq", ControlFlowKind::Sequential, std::nullopt},
        {0x200C, {0,0,0,0}, "cset", "x4, hi", "cset x4, hi", ControlFlowKind::Sequential, std::nullopt},
        {0x2010, {0,0,0,0}, "add", "x0, x2, x3", "add x0, x2, x3", ControlFlowKind::Sequential, std::nullopt},
        {0x2014, {0,0,0,0}, "add", "x0, x0, x4", "add x0, x0, x4", ControlFlowKind::Sequential, std::nullopt},
        {0x2018, {0,0,0,0}, "ret", "", "ret", ControlFlowKind::Return, std::nullopt}
    };
    fn.blocks.push_back(bb);

    auto ir_fn = bytemorph::arch::aarch64::AArch64Lifter().lift_function(fn);
    auto bvm = IrToVmTranslator::translate(ir_fn, TranslateOptions{});
    ASSERT_TRUE(bvm.has_value()) << bvm.error().to_string();

    for (const auto& [x0, x1] : std::vector<std::pair<std::uint64_t, std::uint64_t>>{
             {5ULL, 12ULL}, {12ULL, 12ULL}, {25ULL, 7ULL}}) {
        IrExecOptions ir_opts;
        ir_opts.initial_regs["x0"] = x0;
        ir_opts.initial_regs["x1"] = x1;
        auto ir_res = IrInterpreter::execute(ir_fn, ir_opts);
        ASSERT_TRUE(ir_res.has_value()) << ir_res.error().to_string();

        VmExecOptions vm_opts;
        vm_opts.initial_regs[0] = x0;
        vm_opts.initial_regs[1] = x1;
        auto vm_res = VmInterpreter::execute(bvm.value(), vm_opts);
        ASSERT_TRUE(vm_res.has_value()) << vm_res.error().to_string();

        EXPECT_EQ(vm_res.value().return_value, ir_res.value().return_value);
    }
}

TEST(ProtectionV09Test, SignedAndUnsignedFlagsAccuracy) {
    using namespace bytemorph::virt;
    BvmProgram prog;
    prog.instructions = {
        {VmOpcode::Cmp, 0, 1, 2, 0},
        {VmOpcode::SetCc, 0, 0, static_cast<std::uint8_t>(VmCondCode::Lt), 0},
        {VmOpcode::SetCc, 3, 0, static_cast<std::uint8_t>(VmCondCode::Below), 0},
        {VmOpcode::SetCc, 6, 0, static_cast<std::uint8_t>(VmCondCode::Overflow), 0},
        {VmOpcode::Shl, 3, 3, 7, 0},
        {VmOpcode::Or, 0, 0, 3, 0},
        {VmOpcode::Shl, 6, 6, 8, 0},
        {VmOpcode::Or, 0, 0, 6, 0},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };

    VmExecOptions opts;
    // INT64_MIN (0x8000000000000000) vs 1:
    // Signed Lt = 1 (bit0), Unsigned Below = 0 (bit1), Overflow = 1 (bit2) => 5
    opts.initial_regs[1] = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::min());
    opts.initial_regs[2] = 1ULL;
    opts.initial_regs[7] = 1ULL;
    opts.initial_regs[8] = 2ULL;
    auto res = VmInterpreter::execute(prog, opts);
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(res.value().return_value, 5ULL);
}

TEST(ProtectionV09Test, VmMemoryPoolZeroLeakAndConcurrency) {
    using namespace bytemorph::virt;

    BvmProgram writer_prog;
    writer_prog.instructions = {
        {VmOpcode::MovImm, 1, 0, 0, 0xDEADBEEFCAFEULL},
        {VmOpcode::Store, 4, 1, 64, 16},
        {VmOpcode::Load, 0, 4, 64, 16},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };
    BvmProgram reader_prog;
    reader_prog.instructions = {
        {VmOpcode::Load, 0, 4, 64, 16},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };

    // Warm-up pool
    ASSERT_TRUE(VmInterpreter::execute(writer_prog).has_value());
    for (int i = 0; i < 50; ++i) {
        auto wr = VmInterpreter::execute(writer_prog);
        ASSERT_TRUE(wr.has_value());
        EXPECT_EQ(wr.value().return_value, 0xDEADBEEFCAFEULL);
        EXPECT_EQ(wr.value().allocations_count, 0u);

        auto rd = VmInterpreter::execute(reader_prog);
        ASSERT_TRUE(rd.has_value());
        EXPECT_EQ(rd.value().return_value, 0ULL); // Zero state leak!
    }

    // Concurrent multi-threaded execution
    std::vector<std::thread> threads;
    std::atomic<int> failures{0};
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&, t]() {
            for (int iter = 0; iter < 150; ++iter) {
                BvmProgram tp;
                const std::int64_t val = static_cast<std::int64_t>(t * 1000 + iter + 1);
                tp.instructions = {
                    {VmOpcode::MovImm, 1, 0, 0, val},
                    {VmOpcode::Store, 4, 1, 64, 8},
                    {VmOpcode::Load, 0, 4, 64, 8},
                    {VmOpcode::Ret, 0, 0, 0, 0}
                };
                auto r = VmInterpreter::execute(tp);
                if (!r.has_value() || r.value().return_value != static_cast<std::uint64_t>(val)) {
                    failures.fetch_add(1);
                }
            }
        });
    }
    for (auto& th : threads) th.join();
    EXPECT_EQ(failures.load(), 0);
}

TEST(ProtectionV09Test, NativeArm64PicRuntimeV09Emission) {
    using namespace bytemorph::virt;
    BvmProgram prog;
    prog.instructions = {
        {VmOpcode::LeaPic, 2, 0, 0, 0x1200},
        {VmOpcode::Cmp, 0, 0, 1, 0},
        {VmOpcode::SetCc, 3, 0, static_cast<std::uint8_t>(VmCondCode::Above), 0},
        {VmOpcode::SelectCc, 0, 3, static_cast<std::uint8_t>(VmCondCode::Ne), 0},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };
    bytemorph::prot::detail::SharedRuntimeLayout layout;
    auto code = bytemorph::prot::detail::emit_shared_pic_arm64_vm_runtime(
        std::vector<BvmProgram>{prog}, layout);
    ASSERT_TRUE(code.has_value()) << code.error().to_string();
    EXPECT_GT(code.value().size(), 100u);
    EXPECT_EQ(code.value().size() % 4, 0u);
}

#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
TEST(ProtectionV09Test, NativeX64PicRuntimeV09OpcodesAndRealPeExecution) {
    using namespace bytemorph::virt;
    // 1. Direct native JIT test of LeaPic, Cmp (CF/OF), SelectCc, SetCc
    BvmProgram prog;
    prog.instructions = {
        {VmOpcode::LeaPic, 6, 0, 0, 0x400},
        {VmOpcode::Cmp, 0, 1, 2, 0},
        {VmOpcode::SetCc, 3, 0, static_cast<std::uint8_t>(VmCondCode::Below), 0},
        {VmOpcode::MovImm, 0, 0, 0, 100},
        {VmOpcode::SelectCc, 0, 6, static_cast<std::uint8_t>(VmCondCode::Eq), 0},
        {VmOpcode::Add, 0, 0, 3, 0},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };
    bytemorph::prot::detail::SharedRuntimeLayout layout;
    auto code = bytemorph::prot::detail::emit_shared_pic_x64_vm_runtime(
        std::vector<BvmProgram>{prog}, bytemorph::prot::detail::AbiKind::Win64, layout);
    ASSERT_TRUE(code.has_value()) << code.error().to_string();

    void* exec_mem = ::VirtualAlloc(nullptr, code.value().size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(exec_mem, nullptr);
    std::memcpy(exec_mem, code.value().data(), code.value().size());
    using FnType = std::uint64_t(*)(std::uint64_t, std::uint64_t);
    auto fn = reinterpret_cast<FnType>(reinterpret_cast<std::uint8_t*>(exec_mem) + layout.entry_offsets[0]);
    const std::uint64_t entry_addr = reinterpret_cast<std::uint64_t>(exec_mem);
    // Call with (5, 10): Below=1, Eq=0 -> 100 + 1 = 101
    EXPECT_EQ(fn(5, 10), 101ULL);
    // Call with (10, 10): Below=0, Eq=1 -> (entry_addr + 0x400) + 0
    EXPECT_EQ(fn(10, 10), entry_addr + 0x400ULL);
    ::VirtualFree(exec_mem, 0, MEM_RELEASE);

    // 2. Real PE protection + execution with globals, cmov, unsigned cmp
#ifdef BYTEMORPH_LAB_PE_TARGET_PATH
    const std::filesystem::path target_exe(BYTEMORPH_LAB_PE_TARGET_PATH);
    if (std::filesystem::exists(target_exe)) {
        const std::filesystem::path out_exe =
            std::filesystem::temp_directory_path() / "bytemorph_v09_lab_protected.exe";
        std::filesystem::remove(out_exe);

        bytemorph::prot::ProtectOptions opts;
        opts.profile = bytemorph::prot::ProtectionProfile::Balanced;
        opts.seed = 0x571D0909ULL;
        opts.target_function_names = {
            "bm_target_compute",
            "bm_target_global_rw",
            "bm_target_cmov_select",
            "bm_target_unsigned_cmp"
        };
        auto prot_res = bytemorph::prot::ProtectionEngine::protect(target_exe, out_exe, opts);
        ASSERT_TRUE(prot_res.has_value()) << prot_res.error().to_string();

        auto run_exe = [](const std::string& cmd) -> std::string {
            FILE* pipe = _popen(cmd.c_str(), "r");
            if (!pipe) return "";
            char buf[256];
            std::string out;
            while (std::fgets(buf, sizeof(buf), pipe)) out += buf;
            _pclose(pipe);
            return out;
        };
        const std::string orig_out = run_exe("\"" + target_exe.string() + "\" 42 19 --v09");
        const std::string prot_out = run_exe("\"" + out_exe.string() + "\" 42 19 --v09");
        EXPECT_FALSE(orig_out.empty());
        EXPECT_EQ(prot_out, orig_out);
        std::filesystem::remove(out_exe);
    }
#endif
}
#endif

TEST(ProtectionV09Test, V09OpcodeCodecRoundtripAndValidation) {
    using namespace bytemorph::virt;
    BvmProgram prog;
    prog.build_seed = 0x9999ULL;
    prog.instructions = {
        {VmOpcode::LeaPic, 2, 0, 0, -0x1234},
        {VmOpcode::SetCc, 3, 0, static_cast<std::uint8_t>(VmCondCode::AboveEq), 0},
        {VmOpcode::SelectCc, 0, 2, static_cast<std::uint8_t>(VmCondCode::Overflow), 0},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };
    auto enc = BvmCodec::encode(prog);
    ASSERT_TRUE(enc.has_value());
    auto dec = BvmCodec::decode(enc.value());
    ASSERT_TRUE(dec.has_value());
    ASSERT_EQ(dec.value().instructions.size(), 4u);
    EXPECT_EQ(dec.value().instructions[0].opcode, VmOpcode::LeaPic);
    EXPECT_EQ(dec.value().instructions[0].imm, -0x1234);
    EXPECT_EQ(dec.value().instructions[1].opcode, VmOpcode::SetCc);
    EXPECT_EQ(dec.value().instructions[2].opcode, VmOpcode::SelectCc);

    BvmProgram invalid_cc;
    invalid_cc.instructions = {
        {VmOpcode::SetCc, 0, 0, 99, 0},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };
    EXPECT_FALSE(VmInterpreter::execute(invalid_cc).has_value());
}

#if defined(__has_feature)
#if __has_feature(address_sanitizer) || __has_feature(undefined_behavior_sanitizer)
#define BYTEMORPH_HAS_SANITIZER 1
#endif
#elif defined(__SANITIZE_ADDRESS__)
#define BYTEMORPH_HAS_SANITIZER 1
#endif

TEST(ProtectionV09Test, SmartEligibility3AcceptsGlobalsInLabPe) {
#if defined(BYTEMORPH_LAB_PE_TARGET_PATH) && !defined(BYTEMORPH_HAS_SANITIZER)
    const std::filesystem::path target_exe(BYTEMORPH_LAB_PE_TARGET_PATH);
    if (std::filesystem::exists(target_exe)) {
        auto compat = bytemorph::prot::ProtectionEngine::check_compatibility(target_exe, false);
        ASSERT_TRUE(compat.has_value()) << compat.error().to_string();
        bool found_global_rw = false;
        bool found_cmov = false;
        bool found_ucmp = false;
        for (const auto& f : compat.value().eligible_functions) {
            if (f.name.find("bm_target_global_rw") != std::string::npos) found_global_rw = true;
            if (f.name.find("bm_target_cmov_select") != std::string::npos) found_cmov = true;
            if (f.name.find("bm_target_unsigned_cmp") != std::string::npos) found_ucmp = true;
        }
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
        EXPECT_TRUE(found_global_rw);
#else
        (void)found_global_rw;
#endif
        EXPECT_TRUE(found_cmov);
        EXPECT_TRUE(found_ucmp);
    }
#endif
}

TEST(ProtectionV09Test, MultiFunctionProtectionWithGlobalsAndAeadVerify) {
#if defined(BYTEMORPH_LAB_PE_TARGET_PATH) && !defined(BYTEMORPH_HAS_SANITIZER)
    const std::filesystem::path target_exe(BYTEMORPH_LAB_PE_TARGET_PATH);
    if (std::filesystem::exists(target_exe)) {
        const std::filesystem::path out_exe =
            std::filesystem::temp_directory_path() / "bytemorph_v09_verify_protected.exe";
        std::filesystem::remove(out_exe);

        bytemorph::prot::ProtectOptions opts;
        opts.profile = bytemorph::prot::ProtectionProfile::Balanced;
        opts.seed = 0x90909090ULL;
        opts.allow_strip_signature = true;
        opts.target_function_names = {
            "bm_target_global_rw",
            "bm_target_cmov_select",
            "bm_target_unsigned_cmp"
        };
        auto prot = bytemorph::prot::ProtectionEngine::protect(target_exe, out_exe, opts);
        ASSERT_TRUE(prot.has_value()) << prot.error().to_string();
        EXPECT_EQ(prot.value().protected_functions.size(), 3u);

        auto ver = bytemorph::prot::ProtectionEngine::verify(out_exe);
        ASSERT_TRUE(ver.has_value() && ver.value().valid);
        EXPECT_EQ(ver.value().metadata.functions.size(), 3u);
        std::filesystem::remove(out_exe);
    }
#endif
}

TEST(ProtectionV010Test, RuntimeAeadEncryptedBytecodeX64AndTamperDetection) {
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
    using namespace bytemorph::virt;
    BvmProgram prog;
    prog.instructions = {
        {VmOpcode::Add, 0, 1, 2, 0},
        {VmOpcode::Mul, 0, 0, 1, 0},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };
    bytemorph::prot::detail::SharedRuntimeLayout layout;
    bytemorph::prot::detail::SharedRuntimeOptions rt_opts;
    rt_opts.encrypt_bytecode = true;
    rt_opts.seed = 0xA1B2C3D4E5F60708ULL;
    auto code = bytemorph::prot::detail::emit_shared_pic_x64_vm_runtime(
        std::vector<BvmProgram>{prog}, bytemorph::prot::detail::AbiKind::Win64, layout, rt_opts);
    ASSERT_TRUE(code.has_value()) << code.error().to_string();

    void* exec_mem = ::VirtualAlloc(nullptr, code.value().size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(exec_mem, nullptr);
    std::memcpy(exec_mem, code.value().data(), code.value().size());
    using FnType = std::uint64_t(*)(std::uint64_t, std::uint64_t);
    auto fn = reinterpret_cast<FnType>(reinterpret_cast<std::uint8_t*>(exec_mem) + layout.entry_offsets[0]);
    // (42 + 19) * 42 = 2562
    EXPECT_EQ(fn(42, 19), 2562ULL);

    // Flip 1 byte at the very end of the sealed bytecode ciphertext to simulate tampering
    auto* raw_bytes = reinterpret_cast<std::uint8_t*>(exec_mem);
    raw_bytes[code.value().size() - 1] ^= 0xFF;
    EXPECT_EQ(fn(42, 19), 0xDEADAEADDEADAEADULL);
    ::VirtualFree(exec_mem, 0, MEM_RELEASE);
#else
    SUCCEED();
#endif
}

TEST(ProtectionV010Test, RuntimeAeadEncryptedArm64EmissionAndMetadataV2) {
    using namespace bytemorph::virt;
    BvmProgram prog;
    prog.instructions = {
        {VmOpcode::Add, 0, 0, 1, 0},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };
    bytemorph::prot::detail::SharedRuntimeLayout layout;
    bytemorph::prot::detail::SharedRuntimeOptions rt_opts;
    rt_opts.encrypt_bytecode = true;
    rt_opts.seed = 0x1020304050607080ULL;
    auto code = bytemorph::prot::detail::emit_shared_pic_arm64_vm_runtime(
        std::vector<BvmProgram>{prog}, layout, rt_opts);
    ASSERT_TRUE(code.has_value()) << code.error().to_string();
    EXPECT_GT(code.value().size(), 400u);

    bytemorph::prot::ProtectionMetadata meta;
    meta.profile = bytemorph::prot::ProtectionProfile::Maximum;
    meta.seed = rt_opts.seed;
    meta.bytecode_encrypted = true;
    meta.encrypted_functions.push_back({0, bytemorph::prot::CryptoAead::generate_nonce(rt_opts.seed, 1), {}, 28, {}});
    auto ser = bytemorph::prot::detail::serialize_metadata(meta);
    auto des = bytemorph::prot::detail::deserialize_metadata(ser);
    ASSERT_TRUE(des.has_value()) << des.error().to_string();
    EXPECT_TRUE(des.value().bytecode_encrypted);
    ASSERT_EQ(des.value().encrypted_functions.size(), 1u);
    EXPECT_EQ(des.value().encrypted_functions[0].plaintext_size, 28u);
}

TEST(ProtectionV010Test, ProtectMaximumProfileWithEncryptedBytecodeRealPe) {
#if defined(_WIN32) && defined(BYTEMORPH_LAB_PE_TARGET_PATH) && !defined(BYTEMORPH_HAS_SANITIZER)
    const std::filesystem::path target_exe(BYTEMORPH_LAB_PE_TARGET_PATH);
    if (std::filesystem::exists(target_exe)) {
        const std::filesystem::path out_exe =
            std::filesystem::temp_directory_path() / "bytemorph_v010_enc_protected.exe";
        std::filesystem::remove(out_exe);

        bytemorph::prot::ProtectOptions opts;
        opts.profile = bytemorph::prot::ProtectionProfile::Maximum;
        opts.encrypt_bytecode = true;
        opts.seed = 0x1010202030304040ULL;
        opts.target_function_names = {"bm_target_compute", "bm_target_cmov_select", "bm_target_unsigned_cmp"};
        auto prot = bytemorph::prot::ProtectionEngine::protect(target_exe, out_exe, opts);
        ASSERT_TRUE(prot.has_value()) << prot.error().to_string();

        auto ver = bytemorph::prot::ProtectionEngine::verify(out_exe);
        ASSERT_TRUE(ver.has_value() && ver.value().valid);
        EXPECT_TRUE(ver.value().metadata.bytecode_encrypted);
        EXPECT_EQ(ver.value().metadata.encrypted_functions.size(), 3u);

        auto run_exe = [](const std::string& cmd) -> std::string {
            FILE* pipe = _popen(cmd.c_str(), "r");
            if (!pipe) return "";
            char buf[256];
            std::string out;
            while (std::fgets(buf, sizeof(buf), pipe)) out += buf;
            _pclose(pipe);
            return out;
        };
        EXPECT_EQ(run_exe("\"" + out_exe.string() + "\" 42 19 --v09"),
                  run_exe("\"" + target_exe.string() + "\" 42 19 --v09"));
        std::filesystem::remove(out_exe);
    }
#else
    SUCCEED();
#endif
}

TEST(ProtectionV010Test, SimdX86_64LiftingTranslationAndDifferential) {
    using namespace bytemorph::core::ir;
    using namespace bytemorph::virt;

    bytemorph::core::analysis::FunctionInfo fn;
    fn.name = "x64_simd_fp";
    fn.entry_va = 0x1000;
    bytemorph::core::analysis::BasicBlock bb;
    bb.start_va = 0x1000;
    bb.end_va = 0x1020;
    bb.instructions = {
        {0x1000, {0,0,0}, "movsd", "xmm2, xmm0", "movsd xmm2, xmm0", ControlFlowKind::Sequential, std::nullopt},
        {0x1004, {0,0,0}, "addsd", "xmm2, xmm1", "addsd xmm2, xmm1", ControlFlowKind::Sequential, std::nullopt},
        {0x1008, {0,0,0}, "mulsd", "xmm2, xmm0", "mulsd xmm2, xmm0", ControlFlowKind::Sequential, std::nullopt},
        {0x100C, {0,0,0}, "movsd", "xmm0, xmm2", "movsd xmm0, xmm2", ControlFlowKind::Sequential, std::nullopt},
        {0x1010, {0xC3}, "ret", "", "ret", ControlFlowKind::Return, std::nullopt}
    };
    fn.blocks.push_back(bb);

    auto ir_fn = bytemorph::arch::x86_64::X86_64Lifter().lift_function(fn);
    auto bvm = IrToVmTranslator::translate(ir_fn, TranslateOptions{});
    ASSERT_TRUE(bvm.has_value()) << bvm.error().to_string();

    double a = 3.5, b = 2.25;
    std::uint64_t ua = 0, ub = 0;
    std::memcpy(&ua, &a, 8);
    std::memcpy(&ub, &b, 8);

    IrExecOptions ir_opts;
    ir_opts.initial_vregs[0][0] = ua;
    ir_opts.initial_vregs[1][0] = ub;
    auto ir_res = IrInterpreter::execute(ir_fn, ir_opts);
    ASSERT_TRUE(ir_res.has_value());

    VmExecOptions vm_opts;
    vm_opts.initial_vregs[0][0] = ua;
    vm_opts.initial_vregs[1][0] = ub;
    auto vm_res = VmInterpreter::execute(bvm.value(), vm_opts);
    ASSERT_TRUE(vm_res.has_value());

    double out_ir = 0.0, out_vm = 0.0;
    std::memcpy(&out_ir, &ir_res.value().vregs[0][0], 8);
    std::memcpy(&out_vm, &vm_res.value().vregs[0][0], 8);
    EXPECT_DOUBLE_EQ(out_ir, (3.5 + 2.25) * 3.5);
    EXPECT_DOUBLE_EQ(out_vm, out_ir);
}

TEST(ProtectionV010Test, Arm64FloatingPointDifferential) {
    using namespace bytemorph::core::ir;
    using namespace bytemorph::virt;

    bytemorph::core::analysis::FunctionInfo fn;
    fn.name = "a64_fp";
    fn.entry_va = 0x2000;
    bytemorph::core::analysis::BasicBlock bb;
    bb.start_va = 0x2000;
    bb.end_va = 0x2014;
    bb.instructions = {
        {0x2000, {0,0,0,0}, "fadd", "s2, s0, s1", "fadd s2, s0, s1", ControlFlowKind::Sequential, std::nullopt},
        {0x2004, {0,0,0,0}, "fsub", "s3, s0, s1", "fsub s3, s0, s1", ControlFlowKind::Sequential, std::nullopt},
        {0x2008, {0,0,0,0}, "fmul", "s0, s2, s3", "fmul s0, s2, s3", ControlFlowKind::Sequential, std::nullopt},
        {0x200C, {0,0,0,0}, "ret", "", "ret", ControlFlowKind::Return, std::nullopt}
    };
    fn.blocks.push_back(bb);

    auto ir_fn = bytemorph::arch::aarch64::AArch64Lifter().lift_function(fn);
    auto bvm = IrToVmTranslator::translate(ir_fn, TranslateOptions{});
    ASSERT_TRUE(bvm.has_value()) << bvm.error().to_string();

    float a = 5.5f, b = 1.5f;
    std::uint32_t ua = 0, ub = 0;
    std::memcpy(&ua, &a, 4);
    std::memcpy(&ub, &b, 4);

    IrExecOptions ir_opts;
    ir_opts.initial_vregs[0][0] = ua;
    ir_opts.initial_vregs[1][0] = ub;
    auto ir_res = IrInterpreter::execute(ir_fn, ir_opts);
    ASSERT_TRUE(ir_res.has_value());

    VmExecOptions vm_opts;
    vm_opts.initial_vregs[0][0] = ua;
    vm_opts.initial_vregs[1][0] = ub;
    auto vm_res = VmInterpreter::execute(bvm.value(), vm_opts);
    ASSERT_TRUE(vm_res.has_value());

    float out_ir = 0.0f, out_vm = 0.0f;
    std::uint32_t r_ir = static_cast<std::uint32_t>(ir_res.value().vregs[0][0]);
    std::uint32_t r_vm = static_cast<std::uint32_t>(vm_res.value().vregs[0][0]);
    std::memcpy(&out_ir, &r_ir, 4);
    std::memcpy(&out_vm, &r_vm, 4);
    EXPECT_FLOAT_EQ(out_ir, (5.5f + 1.5f) * (5.5f - 1.5f));
    EXPECT_FLOAT_EQ(out_vm, out_ir);
}

TEST(ProtectionV010Test, Ieee754NanInfAndNegativeZeroPreservation) {
    using namespace bytemorph::virt;
    BvmProgram prog;
    prog.instructions = {
        {VmOpcode::VCmpF64, 0, 0, 1, 0},
        {VmOpcode::VDivF64, 2, 0, 1, 0},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };

    // 1.0 / 0.0 -> +Inf, Cmp(NaN, 1.0) -> zf=1, cf=1, pf=1
    double qnan = std::numeric_limits<double>::quiet_NaN();
    double one = 1.0;
    double zero = 0.0;
    VmExecOptions o1;
    std::memcpy(&o1.initial_vregs[0][0], &qnan, 8);
    std::memcpy(&o1.initial_vregs[1][0], &one, 8);
    auto r1 = VmInterpreter::execute(prog, o1);
    ASSERT_TRUE(r1.has_value());
    EXPECT_TRUE(r1.value().zf && r1.value().cf && r1.value().pf);
    double out1 = 0.0;
    std::memcpy(&out1, &r1.value().vregs[2][0], 8);
    EXPECT_TRUE(std::isnan(out1));

    VmExecOptions o2;
    std::memcpy(&o2.initial_vregs[0][0], &one, 8);
    std::memcpy(&o2.initial_vregs[1][0], &zero, 8);
    auto r2 = VmInterpreter::execute(prog, o2);
    ASSERT_TRUE(r2.has_value());
    double out2 = 0.0;
    std::memcpy(&out2, &r2.value().vregs[2][0], 8);
    EXPECT_TRUE(std::isinf(out2) && out2 > 0.0);
}

TEST(ProtectionV010Test, NativeX64SimdFp64Execution) {
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
    using namespace bytemorph::virt;
    BvmProgram prog;
    prog.instructions = {
        {VmOpcode::VAddF64, 2, 0, 1, 0},
        {VmOpcode::VMulF64, 0, 2, 0, 0},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };
    bytemorph::prot::detail::SharedRuntimeLayout layout;
    auto code = bytemorph::prot::detail::emit_shared_pic_x64_vm_runtime(
        std::vector<BvmProgram>{prog}, bytemorph::prot::detail::AbiKind::Win64, layout);
    ASSERT_TRUE(code.has_value()) << code.error().to_string();

    void* exec_mem = ::VirtualAlloc(nullptr, code.value().size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    ASSERT_NE(exec_mem, nullptr);
    std::memcpy(exec_mem, code.value().data(), code.value().size());
    using FpFn = double(*)(double, double);
    auto fn = reinterpret_cast<FpFn>(reinterpret_cast<std::uint8_t*>(exec_mem) + layout.entry_offsets[0]);
    EXPECT_DOUBLE_EQ(fn(3.5, 2.5), (3.5 + 2.5) * 3.5);
    ::VirtualFree(exec_mem, 0, MEM_RELEASE);
#else
    SUCCEED();
#endif
}

TEST(ProtectionV010Test, ExceptionAndUnwindDetectsActiveEhHandlers) {
#if defined(BYTEMORPH_LAB_PE_TARGET_PATH) && !defined(BYTEMORPH_HAS_SANITIZER)
    const std::filesystem::path target_exe(BYTEMORPH_LAB_PE_TARGET_PATH);
    if (std::filesystem::exists(target_exe)) {
        auto ex_res = bytemorph::prot::ProtectionEngine::analyze_exceptions(target_exe);
        ASSERT_TRUE(ex_res.has_value()) << ex_res.error().to_string();
        bool saw_eh_entry = false;
        for (const auto& e : ex_res.value()) {
            if (e.has_handler) {
                saw_eh_entry = true;
                EXPECT_FALSE(e.compatible_with_vm);
            }
        }
#if defined(_WIN32)
        EXPECT_TRUE(saw_eh_entry);
#else
        (void)saw_eh_entry;
#endif
    }
#else
    SUCCEED();
#endif
}

TEST(ProtectionV010Test, ConcurrentEncryptedVmAndAeadExecution) {
    using namespace bytemorph::prot;
    using namespace bytemorph::virt;
    const auto key = CryptoAead::derive_key_from_seed(0x55556666ULL, "concurrent");
    std::vector<std::thread> threads;
    std::atomic<int> failures{0};
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&, t]() {
            for (int iter = 0; iter < 100; ++iter) {
                BvmProgram p;
                p.build_seed = static_cast<std::uint64_t>(t * 1000 + iter + 1);
                p.instructions = {
                    {VmOpcode::MovImm, 1, 0, 0, static_cast<std::int64_t>(t + 10)},
                    {VmOpcode::MovImm, 2, 0, 0, static_cast<std::int64_t>(iter + 1)},
                    {VmOpcode::Add, 0, 1, 2, 0},
                    {VmOpcode::Ret, 0, 0, 0, 0}
                };
                auto enc = BvmCodec::encode(p);
                if (!enc) { failures.fetch_add(1); continue; }
                const auto nonce = CryptoAead::generate_nonce(p.build_seed, static_cast<std::uint64_t>(iter));
                auto box = CryptoAead::seal(enc.value(), {}, key, nonce);
                if (!box) { failures.fetch_add(1); continue; }
                auto open = CryptoAead::open(box.value(), {}, key);
                if (!open) { failures.fetch_add(1); continue; }
                auto dec = BvmCodec::decode(open.value());
                if (!dec) { failures.fetch_add(1); continue; }
                auto res = VmInterpreter::execute(dec.value());
                if (!res || res.value().return_value != static_cast<std::uint64_t>(t + 10 + iter + 1)) {
                    failures.fetch_add(1);
                }
            }
        });
    }
    for (auto& th : threads) th.join();
    EXPECT_EQ(failures.load(), 0);
}

TEST(ProtectionV010Test, BvmCodecSimdAndMetadataV2FuzzSafety) {
    using namespace bytemorph::virt;
    BvmProgram p;
    p.build_seed = 0x1234ABCDULL;
    p.instructions = {
        {VmOpcode::VMovReg, 0, 1, 0, 64},
        {VmOpcode::VAddF64, 0, 0, 2, 0},
        {VmOpcode::VCmpF32, 0, 0, 1, 0},
        {VmOpcode::VXor, 3, 3, 3, 0},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };
    auto enc = BvmCodec::encode(p);
    ASSERT_TRUE(enc.has_value());
    auto dec = BvmCodec::decode(enc.value());
    ASSERT_TRUE(dec.has_value());
    EXPECT_EQ(dec.value().instructions.size(), 5u);

    // Truncated v2 metadata must be rejected cleanly
    bytemorph::prot::ProtectionMetadata meta;
    meta.bytecode_encrypted = true;
    meta.encrypted_functions.push_back({0, {}, {}, 12, {}});
    auto raw = bytemorph::prot::detail::serialize_metadata(meta);
    raw.resize(raw.size() - 10);
    EXPECT_FALSE(bytemorph::prot::detail::deserialize_metadata(raw).has_value());
}

TEST(ProtectionV011Test, CryptoAeadKnownVectorsAndSecureWipe) {
    using namespace bytemorph::prot;
    // RFC 7693 BLAKE2b-256 empty input known vector:
    // 0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8
    const auto empty_hash = CryptoAead::blake2b_256(std::span<const std::uint8_t>{});
    const std::array<std::uint8_t, 32> expected_empty_blake2b{
        0x0e, 0x57, 0x51, 0xc0, 0x26, 0xe5, 0x43, 0xb2,
        0xe8, 0xab, 0x2e, 0xb0, 0x60, 0x99, 0xda, 0xa1,
        0xd1, 0xe5, 0xdf, 0x47, 0x77, 0x8f, 0x77, 0x87,
        0xfa, 0xab, 0x45, 0xcd, 0xf1, 0x2f, 0xe3, 0xa8
    };
    EXPECT_EQ(empty_hash, expected_empty_blake2b);

    // Deterministic XChaCha20-Poly1305 KAT & authentication-before-use check
    AeadKey key{};
    for (std::size_t i = 0; i < key.bytes.size(); ++i) key.bytes[i] = static_cast<std::uint8_t>(0x80 + i);
    AeadNonce nonce{};
    for (std::size_t i = 0; i < nonce.bytes.size(); ++i) nonce.bytes[i] = static_cast<std::uint8_t>(0x10 + i);
    const std::vector<std::uint8_t> pt = {'B', 'y', 't', 'e', 'M', 'o', 'r', 'p', 'h', 'v', '0', '1', '1'};
    const std::vector<std::uint8_t> aad = {'B', 'M', 'B', 'C', 0x02, 0x00};

    auto sealed = CryptoAead::seal(pt, aad, key, nonce);
    ASSERT_TRUE(sealed.has_value());
    auto opened = CryptoAead::open(sealed.value(), aad, key);
    ASSERT_TRUE(opened.has_value());
    EXPECT_EQ(opened.value(), pt);

    // Tamper AAD, ciphertext, and MAC: all must fail authentication
    auto bad_aad = aad;
    bad_aad[0] ^= 0x01;
    EXPECT_FALSE(CryptoAead::open(sealed.value(), bad_aad, key).has_value());

    auto tampered = sealed.value();
    tampered.ciphertext[0] ^= 0xFF;
    EXPECT_FALSE(CryptoAead::open(tampered, aad, key).has_value());

    tampered = sealed.value();
    tampered.mac[0] ^= 0xFF;
    EXPECT_FALSE(CryptoAead::open(tampered, aad, key).has_value());

    // Secure wipe zeroes key material
    CryptoAead::secure_wipe(key.bytes);
    for (std::uint8_t b : key.bytes) EXPECT_EQ(b, 0u);
}

TEST(ProtectionV011Test, MetadataV2RejectsDuplicateNonceAndInvalidFnIndex) {
    using namespace bytemorph::prot;
    ProtectionMetadata meta;
    meta.profile = ProtectionProfile::Maximum;
    meta.seed = 0xCAFEBABE1234ULL;
    meta.bytecode_encrypted = true;
    meta.functions.push_back({"fn_a", 0x1000, 0x2000, 5, 10, 10, 10});
    meta.functions.push_back({"fn_b", 0x1100, 0x2100, 5, 10, 10, 10});

    const auto n0 = CryptoAead::generate_nonce(meta.seed, 0);
    // Duplicate nonce across two functions must be rejected
    meta.encrypted_functions.push_back({0, n0, {}, 16, {}});
    meta.encrypted_functions.push_back({1, n0, {}, 16, {}});
    auto ser_dup_nonce = detail::serialize_metadata(meta);
    EXPECT_FALSE(detail::deserialize_metadata(ser_dup_nonce).has_value());

    // Out-of-range fn_index must be rejected when functions list is populated
    meta.encrypted_functions.clear();
    meta.encrypted_functions.push_back({5, n0, {}, 16, {}});
    auto ser_bad_idx = detail::serialize_metadata(meta);
    EXPECT_FALSE(detail::deserialize_metadata(ser_bad_idx).has_value());

    // Zero plaintext_size must be rejected
    meta.encrypted_functions.clear();
    meta.encrypted_functions.push_back({0, n0, {}, 0, {}});
    auto ser_zero_sz = detail::serialize_metadata(meta);
    EXPECT_FALSE(detail::deserialize_metadata(ser_zero_sz).has_value());
}

TEST(ProtectionV011Test, Simd20ConversionsAndPackedVectorDifferential) {
    using namespace bytemorph::core::analysis;
    using namespace bytemorph::core::ir;
    using namespace bytemorph::virt;

    // x86-64: cvtsi2sd xmm0, rax; cvtss2sd xmm1, xmm1; addsd xmm0, xmm1; cvttsd2si rax, xmm0; paddd xmm2, xmm3; ret
    FunctionInfo x64_fn;
    x64_fn.name = "simd20_x64";
    x64_fn.entry_va = 0x1000;
    x64_fn.size_bytes = 21;
    BasicBlock x64_bb;
    x64_bb.start_va = 0x1000;
    x64_bb.end_va = 0x1015;
    x64_bb.instructions = {
        {0x1000, {}, "cvtsi2sd", "xmm0, rax", "cvtsi2sd xmm0, rax", ControlFlowKind::Sequential, std::nullopt, false},
        {0x1004, {}, "cvtss2sd", "xmm1, xmm1", "cvtss2sd xmm1, xmm1", ControlFlowKind::Sequential, std::nullopt, false},
        {0x1008, {}, "addsd", "xmm0, xmm1", "addsd xmm0, xmm1", ControlFlowKind::Sequential, std::nullopt, false},
        {0x100C, {}, "cvttsd2si", "rax, xmm0", "cvttsd2si rax, xmm0", ControlFlowKind::Sequential, std::nullopt, false},
        {0x1010, {}, "paddd", "xmm2, xmm3", "paddd xmm2, xmm3", ControlFlowKind::Sequential, std::nullopt, false},
        {0x1014, {}, "ret", "", "ret", ControlFlowKind::Return, std::nullopt, false},
    };
    x64_fn.blocks.push_back(std::move(x64_bb));
    const auto ir_x64 = bytemorph::arch::x86_64::X86_64Lifter().lift_function(x64_fn);

    IrExecOptions ir_opts;
    ir_opts.initial_regs["rax"] = 42;
    const float f_in = 7.75f;
    std::uint32_t uf = 0;
    std::memcpy(&uf, &f_in, 4);
    ir_opts.initial_vregs[1][0] = uf;
    ir_opts.initial_vregs[2][0] = (10ULL << 32) | 5ULL;
    ir_opts.initial_vregs[3][0] = (20ULL << 32) | 7ULL;

    auto ir_res = IrInterpreter::execute(ir_x64, ir_opts);
    ASSERT_TRUE(ir_res.has_value()) << ir_res.error().to_string();
    EXPECT_EQ(ir_res.value().return_value, 49ULL);
    EXPECT_EQ(ir_res.value().vregs[2][0], (30ULL << 32) | 12ULL);

    auto vm_prog = IrToVmTranslator::translate(ir_x64);
    ASSERT_TRUE(vm_prog.has_value()) << vm_prog.error().to_string();
    VmExecOptions vm_opts;
    vm_opts.initial_regs[0] = 42; // rax -> R0
    vm_opts.initial_vregs[1][0] = uf;
    vm_opts.initial_vregs[2][0] = (10ULL << 32) | 5ULL;
    vm_opts.initial_vregs[3][0] = (20ULL << 32) | 7ULL;
    auto vm_res = VmInterpreter::execute(vm_prog.value(), vm_opts);
    ASSERT_TRUE(vm_res.has_value()) << vm_res.error().to_string();
    EXPECT_EQ(vm_res.value().return_value, ir_res.value().return_value);
    EXPECT_EQ(vm_res.value().vregs[2][0], ir_res.value().vregs[2][0]);

    // ARM64: scvtf d0, x0; fcvt d1, s1; fadd d0, d0, d1; fcvtzs x0, d0; add v2.4s, v2.4s, v3.4s; ret
    FunctionInfo a64_fn;
    a64_fn.name = "simd20_a64";
    a64_fn.entry_va = 0x2000;
    a64_fn.size_bytes = 24;
    BasicBlock a64_bb;
    a64_bb.start_va = 0x2000;
    a64_bb.end_va = 0x2018;
    a64_bb.instructions = {
        {0x2000, {}, "scvtf", "d0, x0", "scvtf d0, x0", ControlFlowKind::Sequential, std::nullopt, false},
        {0x2004, {}, "fcvt", "d1, s1", "fcvt d1, s1", ControlFlowKind::Sequential, std::nullopt, false},
        {0x2008, {}, "fadd", "d0, d0, d1", "fadd d0, d0, d1", ControlFlowKind::Sequential, std::nullopt, false},
        {0x200C, {}, "fcvtzs", "x0, d0", "fcvtzs x0, d0", ControlFlowKind::Sequential, std::nullopt, false},
        {0x2010, {}, "add", "v2.4s, v2.4s, v3.4s", "add v2.4s, v2.4s, v3.4s", ControlFlowKind::Sequential, std::nullopt, false},
        {0x2014, {}, "ret", "", "ret", ControlFlowKind::Return, std::nullopt, false},
    };
    a64_fn.blocks.push_back(std::move(a64_bb));
    const auto ir_a64 = bytemorph::arch::aarch64::AArch64Lifter().lift_function(a64_fn);
    ir_opts.initial_regs.clear();
    ir_opts.initial_regs["x0"] = 42;
    auto ir_a64_res = IrInterpreter::execute(ir_a64, ir_opts);
    ASSERT_TRUE(ir_a64_res.has_value()) << ir_a64_res.error().to_string();
    EXPECT_EQ(ir_a64_res.value().return_value, 49ULL);
    EXPECT_EQ(ir_a64_res.value().vregs[2][0], (30ULL << 32) | 12ULL);

    auto vm_a64 = IrToVmTranslator::translate(ir_a64);
    ASSERT_TRUE(vm_a64.has_value()) << vm_a64.error().to_string();
    auto vm_a64_res = VmInterpreter::execute(vm_a64.value(), vm_opts);
    ASSERT_TRUE(vm_a64_res.has_value()) << vm_a64_res.error().to_string();
    EXPECT_EQ(vm_a64_res.value().return_value, 49ULL);
    EXPECT_EQ(vm_a64_res.value().vregs[2][0], (30ULL << 32) | 12ULL);
}

TEST(ProtectionV011Test, NativeX64Simd20AndMxcsrPreservationExecution) {
#if (defined(__x86_64__) || defined(_M_X64)) && !defined(BYTEMORPH_HAS_SANITIZER)
    using namespace bytemorph::virt;
    // R1 = int(25), xmm1 = float(4.5) -> cvt R1->xmm0(f64), cvt xmm1(f32)->xmm1(f64), xmm0+=xmm1 -> cvt xmm0(f64)->R0(i64) == 29
    BvmProgram prog;
    prog.instructions = {
        {VmOpcode::MovImm, 1, 0, 0, 25},
        {VmOpcode::VCvtI2F, 0, 1, 0, 6},      // dst_f64 | src_64
        {VmOpcode::VCvtF2F, 1, 1, 0, 64},     // f32 -> f64
        {VmOpcode::VAddF64, 0, 0, 1, 0},
        {VmOpcode::VCvtF2I, 0, 0, 0, 6},      // src_f64 | dst_64
        {VmOpcode::Ret, 0, 0, 0, 0}
    };
    bytemorph::prot::detail::SharedRuntimeLayout layout;
#ifdef _WIN32
    const auto abi = bytemorph::prot::detail::AbiKind::Win64;
#else
    const auto abi = bytemorph::prot::detail::AbiKind::SysV_AMD64;
#endif
    auto code = bytemorph::prot::detail::emit_shared_pic_x64_vm_runtime(
        std::vector<BvmProgram>{prog}, abi, layout);
    ASSERT_TRUE(code.has_value()) << code.error().to_string();

    void* exec_mem = nullptr;
#ifdef _WIN32
    exec_mem = VirtualAlloc(nullptr, code.value().size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(exec_mem, nullptr);
    std::memcpy(exec_mem, code.value().data(), code.value().size());
    DWORD old_prot = 0;
    ASSERT_TRUE(VirtualProtect(exec_mem, code.value().size(), PAGE_EXECUTE_READ, &old_prot));
#else
    exec_mem = mmap(nullptr, code.value().size(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(exec_mem, MAP_FAILED);
    std::memcpy(exec_mem, code.value().data(), code.value().size());
    ASSERT_EQ(mprotect(exec_mem, code.value().size(), PROT_READ | PROT_EXEC), 0);
#endif
    using FnPtr = std::int64_t (*)(double, float);
    auto fn = reinterpret_cast<FnPtr>(static_cast<std::uint8_t*>(exec_mem) + layout.entry_offsets[0]);
    const std::int64_t out = fn(0.0, 4.5f);
    EXPECT_EQ(out, 29);
#ifdef _WIN32
    VirtualFree(exec_mem, 0, MEM_RELEASE);
#else
    munmap(exec_mem, code.value().size());
#endif
#else
    GTEST_SKIP() << "Native x64 SIMD 2.0 test runs on non-sanitized x86-64 hosts";
#endif
}

TEST(ProtectionV011Test, RealLabCAppProtectionAndEquivalence) {
#if defined(_WIN32) && defined(BYTEMORPH_LAB_C_APP_PATH) && !defined(BYTEMORPH_HAS_SANITIZER)
    const std::filesystem::path orig_exe(BYTEMORPH_LAB_C_APP_PATH);
    if (std::filesystem::exists(orig_exe)) {
        const std::filesystem::path prot_exe =
            std::filesystem::temp_directory_path() / "bytemorph_v011_lab_c_prot.exe";
        const std::filesystem::path out_orig =
            std::filesystem::temp_directory_path() / "bytemorph_v011_lab_c_orig.txt";
        const std::filesystem::path out_prot =
            std::filesystem::temp_directory_path() / "bytemorph_v011_lab_c_prot.txt";
        std::filesystem::remove(prot_exe);
        std::filesystem::remove(out_orig);
        std::filesystem::remove(out_prot);

        bytemorph::prot::ProtectOptions opts;
        opts.profile = bytemorph::prot::ProtectionProfile::Balanced;
        opts.protect_all_eligible = true;
        opts.encrypt_bytecode = true;
        opts.allow_external_calls = true;

        auto prot_res = bytemorph::prot::ProtectionEngine::protect(orig_exe, prot_exe, opts);
        ASSERT_TRUE(prot_res.has_value()) << prot_res.error().to_string();
        EXPECT_GE(prot_res.value().protected_functions.size(), 2u);

        auto ver_res = bytemorph::prot::ProtectionEngine::verify(prot_exe);
        ASSERT_TRUE(ver_res.has_value()) << ver_res.error().to_string();
        EXPECT_TRUE(ver_res.value().valid);
        EXPECT_TRUE(ver_res.value().aead_authenticated);
        EXPECT_TRUE(ver_res.value().metadata.bytecode_encrypted);

        auto run_and_capture = [](const std::filesystem::path& exe, const std::filesystem::path& out_f, int& rc) {
#ifdef _WIN32
            const std::string cmd = "\"\"" + exe.string() + "\" --seed 31 --out \"" + out_f.string() + "\"\"";
            FILE* p = _popen(cmd.c_str(), "r");
#else
            const std::string cmd = "\"" + exe.string() + "\" --seed 31 --out \"" + out_f.string() + "\"";
            FILE* p = popen(cmd.c_str(), "r");
#endif
            std::string s;
            if (p) {
                char buf[256];
                while (std::fgets(buf, sizeof(buf), p) != nullptr) s += buf;
#ifdef _WIN32
                rc = _pclose(p);
#else
                rc = pclose(p);
#endif
            }
            return s;
        };
        int rc1 = -1, rc2 = -1;
        const std::string s1 = run_and_capture(orig_exe, out_orig, rc1);
        const std::string s2 = run_and_capture(prot_exe, out_prot, rc2);
        EXPECT_EQ(rc1, 0);
        EXPECT_EQ(rc2, 0);
        EXPECT_EQ(s1, s2);

        {
            std::ifstream f1(out_orig, std::ios::binary), f2(out_prot, std::ios::binary);
            const std::string c1((std::istreambuf_iterator<char>(f1)), std::istreambuf_iterator<char>());
            const std::string c2((std::istreambuf_iterator<char>(f2)), std::istreambuf_iterator<char>());
            EXPECT_FALSE(c1.empty());
            EXPECT_EQ(c1, c2);
        }

        std::filesystem::remove(prot_exe);
        std::filesystem::remove(out_orig);
        std::filesystem::remove(out_prot);
    }
#else
    GTEST_SKIP() << "Real Windows lab C app equivalence runs on non-sanitized Windows x64";
#endif
}

TEST(ProtectionV011Test, RealLabCppAppMultiHundredFuncsAndMultithreadEquivalence) {
#if defined(_WIN32) && defined(BYTEMORPH_LAB_CPP_APP_PATH) && !defined(BYTEMORPH_HAS_SANITIZER)
    const std::filesystem::path orig_exe(BYTEMORPH_LAB_CPP_APP_PATH);
    if (std::filesystem::exists(orig_exe)) {
        auto comp_res = bytemorph::prot::ProtectionEngine::check_compatibility(orig_exe, true);
        ASSERT_TRUE(comp_res.has_value()) << comp_res.error().to_string();
        EXPECT_GE(comp_res.value().eligible_functions.size() + comp_res.value().rejected_functions.size(), 100u);

        bool eh_rejected = false;
        for (const auto& r : comp_res.value().rejected_functions) {
            if (r.name.find("lab_cpp_eh_fn") != std::string::npos &&
                r.category == "exception_unwind_incompatible") {
                eh_rejected = true;
            }
        }
        EXPECT_TRUE(eh_rejected);

        const std::filesystem::path prot_exe =
            std::filesystem::temp_directory_path() / "bytemorph_v011_lab_cpp_prot.exe";
        const std::filesystem::path out_orig =
            std::filesystem::temp_directory_path() / "bytemorph_v011_lab_cpp_orig.txt";
        const std::filesystem::path out_prot =
            std::filesystem::temp_directory_path() / "bytemorph_v011_lab_cpp_prot.txt";
        std::filesystem::remove(prot_exe);
        std::filesystem::remove(out_orig);
        std::filesystem::remove(out_prot);

        bytemorph::prot::ProtectOptions opts;
        opts.profile = bytemorph::prot::ProtectionProfile::Balanced;
        opts.protect_all_eligible = true;
        opts.encrypt_bytecode = true;
        opts.allow_external_calls = true;

        auto prot_res = bytemorph::prot::ProtectionEngine::protect(orig_exe, prot_exe, opts);
        ASSERT_TRUE(prot_res.has_value()) << prot_res.error().to_string();
        EXPECT_GE(prot_res.value().protected_functions.size(), 10u);

        auto ver_res = bytemorph::prot::ProtectionEngine::verify(prot_exe);
        ASSERT_TRUE(ver_res.has_value()) << ver_res.error().to_string();
        EXPECT_TRUE(ver_res.value().aead_authenticated);

        auto run_and_capture = [](const std::filesystem::path& exe, const std::filesystem::path& out_f, int& rc) {
#ifdef _WIN32
            const std::string cmd = "\"\"" + exe.string() + "\" --seed 29 --out \"" + out_f.string() + "\"\"";
            FILE* p = _popen(cmd.c_str(), "r");
#else
            const std::string cmd = "\"" + exe.string() + "\" --seed 29 --out \"" + out_f.string() + "\"";
            FILE* p = popen(cmd.c_str(), "r");
#endif
            std::string s;
            if (p) {
                char buf[256];
                while (std::fgets(buf, sizeof(buf), p) != nullptr) s += buf;
#ifdef _WIN32
                rc = _pclose(p);
#else
                rc = pclose(p);
#endif
            }
            return s;
        };
        int rc1 = -1, rc2 = -1;
        const std::string s1 = run_and_capture(orig_exe, out_orig, rc1);
        const std::string s2 = run_and_capture(prot_exe, out_prot, rc2);
        EXPECT_EQ(rc1, 0);
        EXPECT_EQ(rc2, 0);
        EXPECT_EQ(s1, s2);

        {
            std::ifstream f1(out_orig, std::ios::binary), f2(out_prot, std::ios::binary);
            const std::string c1((std::istreambuf_iterator<char>(f1)), std::istreambuf_iterator<char>());
            const std::string c2((std::istreambuf_iterator<char>(f2)), std::istreambuf_iterator<char>());
            EXPECT_FALSE(c1.empty());
            EXPECT_EQ(c1, c2);
        }

        std::filesystem::remove(prot_exe);
        std::filesystem::remove(out_orig);
        std::filesystem::remove(out_prot);
    }
#else
    GTEST_SKIP() << "Real Windows lab C++ app equivalence runs on non-sanitized Windows x64";
#endif
}

TEST(ProtectionV011Test, SmartEligibility50BudgetAndMetrics) {
    using namespace bytemorph::core::analysis;
    using namespace bytemorph::prot;

    // Build a synthetic binary or inspect lab_pe_target for Smart Eligibility 5.0 fields
#ifdef BYTEMORPH_LAB_PE_TARGET_PATH
    const std::filesystem::path target_exe(BYTEMORPH_LAB_PE_TARGET_PATH);
    if (std::filesystem::exists(target_exe)) {
        auto comp = ProtectionEngine::check_compatibility(target_exe, true);
        ASSERT_TRUE(comp.has_value()) << comp.error().to_string();
        ASSERT_FALSE(comp.value().eligible_functions.empty());
        for (const auto& ef : comp.value().eligible_functions) {
            EXPECT_FALSE(ef.decision_explanation.empty());
        }
    }
#endif
}

TEST(ProtectionV012Test, IrOptimizer20PassesAndSemanticEquivalence) {
    using namespace bytemorph::core::ir;

    IrFunction fn;
    fn.name = "opt_test";
    fn.entry_va = 0x1000;
    IrBasicBlock bb;
    bb.id = 0;
    bb.start_va = 0x1000;

    // v0 = 10; v1 = 20; v2 = v0 + v1 (fold -> 30); v3 = v2 + 0 (alg -> v2);
    // dead_v = v3 * 7 (DCE); rax = v3 + rcx; ret
    bb.instructions.push_back({0x1000, IrOpcode::Mov, {IrOperand::vreg("v_alpha")}, {IrOperand::immediate(10)}, "", ""});
    bb.instructions.push_back({0x1004, IrOpcode::Mov, {IrOperand::vreg("v_beta")}, {IrOperand::immediate(20)}, "", ""});
    bb.instructions.push_back({0x1008, IrOpcode::Add, {IrOperand::vreg("v_sum")}, {IrOperand::vreg("v_alpha"), IrOperand::vreg("v_beta")}, "", ""});
    bb.instructions.push_back({0x100C, IrOpcode::Add, {IrOperand::vreg("v_zero")}, {IrOperand::vreg("v_sum"), IrOperand::immediate(0)}, "", ""});
    bb.instructions.push_back({0x1010, IrOpcode::Mul, {IrOperand::vreg("v_dead")}, {IrOperand::vreg("v_zero"), IrOperand::immediate(7)}, "", ""});
    bb.instructions.push_back({0x1014, IrOpcode::Mov, {IrOperand::vreg("v_copy")}, {IrOperand::vreg("v_zero")}, "", ""});
    bb.instructions.push_back({0x1018, IrOpcode::Add, {IrOperand::reg("rax")}, {IrOperand::reg("rcx"), IrOperand::vreg("v_copy")}, "", ""});
    bb.instructions.push_back({0x101C, IrOpcode::Ret, {}, {}, "", ""});
    fn.blocks.push_back(std::move(bb));

    const IrFunction orig = fn;
    IrOptimizeOptions opts;
    opts.level = 3;
    const auto stats = IrOptimizer::optimize(fn, opts);

    EXPECT_LT(stats.instructions_after, stats.instructions_before);
    EXPECT_GT(stats.constants_folded, 0u);
    EXPECT_GT(stats.dead_instructions_removed, 0u);

    for (std::int64_t x : {-50LL, 0LL, 17LL, 12345LL}) {
        IrExecOptions s_orig, s_opt;
        s_orig.initial_regs["rcx"] = static_cast<std::uint64_t>(x);
        s_opt.initial_regs["rcx"] = static_cast<std::uint64_t>(x);
        auto r_orig = IrInterpreter::execute(orig, s_orig);
        auto r_opt = IrInterpreter::execute(fn, s_opt);
        ASSERT_TRUE(r_orig.has_value());
        ASSERT_TRUE(r_opt.has_value());
        EXPECT_EQ(r_orig.value().regs["rax"], r_opt.value().regs["rax"]);
    }
}

TEST(ProtectionV012Test, VmInterpreter40PrepareCacheAndDifferentialEquivalence) {
    using namespace bytemorph::virt;

    BvmProgram prog;
    prog.build_seed = 0x12345678ULL;
    prog.instructions = {
        {VmOpcode::MovImm, 1, 0, 0, 100},
        {VmOpcode::Store, 4, 1, 8, -8},
        {VmOpcode::Load, 2, 4, 8, -8},
        {VmOpcode::Add, 0, 0, 2, 0},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };

    auto prep = VmInterpreter::prepare(prog);
    ASSERT_TRUE(prep.has_value()) << prep.error().to_string();
    EXPECT_TRUE(prep.value().has_mem_ops);
    EXPECT_FALSE(prep.value().has_simd_ops);

    for (int i = 0; i < 64; ++i) {
        VmExecOptions opts;
        opts.initial_regs[0] = static_cast<std::uint64_t>(i * 3);
        auto r1 = VmInterpreter::execute(prog, opts);
        auto r2 = VmInterpreter::execute_prepared(prep.value(), opts);
        ASSERT_TRUE(r1.has_value());
        ASSERT_TRUE(r2.has_value());
        EXPECT_EQ(r1.value().return_value, static_cast<std::uint64_t>(i * 3 + 100));
        EXPECT_EQ(r1.value().return_value, r2.value().return_value);
    }
}

TEST(ProtectionV012Test, SdkMarkersAndAutoSelectProtectionEquivalence) {
#ifdef BYTEMORPH_LAB_SDK_APP_PATH
    const std::filesystem::path sdk_exe(BYTEMORPH_LAB_SDK_APP_PATH);
    if (!std::filesystem::exists(sdk_exe)) {
        GTEST_SKIP() << "lab_sdk_app not built";
    }
    const auto out_exe = std::filesystem::temp_directory_path() /
        ("lab_sdk_app_protected" + sdk_exe.extension().string());

    bytemorph::prot::ProtectOptions opts;
    opts.profile = bytemorph::prot::ProtectionProfile::Balanced;
    opts.auto_select_functions = true;
    opts.encrypt_bytecode = true;
    opts.allow_strip_signature = true;

    auto res = bytemorph::prot::ProtectionEngine::protect(sdk_exe, out_exe, opts);
    ASSERT_TRUE(res.has_value()) << res.error().to_string();
    EXPECT_GE(res.value().protected_functions.size(), 1u);

    auto ver = bytemorph::prot::ProtectionEngine::verify(out_exe);
    ASSERT_TRUE(ver.has_value()) << ver.error().to_string();
    EXPECT_TRUE(ver.value().valid);
    EXPECT_TRUE(ver.value().aead_authenticated);

#ifdef _WIN32
    auto run_capture = [](const std::filesystem::path& exe, int& rc) -> std::string {
        std::string cmd = "\"\"" + exe.string() + "\" 42\"";
        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) { rc = -1; return {}; }
        char buf[256];
        std::string out;
        while (std::fgets(buf, sizeof(buf), pipe)) out += buf;
        rc = _pclose(pipe);
        return out;
    };
    int rc_orig = -1, rc_prot = -1;
    const std::string out_orig = run_capture(sdk_exe, rc_orig);
    const std::string out_prot = run_capture(out_exe, rc_prot);
    EXPECT_EQ(rc_orig, 0);
    EXPECT_EQ(rc_prot, 0);
    EXPECT_EQ(out_orig, out_prot);
#endif
    std::error_code ec;
    std::filesystem::remove(out_exe, ec);
#endif
}

TEST(ProtectionV012Test, SharedLibraryDllSoDylibProtectionAndVerification) {
#ifdef BYTEMORPH_LAB_SHARED_LIB_PATH
    const std::filesystem::path lib_path(BYTEMORPH_LAB_SHARED_LIB_PATH);
    if (!std::filesystem::exists(lib_path)) {
        GTEST_SKIP() << "lab_shared_lib not built";
    }
    const auto out_lib = std::filesystem::temp_directory_path() /
        ("lab_shared_lib_protected" + lib_path.extension().string());

    bytemorph::prot::ProtectOptions opts;
    opts.profile = bytemorph::prot::ProtectionProfile::Balanced;
    opts.protect_all_eligible = true;
    opts.encrypt_bytecode = true;
    opts.allow_strip_signature = true;

    auto res = bytemorph::prot::ProtectionEngine::protect(lib_path, out_lib, opts);
    if (!res.has_value()) {
        auto comp = bytemorph::prot::ProtectionEngine::check_compatibility(lib_path, true);
        std::string diag = res.error().to_string();
        if (comp.has_value()) {
            diag += " | elig=" + std::to_string(comp.value().eligible_functions.size()) +
                    " rej=" + std::to_string(comp.value().rejected_functions.size());
            for (const auto& rf : comp.value().rejected_functions) {
                diag += " [" + rf.name + ": " + rf.category + " -> " + rf.rejection_reason + "]";
            }
        }
        FAIL() << diag;
    }
    EXPECT_GE(res.value().protected_functions.size(), 1u);

    auto ver = bytemorph::prot::ProtectionEngine::verify(out_lib);
    ASSERT_TRUE(ver.has_value()) << ver.error().to_string();
    EXPECT_TRUE(ver.value().valid);
    EXPECT_TRUE(ver.value().aead_authenticated);

#ifdef _WIN32
    HMODULE mod = LoadLibraryA(out_lib.string().c_str());
    ASSERT_NE(mod, nullptr) << "LoadLibraryA failed on protected DLL";
    using AddMulFn = int(*)(int, int);
    using ChecksumFn = std::uint64_t(*)(std::uint64_t, std::uint64_t);
    auto fn_add_mul = reinterpret_cast<AddMulFn>(GetProcAddress(mod, "bm_shared_add_mul"));
    auto fn_csum = reinterpret_cast<ChecksumFn>(GetProcAddress(mod, "bm_shared_checksum"));
    ASSERT_NE(fn_add_mul, nullptr);
    ASSERT_NE(fn_csum, nullptr);
    EXPECT_EQ(fn_add_mul(10, 20), (10 * 7 + 20 * 13) ^ 0x1357);
    std::uint64_t expected = 0x1234ULL ^ 0xCAFEBABEULL;
    for (std::uint64_t i = 0; i < 50; ++i) expected = (expected * 33ULL) + i;
    EXPECT_EQ(fn_csum(0x1234ULL, 50), expected);
    FreeLibrary(mod);
#endif
    std::error_code ec;
    std::filesystem::remove(out_lib, ec);
#endif
}

TEST(ProtectionV012Test, Cryptography30MultiFunctionAeadAndCorruptionHandling) {
#ifdef BYTEMORPH_LAB_SHARED_LIB_PATH
    const std::filesystem::path lib_path(BYTEMORPH_LAB_SHARED_LIB_PATH);
    if (!std::filesystem::exists(lib_path)) {
        GTEST_SKIP() << "lab_shared_lib not built";
    }
    const auto out_lib = std::filesystem::temp_directory_path() /
        ("lab_crypto30_protected" + lib_path.extension().string());

    bytemorph::prot::ProtectOptions opts;
    opts.profile = bytemorph::prot::ProtectionProfile::Maximum;
    opts.protect_all_eligible = true;
    opts.encrypt_bytecode = true;
    opts.allow_strip_signature = true;

    auto res = bytemorph::prot::ProtectionEngine::protect(lib_path, out_lib, opts);
    if (!res.has_value()) {
        auto comp = bytemorph::prot::ProtectionEngine::check_compatibility(lib_path, true);
        std::string diag = res.error().to_string();
        if (comp.has_value()) {
            diag += " | elig=" + std::to_string(comp.value().eligible_functions.size()) +
                    " rej=" + std::to_string(comp.value().rejected_functions.size());
            for (const auto& rf : comp.value().rejected_functions) {
                diag += " [" + rf.name + ": " + rf.category + " -> " + rf.rejection_reason + "]";
            }
        }
        FAIL() << diag;
    }

    auto ver = bytemorph::prot::ProtectionEngine::verify(out_lib);
    ASSERT_TRUE(ver.has_value());
    EXPECT_TRUE(ver.value().valid);
    EXPECT_TRUE(ver.value().aead_authenticated);

    // Corrupt last bytes (BMP4 / sealed payload) and verify clean rejection
    std::ifstream ifs(out_lib, std::ios::binary | std::ios::ate);
    ASSERT_TRUE(ifs.good());
    const auto sz = static_cast<std::size_t>(ifs.tellg());
    ASSERT_GT(sz, 128u);
    ifs.seekg(0);
    std::vector<std::uint8_t> corrupted(sz);
    ifs.read(reinterpret_cast<char*>(corrupted.data()), static_cast<std::streamsize>(sz));
    // Locate BMP4 metadata/payload and corrupt 1 byte inside it to verify AEAD rejection
    bool flipped = false;
    for (std::size_t i = 0; i + 48 < corrupted.size(); ++i) {
        if (corrupted[i] == 'B' && corrupted[i + 1] == 'M' &&
            corrupted[i + 2] == 'P' && corrupted[i + 3] == '4') {
            corrupted[i + 40] ^= 0x5A;
            flipped = true;
            break;
        }
    }
    ASSERT_TRUE(flipped);
    const auto corrupt_path = std::filesystem::temp_directory_path() /
        ("lab_crypto30_corrupt" + lib_path.extension().string());
    {
        std::ofstream ofs(corrupt_path, std::ios::binary);
        ofs.write(reinterpret_cast<const char*>(corrupted.data()), static_cast<std::streamsize>(corrupted.size()));
    }
    auto ver_bad = bytemorph::prot::ProtectionEngine::verify(corrupt_path);
    if (ver_bad.has_value()) {
        EXPECT_FALSE(ver_bad.value().valid);
    }

    std::error_code ec;
    std::filesystem::remove(out_lib, ec);
    std::filesystem::remove(corrupt_path, ec);
#endif
}

TEST(ProtectionV012Test, WindowsArm64Pe32PlusAndLargeStackProbeEmission) {
    using namespace bytemorph::prot::detail;
    using namespace bytemorph::virt;

    // Program large enough (> 3KB encrypted blob) to exercise ARM64 >= 4096B stack probing
    BvmProgram big_prog;
    big_prog.build_seed = 0xA4642026ULL;
    for (int i = 0; i < 320; ++i) {
        big_prog.instructions.push_back({VmOpcode::Add, 0, 0, 1, 0});
    }
    big_prog.instructions.push_back({VmOpcode::Ret, 0, 0, 0, 0});

    SharedRuntimeLayout layout;
    SharedRuntimeOptions rt_opts;
    rt_opts.encrypt_bytecode = true;
    rt_opts.seed = 0xA4642026ULL;
    auto arm64_rt = emit_shared_pic_arm64_vm_runtime(
        std::vector<BvmProgram>{big_prog}, layout, rt_opts);
    ASSERT_TRUE(arm64_rt.has_value()) << arm64_rt.error().to_string();
    EXPECT_GT(arm64_rt.value().size(), 3000u);
    EXPECT_EQ(layout.entry_offsets.size(), 1u);
}

TEST(ProtectionV013Test, PerBlockKeyDerivationAndNonceUniqueness) {
    using namespace bytemorph::prot;

    const auto master = CryptoAead::derive_key_from_seed(0xCAFE013ULL, "bm.rt.v10");
    const auto k00 = CryptoAead::derive_block_key(master, 0, 0, "bm.lazy.block.v1");
    const auto k01 = CryptoAead::derive_block_key(master, 0, 1, "bm.lazy.block.v1");
    const auto k10 = CryptoAead::derive_block_key(master, 1, 0, "bm.lazy.block.v1");
    const auto k00_again = CryptoAead::derive_block_key(master, 0, 0, "bm.lazy.block.v1");

    EXPECT_EQ(k00.bytes, k00_again.bytes);
    EXPECT_NE(k00.bytes, k01.bytes);
    EXPECT_NE(k00.bytes, k10.bytes);
    EXPECT_NE(k01.bytes, k10.bytes);

    const auto n00 = CryptoAead::generate_block_nonce(0xCAFE013ULL, 0, 0);
    const auto n01 = CryptoAead::generate_block_nonce(0xCAFE013ULL, 0, 1);
    const auto n10 = CryptoAead::generate_block_nonce(0xCAFE013ULL, 1, 0);
    EXPECT_NE(n00.bytes, n01.bytes);
    EXPECT_NE(n00.bytes, n10.bytes);
    EXPECT_NE(n01.bytes, n10.bytes);
}

TEST(ProtectionV013Test, LazyBytecodeDecryptionCacheLruAndTamperRejection) {
    using namespace bytemorph::prot;
    using namespace bytemorph::virt;

    BvmProgram prog;
    prog.build_seed = 0x55667788ULL;
    // Sum 1..R0 in a multi-block loop
    prog.instructions = {
        {VmOpcode::MovImm, 1, 0, 0, 0},   // blk 0: sum = 0
        {VmOpcode::MovImm, 2, 0, 0, 1},   // blk 0: step = 1
        {VmOpcode::MovImm, 3, 0, 0, 0},   // blk 0: zero
        {VmOpcode::Cmp, 0, 0, 3, 0},      // blk 1: while r0 > 0
        {VmOpcode::Jle, 0, 0, 0, 7},
        {VmOpcode::Add, 1, 1, 0, 0},      // blk 2: sum += r0
        {VmOpcode::Sub, 0, 0, 2, 0},      // blk 2: r0 -= 1
        {VmOpcode::Jmp, 0, 0, 0, 3},      // blk 2: loop back
        {VmOpcode::MovReg, 0, 1, 0, 0},   // blk 3: r0 = sum (wait pc=8, Jle target should be 8!)
        {VmOpcode::Ret, 0, 0, 0, 0}
    };
    prog.instructions[4].imm = 8;

    const auto master = CryptoAead::derive_key_from_seed(0x99887766ULL, "bm.rt.v10");
    auto sealed = LazyBytecodeEngine::seal_function(prog, master, 0x99887766ULL, 0);
    ASSERT_TRUE(sealed.has_value()) << sealed.error().to_string();
    ASSERT_GE(sealed.value().blocks.size(), 4u);

    auto ver_all = LazyBytecodeEngine::verify_all_blocks(sealed.value(), master);
    ASSERT_TRUE(ver_all.has_value()) << ver_all.error().to_string();

    // Small LRU cache (max 2 blocks) to exercise evictions + secure wipe
    VmBytecodeCache cache(64 * 1024, 2);
    for (std::uint64_t n : {0ULL, 5ULL, 10ULL, 25ULL}) {
        VmExecOptions opts;
        opts.initial_regs[0] = n;
        auto eager = VmInterpreter::execute(prog, opts);
        auto lazy = LazyBytecodeEngine::execute_lazy(sealed.value(), master, cache, opts);
        ASSERT_TRUE(eager.has_value());
        ASSERT_TRUE(lazy.has_value()) << lazy.error().to_string();
        EXPECT_EQ(eager.value().return_value, n * (n + 1) / 2);
        EXPECT_EQ(eager.value().return_value, lazy.value().return_value);
    }

    const auto st = cache.stats();
    EXPECT_GT(st.hits, 0u);
    EXPECT_GT(st.misses, 0u);
    EXPECT_GT(st.evictions, 0u);
    cache.invalidate_all();
    EXPECT_EQ(cache.stats().current_bytes, 0u);

    // Tamper ciphertext in block 1 -> must fail AEAD before executing
    auto tampered = sealed.value();
    tampered.blocks[1].ciphertext[0] ^= 0xFF;
    VmBytecodeCache clean_cache(64 * 1024, 16);
    VmExecOptions opts;
    opts.initial_regs[0] = 5;
    auto bad_res = LazyBytecodeEngine::execute_lazy(tampered, master, clean_cache, opts);
    EXPECT_FALSE(bad_res.has_value());

    // Block substitution / reordering -> must fail AAD/key binding
    auto swapped = sealed.value();
    std::swap(swapped.blocks[1], swapped.blocks[2]);
    auto bad_swap = LazyBytecodeEngine::verify_all_blocks(swapped, master);
    EXPECT_FALSE(bad_swap.has_value());
}

TEST(ProtectionV013Test, ConcurrentLazyBytecodeExecutionAndCacheIsolation) {
    using namespace bytemorph::prot;
    using namespace bytemorph::virt;

    BvmProgram p1, p2;
    p1.build_seed = 0x1111ULL;
    p1.instructions = {
        {VmOpcode::MovImm, 1, 0, 0, 7},
        {VmOpcode::Mul, 0, 0, 1, 0},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };
    p2.build_seed = 0x2222ULL;
    p2.instructions = {
        {VmOpcode::MovImm, 1, 0, 0, 100},
        {VmOpcode::Add, 0, 0, 1, 0},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };

    const auto key = CryptoAead::derive_key_from_seed(0xABCDEFULL, "bm.rt.v10");
    auto b1 = LazyBytecodeEngine::seal_function(p1, key, 0xABCDEFULL, 0);
    auto b2 = LazyBytecodeEngine::seal_function(p2, key, 0xABCDEFULL, 1);
    ASSERT_TRUE(b1.has_value() && b2.has_value());

    VmBytecodeCache shared_cache(64 * 1024, 32);
    std::atomic<int> failures{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&, t]() {
            for (int iter = 0; iter < 50; ++iter) {
                VmExecOptions o;
                o.initial_regs[0] = static_cast<std::uint64_t>(t * 10 + iter);
                auto r1 = LazyBytecodeEngine::execute_lazy(b1.value(), key, shared_cache, o);
                auto r2 = LazyBytecodeEngine::execute_lazy(b2.value(), key, shared_cache, o);
                if (!r1.has_value() || r1.value().return_value != o.initial_regs[0] * 7 ||
                    !r2.has_value() || r2.value().return_value != o.initial_regs[0] + 100) {
                    failures.fetch_add(1);
                }
            }
        });
    }
    for (auto& th : threads) th.join();
    EXPECT_EQ(failures.load(), 0);
}

TEST(ProtectionV013Test, ProtectRealBinaryWithLazyBytecodeModeAndDeepVerify) {
#ifdef BYTEMORPH_LAB_SDK_APP_PATH
    const std::filesystem::path sdk_exe(BYTEMORPH_LAB_SDK_APP_PATH);
    if (!std::filesystem::exists(sdk_exe)) {
        GTEST_SKIP() << "lab_sdk_app not built";
    }
    const auto out_exe = std::filesystem::temp_directory_path() /
        ("lab_sdk_lazy_v013" + sdk_exe.extension().string());

    bytemorph::prot::ProtectOptions opts;
    opts.profile = bytemorph::prot::ProtectionProfile::Maximum;
    opts.bytecode_mode = bytemorph::prot::BytecodeMode::Lazy;
    opts.auto_select_functions = true;
    opts.encrypt_bytecode = true;
    opts.allow_strip_signature = true;

    auto res = bytemorph::prot::ProtectionEngine::protect(sdk_exe, out_exe, opts);
    ASSERT_TRUE(res.has_value()) << res.error().to_string();
    EXPECT_EQ(res.value().bytecode_mode, bytemorph::prot::BytecodeMode::Lazy);
    EXPECT_GT(res.value().encrypted_blocks_count, 0u);

    auto ver = bytemorph::prot::ProtectionEngine::verify(out_exe);
    ASSERT_TRUE(ver.has_value()) << ver.error().to_string();
    EXPECT_TRUE(ver.value().valid);
    EXPECT_TRUE(ver.value().aead_authenticated);
    EXPECT_EQ(ver.value().metadata.bytecode_mode, bytemorph::prot::BytecodeMode::Lazy);
    EXPECT_EQ(ver.value().blocks_verified_count, res.value().encrypted_blocks_count);

#ifdef _WIN32
    auto run_capture = [](const std::filesystem::path& exe, int& rc) -> std::string {
        std::string cmd = "\"\"" + exe.string() + "\" 42\"";
        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) { rc = -1; return {}; }
        char buf[256];
        std::string out;
        while (std::fgets(buf, sizeof(buf), pipe)) out += buf;
        rc = _pclose(pipe);
        return out;
    };
    int rc_orig = -1, rc_prot = -1;
    const std::string out_orig = run_capture(sdk_exe, rc_orig);
    const std::string out_prot = run_capture(out_exe, rc_prot);
    EXPECT_EQ(rc_orig, 0);
    EXPECT_EQ(rc_prot, 0);
    EXPECT_EQ(out_orig, out_prot);
#endif
    std::error_code ec;
    std::filesystem::remove(out_exe, ec);
#endif
}

TEST(ProtectionV013Test, DynamicLinkingAuthorizedCallTargetsResolution) {
#ifdef BYTEMORPH_LAB_C_APP_PATH
    const std::filesystem::path c_app(BYTEMORPH_LAB_C_APP_PATH);
    if (!std::filesystem::exists(c_app)) {
        GTEST_SKIP() << "lab_c_app not built";
    }
    bytemorph::core::binary::BinaryLoader loader;
    loader.register_parser(std::make_unique<bytemorph::formats::pe::PeParser>());
    auto bin_res = loader.load_file(c_app);
    if (bin_res.has_value()) {
        EXPECT_FALSE(bin_res.value()->imports().empty());
        bytemorph::arch::x86_64::X86_64Disassembler disasm;
        bytemorph::core::analysis::BinaryAnalyzer analyzer;
        auto an = analyzer.analyze(*bin_res.value(), disasm);
        ASSERT_TRUE(an.has_value());
        const auto auth = bytemorph::prot::detail::build_authorized_call_targets(*bin_res.value(), an.value());
        EXPECT_FALSE(auth.empty());
        EXPECT_FALSE(auth.contains(0xDEADBEEFCAFEULL));
    }
#endif
}

TEST(ProtectionV014Test, NativePicLazyX64ExecutionAndEquivalence) {
    using namespace bytemorph::virt;
    using namespace bytemorph::prot::detail;

#ifdef _WIN32
    constexpr AbiKind abi = AbiKind::Win64;
    constexpr std::uint8_t arg_reg = 1; // Win64 RCX -> R1
#else
    constexpr AbiKind abi = AbiKind::SysV_AMD64;
    constexpr std::uint8_t arg_reg = 7; // SysV RDI -> R7
#endif

    BvmProgram prog;
    prog.build_seed = 0x1401ULL;
    // sum_{i=0}^{arg0-1} (i * 3 + 1) across 4 basic blocks
    prog.instructions = {
        {VmOpcode::MovImm, 3, 0, 0, 0},       // 0: R3 = acc = 0
        {VmOpcode::MovImm, 2, 0, 0, 0},       // 1: R2 = i = 0
        {VmOpcode::Cmp,    0, 2, arg_reg, 0}, // 2: cmp R2, arg0
        {VmOpcode::Jge,    0, 0, 0, 11},      // 3 -> 11
        {VmOpcode::MovImm, 8, 0, 0, 3},       // 4: R8 = 3
        {VmOpcode::Mul,    9, 2, 8, 0},       // 5: R9 = i * 3
        {VmOpcode::Add,    3, 3, 9, 0},       // 6: acc += i * 3
        {VmOpcode::MovImm, 8, 0, 0, 1},       // 7: R8 = 1
        {VmOpcode::Add,    3, 3, 8, 0},       // 8: acc += 1
        {VmOpcode::Add,    2, 2, 8, 0},       // 9: i += 1
        {VmOpcode::Jmp,    0, 0, 0, 2},       // 10 -> 2
        {VmOpcode::MovReg, 0, 3, 0, 0},       // 11: R0 = acc
        {VmOpcode::Ret,    0, 0, 0, 0},       // 12
    };

    SharedRuntimeOptions eager_opts;
    eager_opts.encrypt_bytecode = true;
    eager_opts.lazy_bytecode = false;
    eager_opts.seed = 0xDEADBEEF14ULL;

    SharedRuntimeOptions lazy_opts = eager_opts;
    lazy_opts.lazy_bytecode = true;

    SharedRuntimeLayout lay_eager, lay_lazy;
    auto rt_eager = emit_shared_pic_x64_vm_runtime({prog}, abi, lay_eager, eager_opts);
    auto rt_lazy = emit_shared_pic_x64_vm_runtime({prog}, abi, lay_lazy, lazy_opts);
    ASSERT_TRUE(rt_eager.has_value());
    ASSERT_TRUE(rt_lazy.has_value());
    ASSERT_EQ(lay_lazy.entry_offsets.size(), 1u);

#if (defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))) || (defined(__linux__) && defined(__x86_64__))
    auto exec_pic = [](const std::vector<std::uint8_t>& code, std::size_t off, std::uint64_t arg) -> std::uint64_t {
#ifdef _WIN32
        void* mem = VirtualAlloc(nullptr, code.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        EXPECT_NE(mem, nullptr);
        std::memcpy(mem, code.data(), code.size());
        DWORD old_p = 0;
        EXPECT_TRUE(VirtualProtect(mem, code.size(), PAGE_EXECUTE_READ, &old_p));
        using Fn = std::uint64_t (*)(std::uint64_t);
        const std::uint64_t r = reinterpret_cast<Fn>(static_cast<std::uint8_t*>(mem) + off)(arg);
        VirtualFree(mem, 0, MEM_RELEASE);
        return r;
#else
        void* mem = mmap(nullptr, code.size(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        EXPECT_NE(mem, MAP_FAILED);
        std::memcpy(mem, code.data(), code.size());
        EXPECT_EQ(mprotect(mem, code.size(), PROT_READ | PROT_EXEC), 0);
        using Fn = std::uint64_t (*)(std::uint64_t);
        const std::uint64_t r = reinterpret_cast<Fn>(static_cast<std::uint8_t*>(mem) + off)(arg);
        munmap(mem, code.size());
        return r;
#endif
    };

    for (const std::uint64_t n : {0ULL, 1ULL, 5ULL, 10ULL, 25ULL}) {
        VmExecOptions vopts;
        vopts.initial_regs[arg_reg] = n;
        auto vm_res = VmInterpreter::execute(prog, vopts);
        ASSERT_TRUE(vm_res.has_value());
        const std::uint64_t got_eager = exec_pic(rt_eager.value(), lay_eager.entry_offsets[0], n);
        const std::uint64_t got_lazy = exec_pic(rt_lazy.value(), lay_lazy.entry_offsets[0], n);
        EXPECT_EQ(got_eager, vm_res.value().return_value);
        EXPECT_EQ(got_lazy, vm_res.value().return_value);
    }
#endif
}

TEST(ProtectionV014Test, NativePicLazyTamperDetection) {
    using namespace bytemorph::virt;
    using namespace bytemorph::prot::detail;

    BvmProgram prog;
    prog.build_seed = 0x1402ULL;
    prog.instructions = {
        {VmOpcode::MovImm, 0, 0, 0, 777},
        {VmOpcode::Ret,    0, 0, 0, 0},
    };
#ifdef _WIN32
    constexpr AbiKind abi = AbiKind::Win64;
#else
    constexpr AbiKind abi = AbiKind::SysV_AMD64;
#endif
    SharedRuntimeOptions opts;
    opts.encrypt_bytecode = true;
    opts.lazy_bytecode = true;
    opts.seed = 0x7A39E2ULL;
    SharedRuntimeLayout layout;
    auto rt_res = emit_shared_pic_x64_vm_runtime({prog}, abi, layout, opts);
    ASSERT_TRUE(rt_res.has_value());
    auto tampered = rt_res.value();
    ASSERT_GT(tampered.size(), 16u);
    tampered[tampered.size() - 4] ^= 0xFFu;

#if (defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))) || (defined(__linux__) && defined(__x86_64__))
#ifdef _WIN32
    void* mem = VirtualAlloc(nullptr, tampered.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_NE(mem, nullptr);
    std::memcpy(mem, tampered.data(), tampered.size());
    DWORD old_p = 0;
    ASSERT_TRUE(VirtualProtect(mem, tampered.size(), PAGE_EXECUTE_READ, &old_p));
    using Fn = std::uint64_t (*)();
    const std::uint64_t r = reinterpret_cast<Fn>(static_cast<std::uint8_t*>(mem) + layout.entry_offsets[0])();
    VirtualFree(mem, 0, MEM_RELEASE);
#else
    void* mem = mmap(nullptr, tampered.size(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(mem, MAP_FAILED);
    std::memcpy(mem, tampered.data(), tampered.size());
    ASSERT_EQ(mprotect(mem, tampered.size(), PROT_READ | PROT_EXEC), 0);
    using Fn = std::uint64_t (*)();
    const std::uint64_t r = reinterpret_cast<Fn>(static_cast<std::uint8_t*>(mem) + layout.entry_offsets[0])();
    munmap(mem, tampered.size());
#endif
    EXPECT_EQ(r, 0xDEADAEADDEADAEADULL);
#endif
}

TEST(ProtectionV014Test, NativePicLazyArm64EmissionAndMultiFunction) {
    using namespace bytemorph::virt;
    using namespace bytemorph::prot::detail;

    BvmProgram p0, p1, p2;
    p0.instructions = {{VmOpcode::MovImm, 0, 0, 0, 11}, {VmOpcode::Ret, 0, 0, 0, 0}};
    p1.instructions = {
        {VmOpcode::Cmp, 0, 0, 0, 0},
        {VmOpcode::Jeq, 0, 0, 0, 3},
        {VmOpcode::MovImm, 0, 0, 0, 22},
        {VmOpcode::Ret, 0, 0, 0, 0},
    };
    p2.instructions = {{VmOpcode::Add, 0, 0, 1, 0}, {VmOpcode::Ret, 0, 0, 0, 0}};

    SharedRuntimeOptions opts;
    opts.encrypt_bytecode = true;
    opts.lazy_bytecode = true;
    opts.seed = 0xA64140ULL;

    SharedRuntimeLayout lay_lazy, lay_plain;
    auto rt_lazy = emit_shared_pic_arm64_vm_runtime({p0, p1, p2}, lay_lazy, opts);
    auto rt_plain = emit_shared_pic_arm64_vm_runtime({p0, p1, p2}, lay_plain, SharedRuntimeOptions{});
    ASSERT_TRUE(rt_lazy.has_value());
    ASSERT_TRUE(rt_plain.has_value());
    EXPECT_EQ(lay_lazy.entry_offsets.size(), 3u);
    EXPECT_EQ(rt_lazy.value().size() % 4, 0u);
    EXPECT_GT(rt_lazy.value().size(), rt_plain.value().size());
}

TEST(ProtectionV014Test, RealBinaryLazyExecutionWithProtectedRuntime) {
#if defined(_WIN32) && defined(BYTEMORPH_LAB_CPP_APP_PATH)
    const std::filesystem::path app_exe(BYTEMORPH_LAB_CPP_APP_PATH);
    if (!std::filesystem::exists(app_exe)) {
        GTEST_SKIP() << "lab_cpp_app not built";
    }
    const auto out_exe = std::filesystem::temp_directory_path() / "lab_cpp_app_v014_lazy.exe";
    bytemorph::prot::ProtectOptions opts;
    opts.profile = bytemorph::prot::ProtectionProfile::Balanced;
    opts.bytecode_mode = bytemorph::prot::BytecodeMode::Lazy;
    opts.encrypt_bytecode = true;
    opts.seed = 0x0140BEEFULL;

    auto prot_res = bytemorph::prot::ProtectionEngine::protect(app_exe, out_exe, opts);
    ASSERT_TRUE(prot_res.has_value()) << prot_res.error().to_string();
    EXPECT_EQ(prot_res.value().bytecode_mode, bytemorph::prot::BytecodeMode::Lazy);
    EXPECT_GT(prot_res.value().encrypted_blocks_count, 0u);

    auto ver_res = bytemorph::prot::ProtectionEngine::verify(out_exe);
    ASSERT_TRUE(ver_res.has_value()) << ver_res.error().to_string();
    EXPECT_TRUE(ver_res.value().valid);
    EXPECT_TRUE(ver_res.value().aead_authenticated);
    EXPECT_GT(ver_res.value().blocks_verified_count, 0u);

    auto run_capture = [](const std::filesystem::path& exe, int& rc) -> std::string {
        std::string cmd = "\"\"" + exe.string() + "\"\"";
        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) { rc = -1; return {}; }
        char buf[256];
        std::string out;
        while (std::fgets(buf, sizeof(buf), pipe)) out += buf;
        rc = _pclose(pipe);
        return out;
    };
    int rc_orig = -1, rc_prot = -1;
    const std::string out_orig = run_capture(app_exe, rc_orig);
    const std::string out_prot = run_capture(out_exe, rc_prot);
    EXPECT_EQ(rc_orig, 0);
    EXPECT_EQ(rc_prot, 0);
    EXPECT_EQ(out_orig, out_prot);

    std::error_code ec;
    std::filesystem::remove(out_exe, ec);
#endif
}
