#include "bytemorph/arch/aarch64/aarch64_disasm.hpp"
#include "bytemorph/arch/aarch64/aarch64_lifter.hpp"
#include "bytemorph/arch/x86_64/x86_64_disasm.hpp"
#include "bytemorph/arch/x86_64/x86_64_lifter.hpp"
#include "bytemorph/core/analysis/analyzer.hpp"
#include "bytemorph/core/binary/loader.hpp"
#include "bytemorph/formats/pe/pe_parser.hpp"
#include "bytemorph/core/ir/ir.hpp"
#include "bytemorph/core/ir/ir_interpreter.hpp"
#include "bytemorph/obf/obfuscation_engine.hpp"
#include "bytemorph/prot/native_vm_emitter.hpp"
#include "bytemorph/prot/pe_rewriter.hpp"
#include "bytemorph/virt/ir_to_vm.hpp"
#include "bytemorph/virt/vm_interpreter.hpp"
#include "sample_builder.hpp"

#include <gtest/gtest.h>

#include <atomic>
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

TEST(ProtectionV09Test, SmartEligibility3AcceptsGlobalsInLabPe) {
#ifdef BYTEMORPH_LAB_PE_TARGET_PATH
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
#ifdef BYTEMORPH_LAB_PE_TARGET_PATH
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
