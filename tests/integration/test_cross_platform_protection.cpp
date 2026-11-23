#include "bytemorph/arch/aarch64/aarch64_disasm.hpp"
#include "bytemorph/arch/aarch64/aarch64_lifter.hpp"
#include "bytemorph/arch/x86_64/x86_64_disasm.hpp"
#include "bytemorph/arch/x86_64/x86_64_lifter.hpp"
#include "bytemorph/core/analysis/analyzer.hpp"
#include "bytemorph/core/ir/ir.hpp"
#include "bytemorph/core/ir/ir_interpreter.hpp"
#include "bytemorph/obf/obfuscation_engine.hpp"
#include "bytemorph/prot/native_vm_emitter.hpp"
#include "bytemorph/prot/pe_rewriter.hpp"
#include "bytemorph/virt/ir_to_vm.hpp"
#include "bytemorph/virt/vm_interpreter.hpp"
#include "sample_builder.hpp"

#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

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
