#include "bytemorph/core/ir/ir_interpreter.hpp"
#include "bytemorph/obf/obfuscation_engine.hpp"
#include "bytemorph/virt/bvm_format.hpp"
#include "bytemorph/virt/ir_to_vm.hpp"
#include "bytemorph/virt/vm_interpreter.hpp"

#include <gtest/gtest.h>

using namespace bytemorph::core::ir;
using namespace bytemorph::obf;
using namespace bytemorph::virt;

TEST(IrToVmDifferentialTest, OriginalIrObfuscatedIrAndVmAgree) {
    // Function with loop: sum = 0; while (rcx > 0) { sum += rcx; rcx -= 1; } return sum in rax;
    IrFunction fn;
    fn.name = "sum_loop";
    fn.entry_va = 0x1000;

    auto rax = IrOperand::reg("rax");
    auto rcx = IrOperand::reg("rcx");

    IrBasicBlock bb0{0, 0x1000, {
        {0x1000, IrOpcode::Mov, {rax}, {IrOperand::immediate(0)}, {}, ""},
        {0x1004, IrOpcode::Cmp, {}, {rcx, IrOperand::immediate(0)}, {}, ""},
        {0x1008, IrOpcode::JumpCond, {}, {IrOperand::label(0x1020)}, "jle", ""},
    }, {0x1010, 0x1020}};

    IrBasicBlock bb1{1, 0x1010, {
        {0x1010, IrOpcode::Add, {rax}, {rax, rcx}, {}, ""},
        {0x1014, IrOpcode::Sub, {rcx}, {rcx, IrOperand::immediate(1)}, {}, ""},
        {0x1018, IrOpcode::Cmp, {}, {rcx, IrOperand::immediate(0)}, {}, ""},
        {0x101C, IrOpcode::JumpCond, {}, {IrOperand::label(0x1010)}, "jg", ""},
    }, {0x1010, 0x1020}};

    IrBasicBlock bb2{2, 0x1020, {
        {0x1020, IrOpcode::Ret, {}, {}, {}, ""}
    }, {}};

    fn.blocks = {bb0, bb1, bb2};

    IrFunction obf_fn = fn;
    ObfuscationConfig cfg;
    cfg.seed = 0xDEADBEEF1234ULL;
    ASSERT_TRUE(ObfuscationPipeline::obfuscate_function(obf_fn, cfg).has_value());

    auto vm_orig_res = IrToVmTranslator::translate(fn, 0x1234ULL);
    auto vm_obf_res = IrToVmTranslator::translate(obf_fn, 0x5678ULL);
    ASSERT_TRUE(vm_orig_res.has_value()) << vm_orig_res.error().to_string();
    ASSERT_TRUE(vm_obf_res.has_value()) << vm_obf_res.error().to_string();

    for (std::uint64_t n : {0ULL, 1ULL, 5ULL, 10ULL, 25ULL}) {
        IrExecOptions ir_opts;
        ir_opts.initial_regs["rcx"] = n;
        auto ir_orig_out = IrInterpreter::execute(fn, ir_opts);
        auto ir_obf_out = IrInterpreter::execute(obf_fn, ir_opts);
        ASSERT_TRUE(ir_orig_out.has_value() && ir_obf_out.has_value());

        VmExecOptions vm_opts;
        vm_opts.initial_regs[1] = n; // R1 = rcx
        auto vm_orig_out = VmInterpreter::execute(vm_orig_res.value(), vm_opts);
        auto vm_obf_out = VmInterpreter::execute(vm_obf_res.value(), vm_opts);
        ASSERT_TRUE(vm_orig_out.has_value() && vm_obf_out.has_value());

        const std::uint64_t expected = n * (n + 1) / 2;
        EXPECT_EQ(ir_orig_out.value().return_value, expected);
        EXPECT_EQ(ir_obf_out.value().return_value, expected);
        EXPECT_EQ(vm_orig_out.value().return_value, expected);
        EXPECT_EQ(vm_obf_out.value().return_value, expected);
    }
}

TEST(IrToVmDifferentialTest, RejectsUnsupportedIrOpcodesExplicitly) {
    IrFunction fn;
    fn.name = "bad_fn";
    fn.entry_va = 0x1000;
    fn.blocks = {{0, 0x1000, {{0x1000, IrOpcode::Syscall, {}, {}, {}, ""}}, {}}};

    auto res = IrToVmTranslator::translate(fn);
    ASSERT_FALSE(res.has_value());
    EXPECT_EQ(res.error().code, bytemorph::core::diagnostics::ErrorCode::UnsupportedFormat);
}
