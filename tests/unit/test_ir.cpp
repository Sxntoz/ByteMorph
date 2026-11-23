#include "bytemorph/arch/x86_64/x86_64_disasm.hpp"
#include "bytemorph/arch/x86_64/x86_64_lifter.hpp"
#include "bytemorph/core/ir/ir.hpp"

#include <gtest/gtest.h>

using namespace bytemorph::core::ir;
using namespace bytemorph::arch::x86_64;

TEST(IrTest, FormatsOperandsAndInstructions) {
    IrInstruction insn;
    insn.source_va = 0x401000;
    insn.opcode = IrOpcode::Add;
    insn.dsts.push_back(IrOperand::vreg("t0", 64));
    insn.srcs.push_back(IrOperand::reg("rax", 64));
    insn.srcs.push_back(IrOperand::immediate(16, 64));

    const auto text = insn.to_string();
    EXPECT_NE(text.find("401000"), std::string::npos);
    EXPECT_NE(text.find("add"), std::string::npos);
    EXPECT_NE(text.find("%t0:i64"), std::string::npos);
    EXPECT_NE(text.find("$rax:i64"), std::string::npos);
}

TEST(IrTest, LiftsX86_64InstructionsToIr) {
    X86_64Disassembler disasm;
    X86_64Lifter lifter;

    // xor eax, eax; ret
    const std::vector<std::uint8_t> code = {0x31, 0xC0, 0xC3};
    auto res = disasm.disassemble(code, 0x401000);
    ASSERT_TRUE(res.has_value());
    ASSERT_EQ(res.value().size(), 2u);

    const auto ir0 = lifter.lift_instruction(res.value()[0]);
    const auto ir1 = lifter.lift_instruction(res.value()[1]);
    EXPECT_EQ(ir0.opcode, IrOpcode::Xor);
    EXPECT_EQ(ir1.opcode, IrOpcode::Ret);
}
