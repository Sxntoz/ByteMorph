#include "bytemorph/arch/aarch64/aarch64_disasm.hpp"
#include "bytemorph/arch/aarch64/aarch64_lifter.hpp"
#include "bytemorph/core/analysis/cfg.hpp"
#include "bytemorph/core/ir/ir.hpp"
#include "sample_builder.hpp"

#include <gtest/gtest.h>

using namespace bytemorph::arch::aarch64;
using namespace bytemorph::core::analysis;
using namespace bytemorph::core::ir;

TEST(AArch64DisasmTest, DecodesInstructionsAndControlFlow) {
    AArch64Disassembler disasm;
    const auto code = bytemorph::tests::sample_arm64_code();
    auto res = disasm.disassemble(code, 0x100001000ULL);
    ASSERT_TRUE(res.has_value()) << res.error().to_string();

    const auto& insns = res.value();
    ASSERT_EQ(insns.size(), 8u);

    EXPECT_EQ(insns[0].mnemonic, "mov");
    EXPECT_EQ(insns[1].mnemonic, "cmp");
    EXPECT_EQ(insns[2].flow, ControlFlowKind::ConditionalJump);
    ASSERT_TRUE(insns[2].branch_target.has_value());
    EXPECT_EQ(*insns[2].branch_target, 0x100001010ULL);

    EXPECT_EQ(insns[4].flow, ControlFlowKind::Call);
    ASSERT_TRUE(insns[4].branch_target.has_value());
    EXPECT_EQ(*insns[4].branch_target, 0x100001018ULL);

    EXPECT_EQ(insns[5].flow, ControlFlowKind::Return);
}

TEST(AArch64DisasmTest, LiftsAArch64InstructionsToIr) {
    AArch64Disassembler disasm;
    AArch64Lifter lifter;
    auto res = disasm.disassemble(bytemorph::tests::sample_arm64_code(), 0x100001000ULL);
    ASSERT_TRUE(res.has_value());

    const auto& insns = res.value();
    EXPECT_EQ(lifter.lift_instruction(insns[0]).opcode, IrOpcode::Mov);
    EXPECT_EQ(lifter.lift_instruction(insns[1]).opcode, IrOpcode::Cmp);
    EXPECT_EQ(lifter.lift_instruction(insns[2]).opcode, IrOpcode::JumpCond);
    EXPECT_EQ(lifter.lift_instruction(insns[3]).opcode, IrOpcode::Add);
    EXPECT_EQ(lifter.lift_instruction(insns[4]).opcode, IrOpcode::Call);
    EXPECT_EQ(lifter.lift_instruction(insns[5]).opcode, IrOpcode::Ret);
}

TEST(AArch64DisasmTest, HandlesInvalidBytesGracefully) {
    AArch64Disassembler disasm;
    const std::vector<std::uint8_t> bad = {0x00, 0x00, 0x00, 0x00, 0xC0, 0x03, 0x5F, 0xD6};
    auto res = disasm.disassemble(bad, 0x1000);
    ASSERT_TRUE(res.has_value());
    EXPECT_GE(res.value().size(), 2u);
}
