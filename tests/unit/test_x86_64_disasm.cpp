#include "bytemorph/arch/x86_64/x86_64_disasm.hpp"
#include "bytemorph/core/analysis/cfg.hpp"
#include "sample_builder.hpp"

#include <gtest/gtest.h>

using namespace bytemorph::arch::x86_64;
using namespace bytemorph::core::analysis;

TEST(X86_64DisasmTest, DecodesControlFlowTargets) {
    X86_64Disassembler disasm;
    const auto code = bytemorph::tests::sample_x86_64_code();
    auto res = disasm.disassemble(code, 0x401000);
    ASSERT_TRUE(res.has_value());
    ASSERT_FALSE(res.value().empty());

    const auto& insns = res.value();
    EXPECT_EQ(insns[0].mnemonic, "call");
    EXPECT_EQ(insns[0].flow, ControlFlowKind::Call);
    ASSERT_TRUE(insns[0].branch_target.has_value());
    EXPECT_EQ(*insns[0].branch_target, 0x40100C);

    bool found_jcc = false;
    bool found_ret = false;
    for (const auto& i : insns) {
        if (i.flow == ControlFlowKind::ConditionalJump) found_jcc = true;
        if (i.flow == ControlFlowKind::Return) found_ret = true;
    }
    EXPECT_TRUE(found_jcc);
    EXPECT_TRUE(found_ret);
}

TEST(X86_64DisasmTest, HandlesInvalidBytesWithoutCrashing) {
    X86_64Disassembler disasm;
    const std::vector<std::uint8_t> bad = {0xFF, 0xFF, 0x90};
    auto res = disasm.disassemble(bad, 0x1000);
    ASSERT_TRUE(res.has_value());
    EXPECT_GE(res.value().size(), 1u);
}
