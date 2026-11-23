#include "bytemorph/virt/asmjit_prototype.hpp"
#include "bytemorph/virt/bvm_format.hpp"
#include "bytemorph/virt/vm_interpreter.hpp"

#include <gtest/gtest.h>

using namespace bytemorph::virt;

TEST(VmTest, ExecutesArithmeticLogicalAndMemoryOps) {
    BvmProgram prog;
    prog.instructions = {
        {VmOpcode::MovImm, 1, 0, 0, 10},
        {VmOpcode::MovImm, 2, 0, 0, 3},
        {VmOpcode::Add, 3, 1, 2, 0},       // R3 = 13
        {VmOpcode::Sub, 4, 1, 2, 0},       // R4 = 7
        {VmOpcode::Mul, 5, 3, 4, 0},       // R5 = 91
        {VmOpcode::Div, 6, 5, 2, 0},       // R6 = 30
        {VmOpcode::MovImm, 7, 0, 0, 5},    // addr = 5
        {VmOpcode::Store, 7, 6, 0, 0},     // mem[5] = 30
        {VmOpcode::Load, 0, 7, 0, 0},      // R0 = mem[5] = 30
        {VmOpcode::Ret, 0, 0, 0, 0}
    };

    auto res = VmInterpreter::execute(prog);
    ASSERT_TRUE(res.has_value()) << res.error().to_string();
    EXPECT_EQ(res.value().return_value, 30ULL);
}

TEST(VmTest, ExecutesLoopsCallsAndReturns) {
    // Sum 1..5 using loop + helper call (pc=7)
    // 0: MovImm R1, 5 (counter)
    // 1: MovImm R0, 0 (sum)
    // 2: Call 7 (R0 = R0 + R1)
    // 3: MovImm R2, 1
    // 4: Sub R1, R1, R2
    // 5: Jne 2
    // 6: Ret
    // 7: Add R0, R0, R1
    // 8: Ret
    BvmProgram prog;
    prog.instructions = {
        {VmOpcode::MovImm, 1, 0, 0, 5},
        {VmOpcode::MovImm, 0, 0, 0, 0},
        {VmOpcode::Call, 0, 0, 0, 7},
        {VmOpcode::MovImm, 2, 0, 0, 1},
        {VmOpcode::Sub, 1, 1, 2, 0},
        {VmOpcode::Jne, 0, 0, 0, 2},
        {VmOpcode::Ret, 0, 0, 0, 0},
        {VmOpcode::Add, 0, 0, 1, 0},
        {VmOpcode::Ret, 0, 0, 0, 0}
    };

    auto res = VmInterpreter::execute(prog);
    ASSERT_TRUE(res.has_value()) << res.error().to_string();
    EXPECT_EQ(res.value().return_value, 15ULL);
}

TEST(VmTest, DiversificationWithDifferentSeedsAndRoundTrip) {
    BvmProgram p1, p2;
    p1.build_seed = 0x1111ULL;
    p2.build_seed = 0x2222ULL;
    p1.instructions = {{VmOpcode::MovImm, 0, 0, 0, 77}, {VmOpcode::Ret, 0, 0, 0, 0}};
    p2.instructions = p1.instructions;

    auto e1 = BvmCodec::encode(p1);
    auto e2 = BvmCodec::encode(p2);
    ASSERT_TRUE(e1.has_value() && e2.has_value());
    EXPECT_NE(e1.value(), e2.value());

    auto d1 = BvmCodec::decode(e1.value());
    auto d2 = BvmCodec::decode(e2.value());
    ASSERT_TRUE(d1.has_value() && d2.has_value());

    auto r1 = VmInterpreter::execute(d1.value());
    auto r2 = VmInterpreter::execute(d2.value());
    ASSERT_TRUE(r1.has_value() && r2.has_value());
    EXPECT_EQ(r1.value().return_value, 77ULL);
    EXPECT_EQ(r2.value().return_value, 77ULL);
}

TEST(VmTest, RejectsMalformedBytecodeAndEnforcesLimits) {
    EXPECT_FALSE(BvmCodec::decode({}).has_value());

    BvmProgram prog;
    prog.instructions = {{VmOpcode::MovImm, 0, 0, 0, 1}, {VmOpcode::Jmp, 0, 0, 0, 0}};
    auto enc = BvmCodec::encode(prog);
    ASSERT_TRUE(enc.has_value());

    // Corrupt checksum/payload
    auto bad = enc.value();
    bad.back() ^= 0x55;
    EXPECT_FALSE(BvmCodec::decode(bad).has_value());

    // Enforce max_steps on infinite loop
    VmExecOptions opts;
    opts.max_steps = 50;
    auto loop_res = VmInterpreter::execute(prog, opts);
    EXPECT_FALSE(loop_res.has_value());

    // Division by zero
    BvmProgram div0;
    div0.instructions = {{VmOpcode::MovImm, 1, 0, 0, 10}, {VmOpcode::MovImm, 2, 0, 0, 0}, {VmOpcode::Div, 0, 1, 2, 0}};
    EXPECT_FALSE(VmInterpreter::execute(div0).has_value());
}

TEST(VmTest, AsmJitPrototypeMatchesVmInterpreter) {
    auto res = AsmJitPrototype::run_arithmetic_comparison(42, 19, 100);
    ASSERT_TRUE(res.has_value()) << res.error().to_string();
    if (res.value().available) {
        EXPECT_EQ(res.value().native_result, res.value().vm_result);
    }
}
