#include "bytemorph/core/ir/ir_interpreter.hpp"
#include "bytemorph/core/ir/ir_serializer.hpp"
#include "bytemorph/obf/obfuscation_engine.hpp"

#include <gtest/gtest.h>

using namespace bytemorph::core::ir;
using namespace bytemorph::obf;

namespace {

IrFunction make_sample_arith_fn() {
    IrFunction fn;
    fn.name = "arith_fn";
    fn.entry_va = 0x1000;

    IrBasicBlock bb;
    bb.id = 0;
    bb.start_va = 0x1000;
    auto rax = IrOperand::reg("rax");
    auto rcx = IrOperand::reg("rcx");
    auto rdx = IrOperand::reg("rdx");
    bb.instructions = {
        {0x1000, IrOpcode::Mov, {rax}, {IrOperand::immediate(0)}, {}, ""},
        {0x1004, IrOpcode::Add, {rax}, {rax, rcx}, {}, ""},
        {0x1008, IrOpcode::Add, {rax}, {rax, IrOperand::immediate(42)}, {}, ""},
        {0x100C, IrOpcode::Xor, {rax}, {rax, rdx}, {}, ""},
        {0x1010, IrOpcode::Sub, {rax}, {rax, IrOperand::immediate(7)}, {}, ""},
        {0x1014, IrOpcode::Ret, {}, {}, {}, ""}
    };
    fn.blocks.push_back(std::move(bb));
    return fn;
}

} // namespace

TEST(ObfuscationTest, PreservesSemanticEquivalenceAcrossPropertyInputs) {
    const auto orig = make_sample_arith_fn();
    auto obf = orig;

    ObfuscationConfig cfg;
    cfg.seed = 0x12345678ULL;
    auto rep = ObfuscationPipeline::obfuscate_function(obf, cfg);
    ASSERT_TRUE(rep.has_value()) << rep.error().to_string();
    EXPECT_GT(rep.value().obfuscated_instructions, rep.value().original_instructions);

    std::vector<IrExecOptions> cases;
    for (std::uint64_t a : {0ULL, 1ULL, 17ULL, 1000ULL, 0xCAFEBABEULL}) {
        for (std::uint64_t b : {0ULL, 3ULL, 99ULL, 0x1337ULL}) {
            IrExecOptions o;
            o.initial_regs["rcx"] = a;
            o.initial_regs["rdx"] = b;
            cases.push_back(std::move(o));
        }
    }

    auto eq = EquivalenceValidator::verify(orig, obf, cases);
    ASSERT_TRUE(eq.has_value()) << eq.error().to_string();
    EXPECT_TRUE(eq.value());
}

TEST(ObfuscationTest, DeterministicWithSameSeedAndDiversifiedWithDifferentSeeds) {
    const auto orig = make_sample_arith_fn();

    IrFunction obf_a1 = orig, obf_a2 = orig, obf_b = orig;
    ObfuscationConfig cfg_a{0xAAAA1111ULL};
    ObfuscationConfig cfg_b{0xBBBB2222ULL};

    ASSERT_TRUE(ObfuscationPipeline::obfuscate_function(obf_a1, cfg_a).has_value());
    ASSERT_TRUE(ObfuscationPipeline::obfuscate_function(obf_a2, cfg_a).has_value());
    ASSERT_TRUE(ObfuscationPipeline::obfuscate_function(obf_b, cfg_b).has_value());

    IrModule m1{"m", bytemorph::core::binary::Architecture::X86_64, {obf_a1}};
    IrModule m2{"m", bytemorph::core::binary::Architecture::X86_64, {obf_a2}};
    IrModule m3{"m", bytemorph::core::binary::Architecture::X86_64, {obf_b}};

    auto b1 = IrSerializer::serialize(m1);
    auto b2 = IrSerializer::serialize(m2);
    auto b3 = IrSerializer::serialize(m3);
    ASSERT_TRUE(b1.has_value() && b2.has_value() && b3.has_value());

    EXPECT_EQ(b1.value(), b2.value());
    EXPECT_NE(b1.value(), b3.value());
}

TEST(ObfuscationTest, IrSerializerRoundTripAndCorruptionDetection) {
    IrModule mod{"roundtrip", bytemorph::core::binary::Architecture::ARM64, {make_sample_arith_fn()}};
    auto bytes = IrSerializer::serialize(mod);
    ASSERT_TRUE(bytes.has_value());

    auto dec = IrSerializer::deserialize(bytes.value());
    ASSERT_TRUE(dec.has_value()) << dec.error().to_string();
    EXPECT_EQ(dec.value().name, "roundtrip");
    EXPECT_EQ(dec.value().functions.size(), 1u);

    auto corrupted = bytes.value();
    corrupted.back() ^= 0xFF;
    EXPECT_FALSE(IrSerializer::deserialize(corrupted).has_value());
}
