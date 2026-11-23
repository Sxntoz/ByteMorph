#include "bytemorph/obf/obfuscation_engine.hpp"

#include <limits>
#include <random>

namespace bytemorph::obf {

using namespace bytemorph::core;
using namespace bytemorph::core::ir;

namespace {

std::size_t count_fn_instructions(const IrFunction& fn) noexcept {
    std::size_t total = 0;
    for (const auto& bb : fn.blocks) total += bb.instructions.size();
    return total;
}

bool is_reg(const IrOperand& op) noexcept {
    return op.kind == IrOperand::Kind::VirtualReg || op.kind == IrOperand::Kind::ArchReg;
}

std::uint64_t next_block_id(const IrFunction& fn) noexcept {
    std::uint64_t m = 0;
    for (const auto& bb : fn.blocks) {
        if (bb.id >= m) m = bb.id + 1;
    }
    return m;
}

std::uint64_t next_synthetic_va(const IrFunction& fn) noexcept {
    std::uint64_t m = 0x90000000ULL;
    for (const auto& bb : fn.blocks) {
        if (bb.start_va >= m) m = bb.start_va + 0x100;
    }
    return m;
}

} // namespace

diagnostics::Result<void> SemanticSubstitutionPass::run(IrFunction& fn) const {
    std::mt19937_64 rng(seed_ ^ fn.entry_va ^ 0x9E3779B97F4A7C15ULL);

    for (auto& bb : fn.blocks) {
        std::vector<IrInstruction> out;
        out.reserve(bb.instructions.size() * 2);

        for (std::size_t i = 0; i < bb.instructions.size(); ++i) {
            const auto& insn = bb.instructions[i];
            const bool next_uses_flags = (i + 1 < bb.instructions.size() &&
                                          bb.instructions[i + 1].opcode == IrOpcode::JumpCond);

            if (insn.opcode == IrOpcode::Mov && insn.dsts.size() == 1 && insn.srcs.size() == 1 &&
                is_reg(insn.dsts[0]) && insn.srcs[0].kind == IrOperand::Kind::Immediate &&
                insn.srcs[0].imm == 0 && !next_uses_flags) {
                // mov r, 0  ==>  xor r, r, r  OR  sub r, r, r
                IrInstruction rep;
                rep.source_va = insn.source_va;
                rep.opcode = (rng() & 1ULL) ? IrOpcode::Xor : IrOpcode::Sub;
                rep.dsts.push_back(insn.dsts[0]);
                rep.srcs.push_back(insn.dsts[0]);
                rep.srcs.push_back(insn.dsts[0]);
                rep.comment = "obf:subst_zero";
                out.push_back(std::move(rep));
                continue;
            }

            if (insn.opcode == IrOpcode::Add && insn.dsts.size() == 1 && insn.srcs.size() == 2 &&
                is_reg(insn.dsts[0]) && insn.srcs[1].kind == IrOperand::Kind::Immediate &&
                insn.srcs[1].imm != (std::numeric_limits<std::int64_t>::min)() && !next_uses_flags) {
                const std::int64_t k = static_cast<std::int64_t>((rng() & 0x7FFFULL) + 1ULL);
                const std::int64_t orig = insn.srcs[1].imm;
                // add dst, src0, orig  ==>  add dst, src0, k; add dst, dst, (orig - k)
                IrInstruction a1 = insn;
                a1.srcs[1] = IrOperand::immediate(k, insn.srcs[1].bit_width);
                a1.comment = "obf:split_add_1";
                IrInstruction a2;
                a2.source_va = insn.source_va;
                a2.opcode = IrOpcode::Add;
                a2.dsts.push_back(insn.dsts[0]);
                a2.srcs.push_back(insn.dsts[0]);
                a2.srcs.push_back(IrOperand::immediate(orig - k, insn.srcs[1].bit_width));
                a2.comment = "obf:split_add_2";
                out.push_back(std::move(a1));
                out.push_back(std::move(a2));
                continue;
            }

            if (insn.opcode == IrOpcode::Sub && insn.dsts.size() == 1 && insn.srcs.size() == 2 &&
                is_reg(insn.dsts[0]) && insn.srcs[1].kind == IrOperand::Kind::Immediate &&
                insn.srcs[1].imm != (std::numeric_limits<std::int64_t>::min)() && !next_uses_flags) {
                // sub dst, src0, imm ==> add dst, src0, -imm
                IrInstruction rep = insn;
                rep.opcode = IrOpcode::Add;
                rep.srcs[1] = IrOperand::immediate(-insn.srcs[1].imm, insn.srcs[1].bit_width);
                rep.comment = "obf:sub_to_add";
                out.push_back(std::move(rep));
                continue;
            }

            out.push_back(insn);
        }

        bb.instructions = std::move(out);
    }
    return diagnostics::Result<void>::ok();
}

diagnostics::Result<void> ArithmeticBooleanMbaPass::run(IrFunction& fn) const {
    std::mt19937_64 rng(seed_ ^ fn.entry_va ^ 0xBF58476D1CE4E5B9ULL);

    for (auto& bb : fn.blocks) {
        std::vector<IrInstruction> out;
        out.reserve(bb.instructions.size() * 3);

        for (std::size_t i = 0; i < bb.instructions.size(); ++i) {
            const auto& insn = bb.instructions[i];
            const bool next_uses_flags = (i + 1 < bb.instructions.size() &&
                                          bb.instructions[i + 1].opcode == IrOpcode::JumpCond);
            if (next_uses_flags || insn.dsts.size() != 1 || !is_reg(insn.dsts[0]) || insn.srcs.size() != 2) {
                out.push_back(insn);
                continue;
            }

            if (insn.opcode == IrOpcode::Add && (rng() % 2 == 0)) {
                // MBA identity: x + y == (x | y) + (x & y)
                auto t0 = IrOperand::vreg("__mba_t0", 64);
                auto t1 = IrOperand::vreg("__mba_t1", 64);

                IrInstruction i_or{insn.source_va, IrOpcode::Or, {t0}, {insn.srcs[0], insn.srcs[1]}, {}, "obf:mba_add_or"};
                IrInstruction i_and{insn.source_va, IrOpcode::And, {t1}, {insn.srcs[0], insn.srcs[1]}, {}, "obf:mba_add_and"};
                IrInstruction i_add{insn.source_va, IrOpcode::Add, {insn.dsts[0]}, {t0, t1}, {}, "obf:mba_add_fin"};
                out.push_back(std::move(i_or));
                out.push_back(std::move(i_and));
                out.push_back(std::move(i_add));
                continue;
            }

            if (insn.opcode == IrOpcode::Xor && (rng() % 2 == 0)) {
                // MBA identity: x ^ y == (x | y) - (x & y)
                auto t0 = IrOperand::vreg("__mba_t0", 64);
                auto t1 = IrOperand::vreg("__mba_t1", 64);

                IrInstruction i_or{insn.source_va, IrOpcode::Or, {t0}, {insn.srcs[0], insn.srcs[1]}, {}, "obf:mba_xor_or"};
                IrInstruction i_and{insn.source_va, IrOpcode::And, {t1}, {insn.srcs[0], insn.srcs[1]}, {}, "obf:mba_xor_and"};
                IrInstruction i_sub{insn.source_va, IrOpcode::Sub, {insn.dsts[0]}, {t0, t1}, {}, "obf:mba_xor_fin"};
                out.push_back(std::move(i_or));
                out.push_back(std::move(i_and));
                out.push_back(std::move(i_sub));
                continue;
            }

            out.push_back(insn);
        }

        bb.instructions = std::move(out);
    }
    return diagnostics::Result<void>::ok();
}

diagnostics::Result<void> ControlFlowObfuscationPass::run(IrFunction& fn) const {
    if (fn.blocks.empty()) {
        return diagnostics::Result<void>::ok();
    }

    std::mt19937_64 rng(seed_ ^ fn.entry_va ^ 0x94D049BB133111EBULL);
    // Split the first block if it has >= 2 non-branch instructions and insert an opaque-true trampoline
    auto& entry_bb = fn.blocks[0];
    if (entry_bb.instructions.size() < 2) {
        return diagnostics::Result<void>::ok();
    }

    const auto last_op = entry_bb.instructions.back().opcode;
    if (last_op == IrOpcode::JumpCond || last_op == IrOpcode::Cmp) {
        return diagnostics::Result<void>::ok();
    }

    const std::size_t split_idx = 1;
    const std::uint64_t cont_va = next_synthetic_va(fn);
    const std::uint64_t decoy_va = cont_va + 0x40;
    const std::uint64_t next_id = next_block_id(fn);

    IrBasicBlock cont_bb;
    cont_bb.id = next_id;
    cont_bb.start_va = cont_va;
    cont_bb.successors = entry_bb.successors;
    cont_bb.instructions.assign(entry_bb.instructions.begin() + static_cast<std::ptrdiff_t>(split_idx),
                                entry_bb.instructions.end());

    IrBasicBlock decoy_bb;
    decoy_bb.id = next_id + 1;
    decoy_bb.start_va = decoy_va;
    decoy_bb.instructions.push_back(IrInstruction{
        decoy_va, IrOpcode::Xor,
        {IrOperand::vreg("__obf_decoy", 64)},
        {IrOperand::vreg("__obf_decoy", 64), IrOperand::immediate(static_cast<std::int64_t>(rng() & 0xFFFFu), 64)},
        {}, "obf:opaque_decoy"
    });
    decoy_bb.instructions.push_back(IrInstruction{
        decoy_va + 4, IrOpcode::Jump, {}, {IrOperand::label(cont_va)}, {}, "obf:decoy_join"
    });
    decoy_bb.successors.push_back(cont_va);

    // Truncate entry_bb and append opaque predicate:
    // t = (seed | 1); t = t & 1; cmp t, 1; je cont_va (always true!)
    entry_bb.instructions.resize(split_idx);
    auto opq_reg = IrOperand::vreg("__obf_opq", 64);
    const std::int64_t odd_val = static_cast<std::int64_t>((rng() | 1ULL) & 0x7FFFULL);
    entry_bb.instructions.push_back(IrInstruction{
        entry_bb.start_va, IrOpcode::Mov, {opq_reg}, {IrOperand::immediate(odd_val, 64)}, {}, "obf:opaque_init"
    });
    entry_bb.instructions.push_back(IrInstruction{
        entry_bb.start_va, IrOpcode::And, {opq_reg}, {opq_reg, IrOperand::immediate(1, 64)}, {}, "obf:opaque_mask"
    });
    entry_bb.instructions.push_back(IrInstruction{
        entry_bb.start_va, IrOpcode::Cmp, {}, {opq_reg, IrOperand::immediate(1, 64)}, {}, "obf:opaque_cmp"
    });
    entry_bb.instructions.push_back(IrInstruction{
        entry_bb.start_va, IrOpcode::JumpCond, {}, {IrOperand::label(cont_va)}, "je", "obf:opaque_branch"
    });
    entry_bb.instructions.push_back(IrInstruction{
        entry_bb.start_va, IrOpcode::Jump, {}, {IrOperand::label(decoy_va)}, {}, "obf:opaque_fallthrough"
    });
    entry_bb.successors = {cont_va, decoy_va};

    fn.blocks.push_back(std::move(cont_bb));
    fn.blocks.push_back(std::move(decoy_bb));
    return diagnostics::Result<void>::ok();
}

diagnostics::Result<ObfuscationReport>
ObfuscationPipeline::obfuscate_function(IrFunction& fn, const ObfuscationConfig& config) {
    ObfuscationReport report;
    report.original_instructions = count_fn_instructions(fn);

    auto within_budget = [&]() -> bool {
        if (report.original_instructions == 0) return true;
        const double cur = static_cast<double>(count_fn_instructions(fn));
        return (cur / static_cast<double>(report.original_instructions)) <= config.max_expansion_factor;
    };

    if (config.enable_substitution && within_budget()) {
        SemanticSubstitutionPass pass(config.seed);
        auto res = pass.run(fn);
        if (!res) return diagnostics::Result<ObfuscationReport>::err(res.error().code, res.error().message, res.error().context);
        report.passes_applied.emplace_back(pass.name());
    }

    if (config.enable_mba && within_budget()) {
        ArithmeticBooleanMbaPass pass(config.seed);
        auto res = pass.run(fn);
        if (!res) return diagnostics::Result<ObfuscationReport>::err(res.error().code, res.error().message, res.error().context);
        report.passes_applied.emplace_back(pass.name());
    }

    if (config.enable_cfg && within_budget()) {
        ControlFlowObfuscationPass pass(config.seed);
        auto res = pass.run(fn);
        if (!res) return diagnostics::Result<ObfuscationReport>::err(res.error().code, res.error().message, res.error().context);
        report.passes_applied.emplace_back(pass.name());
    }

    report.obfuscated_instructions = count_fn_instructions(fn);
    report.expansion_ratio = report.original_instructions == 0
        ? 1.0
        : static_cast<double>(report.obfuscated_instructions) / static_cast<double>(report.original_instructions);
    return report;
}

diagnostics::Result<ObfuscationReport>
ObfuscationPipeline::obfuscate_module(IrModule& mod, const ObfuscationConfig& config) {
    ObfuscationReport total;
    for (auto& fn : mod.functions) {
        auto res = obfuscate_function(fn, config);
        if (!res) return res;
        total.original_instructions += res.value().original_instructions;
        total.obfuscated_instructions += res.value().obfuscated_instructions;
        if (total.passes_applied.empty()) {
            total.passes_applied = res.value().passes_applied;
        }
    }
    total.expansion_ratio = total.original_instructions == 0
        ? 1.0
        : static_cast<double>(total.obfuscated_instructions) / static_cast<double>(total.original_instructions);
    return total;
}

diagnostics::Result<bool>
EquivalenceValidator::verify(const IrFunction& original,
                             const IrFunction& obfuscated,
                             const std::vector<IrExecOptions>& test_cases) {
    for (const auto& opts : test_cases) {
        auto r1 = IrInterpreter::execute(original, opts);
        auto r2 = IrInterpreter::execute(obfuscated, opts);
        if (!r1) {
            return diagnostics::Result<bool>::err(r1.error().code, r1.error().message, "EquivalenceValidator::original");
        }
        if (!r2) {
            return diagnostics::Result<bool>::err(r2.error().code, r2.error().message, "EquivalenceValidator::obfuscated");
        }
        if (r1.value().return_value != r2.value().return_value) {
            return false;
        }
    }
    return true;
}

} // namespace bytemorph::obf
