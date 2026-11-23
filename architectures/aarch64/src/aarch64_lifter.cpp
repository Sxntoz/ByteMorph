#include "bytemorph/arch/aarch64/aarch64_lifter.hpp"

#include <cctype>
#include <string>
#include <vector>

namespace bytemorph::arch::aarch64 {

using namespace bytemorph::core::ir;
using namespace bytemorph::core::analysis;

namespace {

[[nodiscard]] std::vector<std::string> split_operands(const std::string& text) {
    std::vector<std::string> parts;
    std::string cur;
    int bracket_depth = 0;
    for (char ch : text) {
        if (ch == '[') ++bracket_depth;
        else if (ch == ']' && bracket_depth > 0) --bracket_depth;

        if (ch == ',' && bracket_depth == 0) {
            parts.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(ch);
        }
    }
    if (!cur.empty()) {
        parts.push_back(cur);
    }
    for (auto& p : parts) {
        const auto first = p.find_first_not_of(" \t");
        const auto last = p.find_last_not_of(" \t");
        if (first == std::string::npos) {
            p.clear();
        } else {
            p = p.substr(first, last - first + 1);
        }
    }
    return parts;
}

[[nodiscard]] bool try_parse_arm_imm(std::string s, std::int64_t& out) noexcept {
    if (!s.empty() && s[0] == '#') {
        s = s.substr(1);
    }
    if (s.empty()) return false;
    try {
        std::size_t idx = 0;
        const std::int64_t v = std::stoll(s, &idx, 0);
        if (idx == s.size()) {
            out = v;
            return true;
        }
    } catch (...) {
    }
    return false;
}

struct ParsedArm64Address {
    bool valid{false};
    std::string base_reg;
    std::string index_reg;
    std::int64_t lsl_amount{0};
    std::int64_t disp{0};
    bool pre_index{false};
};

[[nodiscard]] ParsedArm64Address parse_arm64_address(const std::string& op) {
    ParsedArm64Address res;
    const auto lbr = op.find('[');
    const auto rbr = op.find(']');
    if (lbr == std::string::npos || rbr == std::string::npos || rbr <= lbr + 1) {
        return res;
    }
    res.pre_index = (rbr + 1 < op.size() && op[rbr + 1] == '!');
    const std::string inside = op.substr(lbr + 1, rbr - lbr - 1);
    const auto tokens = split_operands(inside);
    if (tokens.empty() || tokens[0].empty()) return res;

    res.base_reg = tokens[0];
    if (tokens.size() >= 2) {
        std::int64_t imm_v = 0;
        if (try_parse_arm_imm(tokens[1], imm_v)) {
            res.disp = imm_v;
        } else {
            res.index_reg = tokens[1];
            if (tokens.size() >= 3) {
                if (tokens[2].rfind("lsl #", 0) == 0) {
                    std::int64_t sh = 0;
                    if (try_parse_arm_imm(tokens[2].substr(4), sh)) {
                        res.lsl_amount = sh;
                    }
                }
            }
        }
    }
    res.valid = !res.base_reg.empty();
    return res;
}

[[nodiscard]] std::uint8_t infer_arm64_mem_width(const std::string& mnemonic, const std::string& reg_op) noexcept {
    if (mnemonic.back() == 'b') return 8;
    if (mnemonic.back() == 'h') return 16;
    if (mnemonic == "ldrsw") return 32;
    if (!reg_op.empty() && reg_op[0] == 'w') return 32;
    return 64;
}

[[nodiscard]] IrOperand parse_operand_text(const std::string& op, std::uint8_t mem_width = 64) {
    if (op.empty()) {
        return IrOperand{};
    }
    if (op.find('[') != std::string::npos) {
        const auto addr = parse_arm64_address(op);
        if (addr.valid && addr.index_reg.empty()) {
            return IrOperand::memory_disp(addr.base_reg, addr.disp, mem_width);
        }
        return IrOperand::memory(op, mem_width);
    }
    std::int64_t imm_v = 0;
    if (try_parse_arm_imm(op, imm_v)) {
        return IrOperand::immediate(imm_v, 64);
    }
    return IrOperand::reg(op, 64);
}

} // namespace

IrInstruction AArch64Lifter::lift_instruction(const DisassembledInstruction& insn) const {
    IrInstruction ir;
    ir.source_va = insn.address;
    const auto ops = split_operands(insn.operands_text);

    if (insn.mnemonic == "nop" || insn.mnemonic == "bti" || insn.mnemonic == "hint" ||
        insn.mnemonic == "paciasp" || insn.mnemonic == "autiasp") {
        ir.opcode = IrOpcode::Nop;
    } else if ((insn.mnemonic == "mov" || insn.mnemonic == "movz" || insn.mnemonic == "sxtw" ||
                insn.mnemonic == "uxtw" || insn.mnemonic == "uxtb" || insn.mnemonic == "uxth" ||
                insn.mnemonic == "sxtb" || insn.mnemonic == "sxth" ||
                insn.mnemonic == "adr" || insn.mnemonic == "adrp") && ops.size() >= 2) {
        ir.opcode = IrOpcode::Mov;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if (insn.mnemonic == "neg" && ops.size() >= 2) {
        ir.opcode = IrOpcode::Sub;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(IrOperand::immediate(0, 64));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if ((insn.mnemonic == "add" || insn.mnemonic == "adds") && ops.size() == 4 && ops[1] == ops[2] && ops[3] == "lsl #1") {
        ir.opcode = IrOpcode::Mul;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(IrOperand::immediate(3, 64));
        ir.comment = "add_lsl1_mul3";
    } else if ((insn.mnemonic == "add" || insn.mnemonic == "adds") && ops.size() >= 3) {
        ir.opcode = IrOpcode::Add;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(parse_operand_text(ops[2]));
    } else if ((insn.mnemonic == "sub" || insn.mnemonic == "subs") && ops.size() >= 3) {
        ir.opcode = IrOpcode::Sub;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(parse_operand_text(ops[2]));
    } else if ((insn.mnemonic == "mul" || insn.mnemonic == "smull" || insn.mnemonic == "umull") && ops.size() >= 3) {
        ir.opcode = IrOpcode::Mul;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(parse_operand_text(ops[2]));
    } else if ((insn.mnemonic == "udiv" || insn.mnemonic == "sdiv") && ops.size() >= 3) {
        ir.opcode = IrOpcode::Div;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(parse_operand_text(ops[2]));
    } else if ((insn.mnemonic == "and" || insn.mnemonic == "ands") && ops.size() >= 3) {
        ir.opcode = IrOpcode::And;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(parse_operand_text(ops[2]));
    } else if (insn.mnemonic == "orr" && ops.size() >= 3) {
        ir.opcode = IrOpcode::Or;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(parse_operand_text(ops[2]));
    } else if (insn.mnemonic == "eor" && ops.size() >= 3) {
        ir.opcode = IrOpcode::Xor;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(parse_operand_text(ops[2]));
    } else if (insn.mnemonic == "lsl" && ops.size() >= 3) {
        ir.opcode = IrOpcode::Shl;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(parse_operand_text(ops[2]));
    } else if ((insn.mnemonic == "lsr" || insn.mnemonic == "asr") && ops.size() >= 3) {
        ir.opcode = IrOpcode::Shr;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(parse_operand_text(ops[2]));
    } else if (insn.mnemonic == "cmp" && ops.size() >= 2) {
        ir.opcode = IrOpcode::Cmp;
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if (insn.mnemonic == "tst" && ops.size() >= 2) {
        ir.opcode = IrOpcode::And;
        ir.dsts.push_back(IrOperand::reg("__bm_test_tmp", 64));
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if ((insn.mnemonic == "ldr" || insn.mnemonic == "ldur" || insn.mnemonic == "ldrb" ||
                insn.mnemonic == "ldrh" || insn.mnemonic == "ldrsb" || insn.mnemonic == "ldrsh" ||
                insn.mnemonic == "ldrsw" || insn.mnemonic == "ldp") && ops.size() >= 2) {
        const std::uint8_t w = infer_arm64_mem_width(insn.mnemonic, ops[0]);
        ir.opcode = IrOpcode::Load;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1].find('[') != std::string::npos ? ops[1] : ops.back(), w));
    } else if ((insn.mnemonic == "str" || insn.mnemonic == "stur" || insn.mnemonic == "strb" ||
                insn.mnemonic == "strh" || insn.mnemonic == "stp") && ops.size() >= 2) {
        const std::uint8_t w = infer_arm64_mem_width(insn.mnemonic, ops[0]);
        ir.opcode = IrOpcode::Store;
        ir.dsts.push_back(parse_operand_text(ops[1].find('[') != std::string::npos ? ops[1] : ops.back(), w));
        ir.srcs.push_back(parse_operand_text(ops[0]));
    } else if (insn.flow == ControlFlowKind::UnconditionalJump) {
        ir.opcode = IrOpcode::Jump;
        if (insn.branch_target) {
            ir.srcs.push_back(IrOperand::label(*insn.branch_target));
        } else if (!ops.empty()) {
            ir.srcs.push_back(parse_operand_text(ops[0]));
        }
    } else if (insn.flow == ControlFlowKind::ConditionalJump) {
        ir.opcode = IrOpcode::JumpCond;
        if (insn.branch_target) {
            ir.srcs.push_back(IrOperand::label(*insn.branch_target));
        } else if (!ops.empty()) {
            ir.srcs.push_back(parse_operand_text(ops.back()));
        }
        ir.comment = insn.mnemonic;
    } else if (insn.flow == ControlFlowKind::Call) {
        ir.opcode = IrOpcode::Call;
        if (insn.branch_target) {
            ir.srcs.push_back(IrOperand::label(*insn.branch_target));
        } else if (!ops.empty()) {
            ir.srcs.push_back(parse_operand_text(ops[0]));
        }
    } else if (insn.flow == ControlFlowKind::Return) {
        ir.opcode = IrOpcode::Ret;
    } else if (insn.mnemonic == "svc") {
        ir.opcode = IrOpcode::Syscall;
    } else {
        ir.opcode = IrOpcode::Unknown;
        ir.comment = insn.full_text;
    }

    return ir;
}

IrFunction AArch64Lifter::lift_function(const FunctionInfo& fn) const {
    IrFunction ir_fn;
    ir_fn.name = fn.name;
    ir_fn.entry_va = fn.entry_va;

    const auto idx_tmp = IrOperand::reg("__bm_idx_tmp", 64);
    const auto addr_tmp = IrOperand::reg("__bm_addr_tmp", 64);
    const auto mul_tmp = IrOperand::reg("__bm_mul_tmp", 64);

    auto materialize_arm_mem = [&](std::uint64_t va, IrOperand& op, std::vector<IrInstruction>& out) {
        if (op.kind != IrOperand::Kind::Memory || op.name.find('[') == std::string::npos) {
            return;
        }
        const auto addr = parse_arm64_address(op.name);
        if (!addr.valid) return;
        if (addr.index_reg.empty()) {
            op = IrOperand::memory_disp(addr.base_reg, addr.disp, op.bit_width);
            return;
        }
        if (addr.lsl_amount > 0) {
            out.push_back(IrInstruction{
                va, IrOpcode::Shl, {idx_tmp}, {IrOperand::reg(addr.index_reg, 64), IrOperand::immediate(addr.lsl_amount, 64)}, {}, "arm_idx_shl"});
            out.push_back(IrInstruction{
                va, IrOpcode::Add, {addr_tmp}, {IrOperand::reg(addr.base_reg, 64), idx_tmp}, {}, "arm_idx_add"});
        } else {
            out.push_back(IrInstruction{
                va, IrOpcode::Add, {addr_tmp}, {IrOperand::reg(addr.base_reg, 64), IrOperand::reg(addr.index_reg, 64)}, {}, "arm_idx_add"});
        }
        op = IrOperand::memory_disp("__bm_addr_tmp", 0, op.bit_width);
    };

    std::uint64_t bb_id = 0;
    for (const auto& bb : fn.blocks) {
        IrBasicBlock ir_bb;
        ir_bb.id = bb_id++;
        ir_bb.start_va = bb.start_va;
        ir_bb.successors = bb.successors;
        ir_bb.instructions.reserve(bb.instructions.size() * 2);
        for (const auto& insn : bb.instructions) {
            const auto ops = split_operands(insn.operands_text);

            // cbz / cbnz rn, label
            if ((insn.mnemonic == "cbz" || insn.mnemonic == "cbnz") && !ops.empty()) {
                ir_bb.instructions.push_back(IrInstruction{
                    insn.address, IrOpcode::Cmp, {}, {parse_operand_text(ops[0]), IrOperand::immediate(0, 64)}, {}, "cbz_cmp"});
                IrInstruction jc;
                jc.source_va = insn.address;
                jc.opcode = IrOpcode::JumpCond;
                if (insn.branch_target) {
                    jc.srcs.push_back(IrOperand::label(*insn.branch_target));
                } else {
                    jc.srcs.push_back(parse_operand_text(ops.back()));
                }
                jc.cond = (insn.mnemonic == "cbz") ? "b.eq" : "b.ne";
                jc.comment = jc.cond;
                ir_bb.instructions.push_back(std::move(jc));
                continue;
            }

            // madd / msub rd, rn, rm, ra -> rd = ra +/- (rn * rm)
            if ((insn.mnemonic == "madd" || insn.mnemonic == "msub") && ops.size() == 4) {
                ir_bb.instructions.push_back(IrInstruction{
                    insn.address, IrOpcode::Mul, {mul_tmp}, {parse_operand_text(ops[1]), parse_operand_text(ops[2])}, {}, "madd_mul"});
                ir_bb.instructions.push_back(IrInstruction{
                    insn.address,
                    (insn.mnemonic == "madd") ? IrOpcode::Add : IrOpcode::Sub,
                    {parse_operand_text(ops[0])},
                    {parse_operand_text(ops[3]), mul_tmp},
                    {},
                    insn.mnemonic});
                continue;
            }

            // stp / ldp r1, r2, [base, #disp](!) or [base], #post_disp
            if ((insn.mnemonic == "stp" || insn.mnemonic == "ldp") && ops.size() >= 3) {
                const auto addr = parse_arm64_address(ops[2]);
                if (addr.valid && addr.index_reg.empty()) {
                    const std::uint8_t w = (!ops[0].empty() && ops[0][0] == 'w') ? 32 : 64;
                    const std::int64_t step = (w == 32) ? 4 : 8;
                    const auto base_reg_op = IrOperand::reg(addr.base_reg, 64);

                    if (addr.pre_index && addr.disp != 0) {
                        ir_bb.instructions.push_back(IrInstruction{
                            insn.address, IrOpcode::Add, {base_reg_op}, {base_reg_op, IrOperand::immediate(addr.disp, 64)}, {}, "pair_pre"});
                    }
                    const std::int64_t eff_disp = addr.pre_index ? 0 : addr.disp;
                    if (insn.mnemonic == "stp") {
                        ir_bb.instructions.push_back(IrInstruction{
                            insn.address, IrOpcode::Store, {IrOperand::memory_disp(addr.base_reg, eff_disp, w)}, {parse_operand_text(ops[0])}, {}, "stp_0"});
                        ir_bb.instructions.push_back(IrInstruction{
                            insn.address, IrOpcode::Store, {IrOperand::memory_disp(addr.base_reg, eff_disp + step, w)}, {parse_operand_text(ops[1])}, {}, "stp_1"});
                    } else {
                        ir_bb.instructions.push_back(IrInstruction{
                            insn.address, IrOpcode::Load, {parse_operand_text(ops[0])}, {IrOperand::memory_disp(addr.base_reg, eff_disp, w)}, {}, "ldp_0"});
                        ir_bb.instructions.push_back(IrInstruction{
                            insn.address, IrOpcode::Load, {parse_operand_text(ops[1])}, {IrOperand::memory_disp(addr.base_reg, eff_disp + step, w)}, {}, "ldp_1"});
                    }
                    if (!addr.pre_index && ops.size() == 4) {
                        std::int64_t post_imm = 0;
                        if (try_parse_arm_imm(ops[3], post_imm) && post_imm != 0) {
                            ir_bb.instructions.push_back(IrInstruction{
                                insn.address, IrOpcode::Add, {base_reg_op}, {base_reg_op, IrOperand::immediate(post_imm, 64)}, {}, "pair_post"});
                        }
                    }
                    continue;
                }
            }

            const bool is_shift_alu =
                ops.size() == 4 &&
                (insn.mnemonic == "add" || insn.mnemonic == "adds" || insn.mnemonic == "sub" || insn.mnemonic == "subs" ||
                 insn.mnemonic == "and" || insn.mnemonic == "ands" || insn.mnemonic == "orr" || insn.mnemonic == "eor") &&
                !((insn.mnemonic == "add" || insn.mnemonic == "adds") && ops[1] == ops[2] && ops[3] == "lsl #1") &&
                (ops[3].rfind("lsl #", 0) == 0 || ops[3].rfind("lsr #", 0) == 0 || ops[3].rfind("asr #", 0) == 0);
            if (is_shift_alu) {
                const bool is_lsl = ops[3].rfind("lsl #", 0) == 0;
                const auto shift_amt = parse_operand_text(ops[3].substr(4));
                const auto tmp = IrOperand::reg("__bm_shift_tmp", 64);

                IrInstruction sh;
                sh.source_va = insn.address;
                sh.opcode = is_lsl ? IrOpcode::Shl : IrOpcode::Shr;
                sh.dsts.push_back(tmp);
                sh.srcs.push_back(parse_operand_text(ops[2]));
                sh.srcs.push_back(shift_amt);
                ir_bb.instructions.push_back(std::move(sh));

                IrInstruction alu = lift_instruction(insn);
                if (alu.srcs.size() >= 2) {
                    alu.srcs[1] = tmp;
                }
                ir_bb.instructions.push_back(std::move(alu));
                continue;
            }

            IrInstruction lifted = lift_instruction(insn);
            for (auto& s : lifted.srcs) {
                materialize_arm_mem(insn.address, s, ir_bb.instructions);
            }
            for (auto& d : lifted.dsts) {
                materialize_arm_mem(insn.address, d, ir_bb.instructions);
            }
            ir_bb.instructions.push_back(std::move(lifted));
        }
        ir_fn.blocks.push_back(std::move(ir_bb));
    }

    return ir_fn;
}

} // namespace bytemorph::arch::aarch64
