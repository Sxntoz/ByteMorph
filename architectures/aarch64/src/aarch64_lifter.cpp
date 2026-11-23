#include "bytemorph/arch/aarch64/aarch64_lifter.hpp"

#include <cctype>
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

[[nodiscard]] IrOperand parse_operand_text(const std::string& op) {
    if (op.empty()) {
        return IrOperand{};
    }
    if (op.find('[') != std::string::npos) {
        return IrOperand::memory(op, 64);
    }
    if (op[0] == '#') {
        try {
            std::size_t idx = 0;
            const std::int64_t val = std::stoll(op.substr(1), &idx, 0);
            if (idx > 0) {
                return IrOperand::immediate(val, 64);
            }
        } catch (...) {
        }
    }
    if (op.rfind("0x", 0) == 0 || std::isdigit(static_cast<unsigned char>(op[0]))) {
        try {
            std::size_t idx = 0;
            const std::int64_t val = std::stoll(op, &idx, 0);
            if (idx == op.size()) {
                return IrOperand::immediate(val, 64);
            }
        } catch (...) {
        }
    }
    return IrOperand::reg(op, 64);
}

} // namespace

IrInstruction AArch64Lifter::lift_instruction(const DisassembledInstruction& insn) const {
    IrInstruction ir;
    ir.source_va = insn.address;
    const auto ops = split_operands(insn.operands_text);

    if (insn.mnemonic == "nop") {
        ir.opcode = IrOpcode::Nop;
    } else if ((insn.mnemonic == "mov" || insn.mnemonic == "movz" || insn.mnemonic == "adr" || insn.mnemonic == "adrp") && ops.size() >= 2) {
        ir.opcode = IrOpcode::Mov;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if (insn.mnemonic == "add" && ops.size() == 4 && ops[1] == ops[2] && ops[3] == "lsl #1") {
        ir.opcode = IrOpcode::Mul;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(IrOperand::immediate(3, 64));
        ir.comment = "add_lsl1_mul3";
    } else if (insn.mnemonic == "add" && ops.size() >= 3) {
        ir.opcode = IrOpcode::Add;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(parse_operand_text(ops[2]));
    } else if (insn.mnemonic == "sub" && ops.size() >= 3) {
        ir.opcode = IrOpcode::Sub;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(parse_operand_text(ops[2]));
    } else if (insn.mnemonic == "and" && ops.size() >= 3) {
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
    } else if (insn.mnemonic == "lsr" && ops.size() >= 3) {
        ir.opcode = IrOpcode::Shr;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(parse_operand_text(ops[2]));
    } else if (insn.mnemonic == "cmp" && ops.size() >= 2) {
        ir.opcode = IrOpcode::Cmp;
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if ((insn.mnemonic == "ldr" || insn.mnemonic == "ldp") && ops.size() >= 2) {
        ir.opcode = IrOpcode::Load;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops.back()));
    } else if ((insn.mnemonic == "str" || insn.mnemonic == "stp") && ops.size() >= 2) {
        ir.opcode = IrOpcode::Store;
        ir.dsts.push_back(parse_operand_text(ops.back()));
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

    std::uint64_t bb_id = 0;
    for (const auto& bb : fn.blocks) {
        IrBasicBlock ir_bb;
        ir_bb.id = bb_id++;
        ir_bb.start_va = bb.start_va;
        ir_bb.successors = bb.successors;
        ir_bb.instructions.reserve(bb.instructions.size());
        for (const auto& insn : bb.instructions) {
            const auto ops = split_operands(insn.operands_text);
            const bool is_shift_alu =
                ops.size() == 4 &&
                (insn.mnemonic == "add" || insn.mnemonic == "sub" || insn.mnemonic == "and" ||
                 insn.mnemonic == "orr" || insn.mnemonic == "eor") &&
                !(insn.mnemonic == "add" && ops[1] == ops[2] && ops[3] == "lsl #1") &&
                (ops[3].rfind("lsl #", 0) == 0 || ops[3].rfind("lsr #", 0) == 0);
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
            } else {
                ir_bb.instructions.push_back(lift_instruction(insn));
            }
        }
        ir_fn.blocks.push_back(std::move(ir_bb));
    }

    return ir_fn;
}

} // namespace bytemorph::arch::aarch64
