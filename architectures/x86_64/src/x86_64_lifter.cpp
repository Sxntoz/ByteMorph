#include "bytemorph/arch/x86_64/x86_64_lifter.hpp"

#include <cctype>
#include <sstream>
#include <vector>

namespace bytemorph::arch::x86_64 {

using namespace bytemorph::core;
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
    if (op.rfind("0x", 0) == 0 || op.rfind("-0x", 0) == 0 || std::isdigit(static_cast<unsigned char>(op[0]))) {
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

IrInstruction X86_64Lifter::lift_instruction(const DisassembledInstruction& insn) const {
    IrInstruction ir;
    ir.source_va = insn.address;
    const auto ops = split_operands(insn.operands_text);

    if (insn.mnemonic == "nop" || insn.mnemonic == "endbr64" || insn.mnemonic == "endbr32") {
        ir.opcode = IrOpcode::Nop;
    } else if (insn.mnemonic == "mov" && ops.size() == 2) {
        ir.opcode = IrOpcode::Mov;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if (insn.mnemonic == "lea" && ops.size() == 2) {
        const auto dst = parse_operand_text(ops[0]);
        std::string expr = ops[1];
        const auto lbr = expr.find('[');
        const auto rbr = expr.find(']');
        if (lbr != std::string::npos && rbr != std::string::npos && rbr > lbr + 1) {
            expr = expr.substr(lbr + 1, rbr - lbr - 1);
            // Strip spaces
            std::string clean;
            for (char c : expr) {
                if (c != ' ') clean.push_back(c);
            }
            const auto plus = clean.find('+');
            const auto minus = clean.find('-');
            if (plus != std::string::npos) {
                const std::string lhs = clean.substr(0, plus);
                const std::string rhs = clean.substr(plus + 1);
                const auto star = rhs.find('*');
                std::string rhs_clean = rhs;
                if (star != std::string::npos) {
                    const std::string idx = rhs.substr(0, star);
                    const std::string scale_s = rhs.substr(star + 1);
                    if (lhs == idx && scale_s == "2") {
                        ir.opcode = IrOpcode::Mul;
                        ir.dsts.push_back(dst);
                        ir.srcs.push_back(IrOperand::reg(lhs, 64));
                        ir.srcs.push_back(IrOperand::immediate(3, 64));
                        ir.comment = "lea*3";
                        return ir;
                    }
                    if (scale_s == "1") {
                        rhs_clean = idx;
                    }
                }
                ir.opcode = IrOpcode::Add;
                ir.dsts.push_back(dst);
                ir.srcs.push_back(parse_operand_text(lhs));
                ir.srcs.push_back(parse_operand_text(rhs_clean));
                ir.comment = "lea+";
                return ir;
            }
            if (minus != std::string::npos) {
                const std::string lhs = clean.substr(0, minus);
                const std::string rhs = clean.substr(minus + 1);
                ir.opcode = IrOpcode::Sub;
                ir.dsts.push_back(dst);
                ir.srcs.push_back(parse_operand_text(lhs));
                ir.srcs.push_back(parse_operand_text(rhs));
                ir.comment = "lea-";
                return ir;
            }
        }
        ir.opcode = IrOpcode::Mov;
        ir.dsts.push_back(dst);
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.comment = "lea";
    } else if (insn.mnemonic == "add" && ops.size() == 2) {
        ir.opcode = IrOpcode::Add;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if (insn.mnemonic == "sub" && ops.size() == 2) {
        ir.opcode = IrOpcode::Sub;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if (insn.mnemonic == "xor" && ops.size() == 2) {
        ir.opcode = IrOpcode::Xor;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if (insn.mnemonic == "and" && ops.size() == 2) {
        ir.opcode = IrOpcode::And;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if (insn.mnemonic == "or" && ops.size() == 2) {
        ir.opcode = IrOpcode::Or;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if (insn.mnemonic == "imul" && ops.size() == 2) {
        ir.opcode = IrOpcode::Mul;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if (insn.mnemonic == "imul" && ops.size() == 3) {
        ir.opcode = IrOpcode::Mul;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(parse_operand_text(ops[2]));
    } else if (insn.mnemonic == "shl" && ops.size() == 2) {
        ir.opcode = IrOpcode::Shl;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if (insn.mnemonic == "shr" && ops.size() == 2) {
        ir.opcode = IrOpcode::Shr;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if (insn.mnemonic == "cmp" && ops.size() == 2) {
        ir.opcode = IrOpcode::Cmp;
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if (insn.mnemonic == "push" && ops.size() == 1) {
        ir.opcode = IrOpcode::Store;
        ir.dsts.push_back(IrOperand::memory("rsp", 64));
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.comment = "push";
    } else if (insn.mnemonic == "pop" && ops.size() == 1) {
        ir.opcode = IrOpcode::Load;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(IrOperand::memory("rsp", 64));
        ir.comment = "pop";
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
            ir.srcs.push_back(parse_operand_text(ops[0]));
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
    } else if (insn.mnemonic == "syscall") {
        ir.opcode = IrOpcode::Syscall;
    } else {
        ir.opcode = IrOpcode::Unknown;
        ir.comment = insn.full_text;
    }

    return ir;
}

IrFunction X86_64Lifter::lift_function(const FunctionInfo& fn) const {
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
            ir_bb.instructions.push_back(lift_instruction(insn));
        }
        ir_fn.blocks.push_back(std::move(ir_bb));
    }

    return ir_fn;
}

} // namespace bytemorph::arch::x86_64
