#include "bytemorph/arch/x86_64/x86_64_lifter.hpp"

#include <cctype>
#include <sstream>
#include <string>
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

struct ParsedX86Address {
    bool valid{false};
    std::uint8_t width{64};
    std::string base_reg;
    std::string index_reg;
    std::int64_t scale{1};
    std::int64_t disp{0};
};

[[nodiscard]] bool try_parse_int64(const std::string& s, std::int64_t& out) noexcept {
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

[[nodiscard]] ParsedX86Address parse_x86_address(const std::string& op) {
    ParsedX86Address res;
    const auto lbr = op.find('[');
    const auto rbr = op.find(']');
    if (lbr == std::string::npos || rbr == std::string::npos || rbr <= lbr + 1) {
        return res;
    }

    const std::string prefix = op.substr(0, lbr);
    if (prefix.find("byte") != std::string::npos) res.width = 8;
    else if (prefix.find("dword") != std::string::npos) res.width = 32;
    else if (prefix.find("qword") != std::string::npos) res.width = 64;
    else if (prefix.find("word") != std::string::npos) res.width = 16;

    std::string clean;
    for (std::size_t i = lbr + 1; i < rbr; ++i) {
        if (!std::isspace(static_cast<unsigned char>(op[i]))) {
            clean.push_back(op[i]);
        }
    }
    if (clean.empty()) return res;

    // Split into signed tokens (+term or -term)
    std::size_t pos = 0;
    while (pos < clean.size()) {
        int sign = 1;
        if (clean[pos] == '+') {
            sign = 1;
            ++pos;
        } else if (clean[pos] == '-') {
            sign = -1;
            ++pos;
        }
        const std::size_t next_plus = clean.find('+', pos);
        const std::size_t next_minus = clean.find('-', pos);
        const std::size_t next_sep = std::min(next_plus, next_minus);
        const std::string term = (next_sep == std::string::npos) ? clean.substr(pos) : clean.substr(pos, next_sep - pos);
        pos = (next_sep == std::string::npos) ? clean.size() : next_sep;
        if (term.empty()) continue;

        std::int64_t imm_val = 0;
        if (try_parse_int64(term, imm_val)) {
            res.disp += sign * imm_val;
            continue;
        }

        const auto star = term.find('*');
        if (star != std::string::npos) {
            const std::string lhs = term.substr(0, star);
            const std::string rhs = term.substr(star + 1);
            std::int64_t sc = 1;
            if (try_parse_int64(rhs, sc)) {
                if (sc == 1 && res.base_reg.empty() && sign == 1) {
                    res.base_reg = lhs;
                } else {
                    res.index_reg = lhs;
                    res.scale = sign * sc;
                }
            } else if (try_parse_int64(lhs, sc)) {
                res.index_reg = rhs;
                res.scale = sign * sc;
            }
            continue;
        }

        if (sign == -1) {
            res.index_reg = term;
            res.scale = -1;
        } else if (res.base_reg.empty()) {
            res.base_reg = term;
        } else if (res.index_reg.empty()) {
            res.index_reg = term;
            res.scale = 1;
        } else {
            return ParsedX86Address{};
        }
    }

    if (res.base_reg == "rip" || res.index_reg == "rip") {
        return ParsedX86Address{};
    }
    res.valid = (!res.base_reg.empty() || !res.index_reg.empty());
    return res;
}

[[nodiscard]] IrOperand parse_operand_text(const std::string& op) {
    if (op.empty()) {
        return IrOperand{};
    }
    if (op.find('[') != std::string::npos) {
        const auto parsed = parse_x86_address(op);
        if (parsed.valid && parsed.index_reg.empty() && !parsed.base_reg.empty()) {
            return IrOperand::memory_disp(parsed.base_reg, parsed.disp, parsed.width);
        }
        return IrOperand::memory(op, parsed.width);
    }
    std::int64_t imm_val = 0;
    if (try_parse_int64(op, imm_val)) {
        return IrOperand::immediate(imm_val, 64);
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
    } else if (insn.mnemonic == "cdqe" || insn.mnemonic == "cltq") {
        ir.opcode = IrOpcode::Mov;
        ir.dsts.push_back(IrOperand::reg("rax", 64));
        ir.srcs.push_back(IrOperand::reg("eax", 64));
    } else if (insn.mnemonic == "cqo" || insn.mnemonic == "cdq") {
        ir.opcode = IrOpcode::Mov;
        ir.dsts.push_back(IrOperand::reg("rdx", 64));
        ir.srcs.push_back(IrOperand::immediate(0, 64));
    } else if ((insn.mnemonic == "mov" || insn.mnemonic == "movzx" || insn.mnemonic == "movsxd" ||
                insn.mnemonic == "movsx" || insn.mnemonic == "movabs") && ops.size() == 2) {
        const auto dst = parse_operand_text(ops[0]);
        const auto src = parse_operand_text(ops[1]);
        if (dst.kind == IrOperand::Kind::Memory) {
            ir.opcode = IrOpcode::Store;
        } else if (src.kind == IrOperand::Kind::Memory) {
            ir.opcode = IrOpcode::Load;
        } else {
            ir.opcode = IrOpcode::Mov;
        }
        ir.dsts.push_back(dst);
        ir.srcs.push_back(src);
    } else if (insn.mnemonic == "lea" && ops.size() == 2) {
        const auto dst = parse_operand_text(ops[0]);
        const auto addr = parse_x86_address(ops[1]);
        if (addr.valid) {
            if (!addr.base_reg.empty() && !addr.index_reg.empty() && addr.disp == 0) {
                if (addr.base_reg == addr.index_reg && (addr.scale == 2 || addr.scale == 4 || addr.scale == 8)) {
                    ir.opcode = IrOpcode::Mul;
                    ir.dsts.push_back(dst);
                    ir.srcs.push_back(IrOperand::reg(addr.base_reg, 64));
                    ir.srcs.push_back(IrOperand::immediate(addr.scale + 1, 64));
                    ir.comment = "lea*scale";
                    return ir;
                }
                if (addr.scale == 1) {
                    ir.opcode = IrOpcode::Add;
                    ir.dsts.push_back(dst);
                    ir.srcs.push_back(IrOperand::reg(addr.base_reg, 64));
                    ir.srcs.push_back(IrOperand::reg(addr.index_reg, 64));
                    ir.comment = "lea+";
                    return ir;
                }
                if (addr.scale == -1) {
                    ir.opcode = IrOpcode::Sub;
                    ir.dsts.push_back(dst);
                    ir.srcs.push_back(IrOperand::reg(addr.base_reg, 64));
                    ir.srcs.push_back(IrOperand::reg(addr.index_reg, 64));
                    ir.comment = "lea-";
                    return ir;
                }
            }
            if (!addr.base_reg.empty() && addr.index_reg.empty()) {
                if (addr.disp > 0) {
                    ir.opcode = IrOpcode::Add;
                    ir.dsts.push_back(dst);
                    ir.srcs.push_back(IrOperand::reg(addr.base_reg, 64));
                    ir.srcs.push_back(IrOperand::immediate(addr.disp, 64));
                    ir.comment = "lea+disp";
                    return ir;
                }
                if (addr.disp < 0) {
                    ir.opcode = IrOpcode::Sub;
                    ir.dsts.push_back(dst);
                    ir.srcs.push_back(IrOperand::reg(addr.base_reg, 64));
                    ir.srcs.push_back(IrOperand::immediate(-addr.disp, 64));
                    ir.comment = "lea-disp";
                    return ir;
                }
                ir.opcode = IrOpcode::Mov;
                ir.dsts.push_back(dst);
                ir.srcs.push_back(IrOperand::reg(addr.base_reg, 64));
                return ir;
            }
            if (addr.base_reg.empty() && !addr.index_reg.empty() && addr.disp == 0) {
                ir.opcode = IrOpcode::Mul;
                ir.dsts.push_back(dst);
                ir.srcs.push_back(IrOperand::reg(addr.index_reg, 64));
                ir.srcs.push_back(IrOperand::immediate(addr.scale, 64));
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
    } else if (insn.mnemonic == "inc" && ops.size() == 1) {
        ir.opcode = IrOpcode::Add;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(IrOperand::immediate(1, 64));
    } else if (insn.mnemonic == "dec" && ops.size() == 1) {
        ir.opcode = IrOpcode::Sub;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(IrOperand::immediate(1, 64));
    } else if (insn.mnemonic == "neg" && ops.size() == 1) {
        ir.opcode = IrOpcode::Sub;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(IrOperand::immediate(0, 64));
        ir.srcs.push_back(parse_operand_text(ops[0]));
    } else if (insn.mnemonic == "not" && ops.size() == 1) {
        ir.opcode = IrOpcode::Xor;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(IrOperand::immediate(-1, 64));
        ir.comment = "not";
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
    } else if ((insn.mnemonic == "div" || insn.mnemonic == "idiv") && ops.size() == 1) {
        ir.opcode = IrOpcode::Div;
        ir.dsts.push_back(IrOperand::reg("rax", 64));
        ir.srcs.push_back(IrOperand::reg("rax", 64));
        ir.srcs.push_back(parse_operand_text(ops[0]));
    } else if ((insn.mnemonic == "shl" || insn.mnemonic == "sal") && ops.size() == 2) {
        ir.opcode = IrOpcode::Shl;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if ((insn.mnemonic == "shr" || insn.mnemonic == "sar") && ops.size() == 2) {
        ir.opcode = IrOpcode::Shr;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if (insn.mnemonic == "cmp" && ops.size() == 2) {
        ir.opcode = IrOpcode::Cmp;
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if (insn.mnemonic == "test" && ops.size() == 2) {
        if (ops[0] == ops[1]) {
            ir.opcode = IrOpcode::Cmp;
            ir.srcs.push_back(parse_operand_text(ops[0]));
            ir.srcs.push_back(IrOperand::immediate(0, 64));
        } else {
            ir.opcode = IrOpcode::And;
            ir.dsts.push_back(IrOperand::reg("__bm_test_tmp", 64));
            ir.srcs.push_back(parse_operand_text(ops[0]));
            ir.srcs.push_back(parse_operand_text(ops[1]));
        }
    } else if (insn.mnemonic == "push" && ops.size() == 1) {
        ir.opcode = IrOpcode::Store;
        ir.dsts.push_back(IrOperand::memory_disp("rsp", 0, 64));
        ir.srcs.push_back(parse_operand_text(ops[0]));
        ir.comment = "push";
    } else if (insn.mnemonic == "pop" && ops.size() == 1) {
        ir.opcode = IrOpcode::Load;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(IrOperand::memory_disp("rsp", 0, 64));
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

    const auto rsp_op = IrOperand::reg("rsp", 64);
    const auto rbp_op = IrOperand::reg("rbp", 64);
    const auto idx_tmp = IrOperand::reg("__bm_idx_tmp", 64);
    const auto addr_tmp = IrOperand::reg("__bm_addr_tmp", 64);
    const auto rmw_tmp = IrOperand::reg("__bm_rmw_tmp", 64);

    auto materialize_complex_mem = [&](std::uint64_t va, IrOperand& op, std::vector<IrInstruction>& out) {
        if (op.kind != IrOperand::Kind::Memory || op.name.find('[') == std::string::npos) {
            return;
        }
        const auto addr = parse_x86_address(op.name);
        if (!addr.valid) return;
        if (addr.index_reg.empty() && !addr.base_reg.empty()) {
            op = IrOperand::memory_disp(addr.base_reg, addr.disp, addr.width);
            return;
        }
        if (!addr.index_reg.empty()) {
            IrInstruction mul_i;
            mul_i.source_va = va;
            mul_i.opcode = IrOpcode::Mul;
            mul_i.dsts.push_back(idx_tmp);
            mul_i.srcs.push_back(IrOperand::reg(addr.index_reg, 64));
            mul_i.srcs.push_back(IrOperand::immediate(addr.scale, 64));
            out.push_back(std::move(mul_i));

            if (!addr.base_reg.empty()) {
                IrInstruction add_i;
                add_i.source_va = va;
                add_i.opcode = IrOpcode::Add;
                add_i.dsts.push_back(addr_tmp);
                add_i.srcs.push_back(IrOperand::reg(addr.base_reg, 64));
                add_i.srcs.push_back(idx_tmp);
                out.push_back(std::move(add_i));
                op = IrOperand::memory_disp("__bm_addr_tmp", addr.disp, addr.width);
            } else {
                op = IrOperand::memory_disp("__bm_idx_tmp", addr.disp, addr.width);
            }
        }
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
            if (insn.mnemonic == "push" && ops.size() == 1) {
                IrInstruction sub_sp{insn.address, IrOpcode::Sub, {rsp_op}, {rsp_op, IrOperand::immediate(8, 64)}, {}, "push_sp"};
                IrInstruction st{insn.address, IrOpcode::Store, {IrOperand::memory_disp("rsp", 0, 64)}, {parse_operand_text(ops[0])}, {}, "push_st"};
                ir_bb.instructions.push_back(std::move(sub_sp));
                ir_bb.instructions.push_back(std::move(st));
                continue;
            }
            if (insn.mnemonic == "pop" && ops.size() == 1) {
                IrInstruction ld{insn.address, IrOpcode::Load, {parse_operand_text(ops[0])}, {IrOperand::memory_disp("rsp", 0, 64)}, {}, "pop_ld"};
                IrInstruction add_sp{insn.address, IrOpcode::Add, {rsp_op}, {rsp_op, IrOperand::immediate(8, 64)}, {}, "pop_sp"};
                ir_bb.instructions.push_back(std::move(ld));
                ir_bb.instructions.push_back(std::move(add_sp));
                continue;
            }
            if (insn.mnemonic == "xchg" && ops.size() == 2) {
                const auto op0 = parse_operand_text(ops[0]);
                const auto op1 = parse_operand_text(ops[1]);
                if (op0.kind != IrOperand::Kind::Memory && op1.kind != IrOperand::Kind::Memory &&
                    op0.kind != IrOperand::Kind::None && op1.kind != IrOperand::Kind::None) {
                    const auto xchg_tmp = IrOperand::reg("__bm_xchg_tmp", 64);
                    ir_bb.instructions.push_back(IrInstruction{insn.address, IrOpcode::Mov, {xchg_tmp}, {op0}, {}, "xchg_0"});
                    ir_bb.instructions.push_back(IrInstruction{insn.address, IrOpcode::Mov, {op0}, {op1}, {}, "xchg_1"});
                    ir_bb.instructions.push_back(IrInstruction{insn.address, IrOpcode::Mov, {op1}, {xchg_tmp}, {}, "xchg_2"});
                    continue;
                }
            }
            if (insn.mnemonic == "leave") {
                IrInstruction mov_sp{insn.address, IrOpcode::Mov, {rsp_op}, {rbp_op}, {}, "leave_mov"};
                IrInstruction ld_bp{insn.address, IrOpcode::Load, {rbp_op}, {IrOperand::memory_disp("rsp", 0, 64)}, {}, "leave_ld"};
                IrInstruction add_sp{insn.address, IrOpcode::Add, {rsp_op}, {rsp_op, IrOperand::immediate(8, 64)}, {}, "leave_sp"};
                ir_bb.instructions.push_back(std::move(mov_sp));
                ir_bb.instructions.push_back(std::move(ld_bp));
                ir_bb.instructions.push_back(std::move(add_sp));
                continue;
            }
            if (insn.mnemonic == "lea" && ops.size() == 2) {
                const auto addr = parse_x86_address(ops[1]);
                if (addr.valid && !addr.index_reg.empty() &&
                    !(addr.disp == 0 && !addr.base_reg.empty() &&
                      ((addr.base_reg == addr.index_reg && (addr.scale == 2 || addr.scale == 4 || addr.scale == 8)) ||
                       addr.scale == 1 || addr.scale == -1))) {
                    const auto dst = parse_operand_text(ops[0]);
                    ir_bb.instructions.push_back(IrInstruction{
                        insn.address, IrOpcode::Mul, {idx_tmp}, {IrOperand::reg(addr.index_reg, 64), IrOperand::immediate(addr.scale, 64)}, {}, "lea_idx"});
                    if (!addr.base_reg.empty()) {
                        ir_bb.instructions.push_back(IrInstruction{
                            insn.address, IrOpcode::Add, {dst}, {IrOperand::reg(addr.base_reg, 64), idx_tmp}, {}, "lea_base"});
                    } else {
                        ir_bb.instructions.push_back(IrInstruction{
                            insn.address, IrOpcode::Mov, {dst}, {idx_tmp}, {}, "lea_mov"});
                    }
                    if (addr.disp != 0) {
                        ir_bb.instructions.push_back(IrInstruction{
                            insn.address, IrOpcode::Add, {dst}, {dst, IrOperand::immediate(addr.disp, 64)}, {}, "lea_disp"});
                    }
                    continue;
                }
            }

            IrInstruction lifted = lift_instruction(insn);
            for (auto& s : lifted.srcs) {
                materialize_complex_mem(insn.address, s, ir_bb.instructions);
            }
            for (auto& d : lifted.dsts) {
                materialize_complex_mem(insn.address, d, ir_bb.instructions);
            }

            // Expand Read-Modify-Write ALU instruction with Memory destination (e.g. add dword ptr [rbp-4], 1)
            const bool is_alu = (lifted.opcode == IrOpcode::Add || lifted.opcode == IrOpcode::Sub ||
                                 lifted.opcode == IrOpcode::Mul || lifted.opcode == IrOpcode::And ||
                                 lifted.opcode == IrOpcode::Or  || lifted.opcode == IrOpcode::Xor ||
                                 lifted.opcode == IrOpcode::Shl || lifted.opcode == IrOpcode::Shr);
            if (is_alu && !lifted.dsts.empty() && lifted.dsts[0].kind == IrOperand::Kind::Memory && lifted.srcs.size() >= 2) {
                const IrOperand mem_op = lifted.dsts[0];
                ir_bb.instructions.push_back(IrInstruction{insn.address, IrOpcode::Load, {rmw_tmp}, {mem_op}, {}, "rmw_ld"});
                lifted.dsts[0] = rmw_tmp;
                if (lifted.srcs[0].kind == IrOperand::Kind::Memory) {
                    lifted.srcs[0] = rmw_tmp;
                }
                ir_bb.instructions.push_back(std::move(lifted));
                ir_bb.instructions.push_back(IrInstruction{insn.address, IrOpcode::Store, {mem_op}, {rmw_tmp}, {}, "rmw_st"});
                continue;
            }

            ir_bb.instructions.push_back(std::move(lifted));
        }
        ir_fn.blocks.push_back(std::move(ir_bb));
    }

    return ir_fn;
}

} // namespace bytemorph::arch::x86_64
