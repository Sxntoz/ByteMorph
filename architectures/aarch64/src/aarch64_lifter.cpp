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

[[nodiscard]] std::string normalize_arm_cc(std::string cc) noexcept {
    for (auto& ch : cc) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    if (cc == "eq" || cc == "ne" || cc == "lt" || cc == "le" || cc == "gt" || cc == "ge") return cc;
    if (cc == "lo" || cc == "cc") return "b";
    if (cc == "ls") return "be";
    if (cc == "hi") return "a";
    if (cc == "hs" || cc == "cs") return "ae";
    if (cc == "mi") return "s";
    if (cc == "pl") return "ns";
    if (cc == "vs") return "o";
    if (cc == "vc") return "no";
    return {};
}

} // namespace

IrInstruction AArch64Lifter::lift_instruction(const DisassembledInstruction& insn) const {
    IrInstruction ir;
    ir.source_va = insn.address;
    const auto ops = split_operands(insn.operands_text);

    if (insn.mnemonic == "nop" || insn.mnemonic == "bti" || insn.mnemonic == "hint" ||
        insn.mnemonic == "paciasp" || insn.mnemonic == "autiasp") {
        ir.opcode = IrOpcode::Nop;
    } else if ((insn.mnemonic == "adr" || insn.mnemonic == "adrp") && ops.size() >= 2) {
        std::int64_t target_va = 0;
        if (try_parse_arm_imm(ops[1], target_va)) {
            ir.opcode = IrOpcode::LeaGlobal;
            ir.dsts.push_back(parse_operand_text(ops[0]));
            ir.srcs.push_back(IrOperand::label(static_cast<std::uint64_t>(target_va)));
            ir.comment = insn.mnemonic;
        } else {
            ir.opcode = IrOpcode::Unknown;
            ir.comment = insn.full_text;
        }
    } else if (insn.mnemonic == "cset" && ops.size() >= 2) {
        const std::string cc = normalize_arm_cc(ops[1]);
        if (!cc.empty()) {
            ir.opcode = IrOpcode::SetCc;
            ir.dsts.push_back(parse_operand_text(ops[0]));
            ir.cond = cc;
        } else {
            ir.opcode = IrOpcode::Unknown;
            ir.comment = insn.full_text;
        }
    } else if ((insn.mnemonic == "mov" || insn.mnemonic == "movz" || insn.mnemonic == "sxtw" ||
                insn.mnemonic == "sxtb" || insn.mnemonic == "sxth") && ops.size() >= 2) {
        ir.opcode = IrOpcode::Mov;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
    } else if (insn.mnemonic == "uxtb" && ops.size() >= 2) {
        ir.opcode = IrOpcode::And;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(IrOperand::immediate(0xFF, 64));
    } else if (insn.mnemonic == "uxth" && ops.size() >= 2) {
        ir.opcode = IrOpcode::And;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(IrOperand::immediate(0xFFFF, 64));
    } else if (insn.mnemonic == "fmov" && ops.size() >= 2) {
        const std::uint8_t w = (!ops[0].empty() && (ops[0][0] == 's' || ops[0][0] == 'w' ||
                                (!ops[1].empty() && ops[1][0] == 's'))) ? 32 : 64;
        auto dst = parse_operand_text(ops[0]);
        auto src = parse_operand_text(ops[1]);
        dst.bit_width = w;
        src.bit_width = w;
        ir.opcode = IrOpcode::VMov;
        ir.dsts.push_back(std::move(dst));
        ir.srcs.push_back(std::move(src));
    } else if ((insn.mnemonic == "scvtf" || insn.mnemonic == "ucvtf" ||
                insn.mnemonic == "fcvtzs" || insn.mnemonic == "fcvtzu" ||
                insn.mnemonic == "fcvt") && ops.size() >= 2) {
        auto dst = parse_operand_text(ops[0]);
        auto src = parse_operand_text(ops[1]);
        dst.bit_width = (!ops[0].empty() && (ops[0][0] == 's' || ops[0][0] == 'w')) ? 32 : 64;
        src.bit_width = (!ops[1].empty() && (ops[1][0] == 's' || ops[1][0] == 'w')) ? 32 : 64;
        std::int64_t mode = 0;
        if (insn.mnemonic == "scvtf") mode = 0;
        else if (insn.mnemonic == "ucvtf") mode = 1;
        else if (insn.mnemonic == "fcvtzs") mode = 2;
        else if (insn.mnemonic == "fcvtzu") mode = 3;
        else mode = 4;
        ir.opcode = IrOpcode::FCvt;
        ir.dsts.push_back(std::move(dst));
        ir.srcs.push_back(std::move(src));
        ir.srcs.push_back(IrOperand::immediate(mode, 64));
    } else if ((insn.mnemonic == "add" || insn.mnemonic == "sub" ||
                insn.mnemonic == "and" || insn.mnemonic == "orr" || insn.mnemonic == "eor") &&
               ops.size() >= 3 && ops[0].find('.') != std::string::npos) {
        const auto dot_pos = ops[0].find('.');
        const std::string suffix = ops[0].substr(dot_pos + 1);
        auto strip_vec = [](const std::string& reg) {
            const auto d = reg.find('.');
            return d == std::string::npos ? reg : reg.substr(0, d);
        };
        auto dst = parse_operand_text(strip_vec(ops[0]));
        auto s1 = parse_operand_text(strip_vec(ops[1]));
        auto s2 = parse_operand_text(strip_vec(ops[2]));
        if (insn.mnemonic == "add" || insn.mnemonic == "sub") {
            const std::uint8_t lane_w = (suffix == "2d") ? 64 : 32;
            dst.bit_width = lane_w; s1.bit_width = lane_w; s2.bit_width = lane_w;
            ir.opcode = (insn.mnemonic == "add") ? IrOpcode::VPAdd : IrOpcode::VPSub;
        } else {
            dst.bit_width = 128; s1.bit_width = 128; s2.bit_width = 128;
            if (insn.mnemonic == "and") ir.opcode = IrOpcode::And;
            else if (insn.mnemonic == "orr") ir.opcode = IrOpcode::Or;
            else ir.opcode = IrOpcode::Xor;
        }
        ir.dsts.push_back(std::move(dst));
        ir.srcs.push_back(std::move(s1));
        ir.srcs.push_back(std::move(s2));
    } else if ((insn.mnemonic == "fadd" || insn.mnemonic == "fsub" ||
                insn.mnemonic == "fmul" || insn.mnemonic == "fdiv") && ops.size() >= 3) {
        const std::uint8_t w = (!ops[0].empty() && ops[0][0] == 's') ? 32 : (!ops[0].empty() && ops[0][0] == 'd') ? 64 : 128;
        auto dst = parse_operand_text(ops[0]);
        auto s1 = parse_operand_text(ops[1]);
        auto s2 = parse_operand_text(ops[2]);
        dst.bit_width = w; s1.bit_width = w; s2.bit_width = w;
        if (insn.mnemonic == "fadd") ir.opcode = IrOpcode::FAdd;
        else if (insn.mnemonic == "fsub") ir.opcode = IrOpcode::FSub;
        else if (insn.mnemonic == "fmul") ir.opcode = IrOpcode::FMul;
        else ir.opcode = IrOpcode::FDiv;
        ir.dsts.push_back(std::move(dst));
        ir.srcs.push_back(std::move(s1));
        ir.srcs.push_back(std::move(s2));
    } else if ((insn.mnemonic == "fcmp" || insn.mnemonic == "fcmpe") && ops.size() >= 2) {
        const std::uint8_t w = (!ops[0].empty() && ops[0][0] == 's') ? 32 : 64;
        auto s1 = parse_operand_text(ops[0]);
        auto s2 = parse_operand_text(ops[1]);
        s1.bit_width = w; s2.bit_width = w;
        ir.opcode = IrOpcode::FCmp;
        ir.srcs.push_back(std::move(s1));
        ir.srcs.push_back(std::move(s2));
    } else if (insn.mnemonic == "uxtw" && ops.size() >= 2) {
        ir.opcode = IrOpcode::And;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(IrOperand::immediate(0xFFFFFFFFLL, 64));
    } else if (insn.mnemonic == "mvn" && ops.size() >= 2) {
        ir.opcode = IrOpcode::Xor;
        ir.dsts.push_back(parse_operand_text(ops[0]));
        ir.srcs.push_back(parse_operand_text(ops[1]));
        ir.srcs.push_back(IrOperand::immediate(-1, 64));
    } else if (insn.mnemonic == "movn" && ops.size() >= 2) {
        std::int64_t imm_v = 0;
        if (try_parse_arm_imm(ops[1], imm_v)) {
            ir.opcode = IrOpcode::Mov;
            ir.dsts.push_back(parse_operand_text(ops[0]));
            ir.srcs.push_back(IrOperand::immediate(~imm_v, 64));
        } else {
            ir.opcode = IrOpcode::Unknown;
            ir.comment = insn.full_text;
        }
    } else if ((insn.mnemonic == "neg" || insn.mnemonic == "negs") && ops.size() >= 2) {
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
        for (std::size_t i_idx = 0; i_idx < bb.instructions.size(); ++i_idx) {
            const auto& insn = bb.instructions[i_idx];
            const auto ops = split_operands(insn.operands_text);

            // Fuse ADRP + ADD / ADRP + LDR into exact PC-relative LeaGlobal (+ Load)
            if (insn.mnemonic == "adrp" && ops.size() >= 2 && i_idx + 1 < bb.instructions.size()) {
                std::int64_t page_va = 0;
                if (try_parse_arm_imm(ops[1], page_va)) {
                    const auto& next = bb.instructions[i_idx + 1];
                    const auto next_ops = split_operands(next.operands_text);
                    if (next.mnemonic == "add" && next_ops.size() >= 3 && next_ops[1] == ops[0]) {
                        std::int64_t off_imm = 0;
                        if (try_parse_arm_imm(next_ops[2], off_imm)) {
                            const std::uint64_t target_va = static_cast<std::uint64_t>(page_va + off_imm);
                            ir_bb.instructions.push_back(IrInstruction{
                                insn.address, IrOpcode::LeaGlobal, {parse_operand_text(next_ops[0])},
                                {IrOperand::label(target_va)}, {}, "adrp_add_global"});
                            ++i_idx;
                            continue;
                        }
                    } else if ((next.mnemonic == "ldr" || next.mnemonic == "ldur" ||
                                next.mnemonic == "ldrb" || next.mnemonic == "ldrh" ||
                                next.mnemonic == "ldrsw") && next_ops.size() >= 2) {
                        const auto addr = parse_arm64_address(next_ops[1]);
                        if (addr.valid && addr.base_reg == ops[0] && addr.index_reg.empty()) {
                            const std::uint64_t target_va = static_cast<std::uint64_t>(page_va + addr.disp);
                            const std::uint8_t w = infer_arm64_mem_width(next.mnemonic, next_ops[0]);
                            const auto rip_tmp = IrOperand::reg("__bm_rip_tmp", 64);
                            ir_bb.instructions.push_back(IrInstruction{
                                insn.address, IrOpcode::LeaGlobal, {rip_tmp},
                                {IrOperand::label(target_va)}, {}, "adrp_ldr_global"});
                            ir_bb.instructions.push_back(IrInstruction{
                                next.address, IrOpcode::Load, {parse_operand_text(next_ops[0])},
                                {IrOperand::memory_disp("__bm_rip_tmp", 0, w)}, {}, "adrp_ldr_val"});
                            ++i_idx;
                            continue;
                        }
                    }
                }
            }

            // csel / csinc / csinv / csneg dst, rn, rm, cond
            if ((insn.mnemonic == "csel" || insn.mnemonic == "csinc" ||
                 insn.mnemonic == "csinv" || insn.mnemonic == "csneg") && ops.size() >= 4) {
                const std::string cc = normalize_arm_cc(ops[3]);
                if (!cc.empty()) {
                    const auto dst_op = parse_operand_text(ops[0]);
                    const auto rn_op = parse_operand_text(ops[1]);
                    const auto rm_op = parse_operand_text(ops[2]);
                    const auto cond_tmp = IrOperand::reg("__bm_cond_tmp", 64);
                    if (insn.mnemonic == "csel") {
                        ir_bb.instructions.push_back(IrInstruction{insn.address, IrOpcode::Mov, {dst_op}, {rm_op}, {}, "csel_false"});
                    } else if (insn.mnemonic == "csinc") {
                        ir_bb.instructions.push_back(IrInstruction{insn.address, IrOpcode::Add, {cond_tmp}, {rm_op, IrOperand::immediate(1, 64)}, {}, "csinc_false"});
                        ir_bb.instructions.push_back(IrInstruction{insn.address, IrOpcode::Mov, {dst_op}, {cond_tmp}, {}, "csinc_mv"});
                    } else if (insn.mnemonic == "csinv") {
                        ir_bb.instructions.push_back(IrInstruction{insn.address, IrOpcode::Xor, {cond_tmp}, {rm_op, IrOperand::immediate(-1, 64)}, {}, "csinv_false"});
                        ir_bb.instructions.push_back(IrInstruction{insn.address, IrOpcode::Mov, {dst_op}, {cond_tmp}, {}, "csinv_mv"});
                    } else { // csneg
                        ir_bb.instructions.push_back(IrInstruction{insn.address, IrOpcode::Sub, {cond_tmp}, {IrOperand::immediate(0, 64), rm_op}, {}, "csneg_false"});
                        ir_bb.instructions.push_back(IrInstruction{insn.address, IrOpcode::Mov, {dst_op}, {cond_tmp}, {}, "csneg_mv"});
                    }
                    IrInstruction sel{insn.address, IrOpcode::SelectCc, {dst_op}, {rn_op}, cc, insn.mnemonic};
                    ir_bb.instructions.push_back(std::move(sel));
                    continue;
                }
            }
            if (insn.mnemonic == "csetm" && ops.size() >= 2) {
                const std::string cc = normalize_arm_cc(ops[1]);
                if (!cc.empty()) {
                    const auto cond_tmp = IrOperand::reg("__bm_cond_tmp", 64);
                    ir_bb.instructions.push_back(IrInstruction{insn.address, IrOpcode::SetCc, {cond_tmp}, {}, cc, "csetm_cc"});
                    ir_bb.instructions.push_back(IrInstruction{insn.address, IrOpcode::Sub, {parse_operand_text(ops[0])}, {IrOperand::immediate(0, 64), cond_tmp}, {}, "csetm_neg"});
                    continue;
                }
            }

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
            if (insn.mnemonic == "mneg" && ops.size() >= 3) {
                const auto mneg_tmp = IrOperand::reg("__bm_mneg_tmp", 64);
                ir_bb.instructions.push_back(IrInstruction{
                    insn.address, IrOpcode::Mul, {mneg_tmp}, {parse_operand_text(ops[1]), parse_operand_text(ops[2])}, {}, "mneg_mul"});
                ir_bb.instructions.push_back(IrInstruction{
                    insn.address, IrOpcode::Sub, {parse_operand_text(ops[0])}, {IrOperand::immediate(0, 64), mneg_tmp}, {}, "mneg_sub"});
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
