#include "bytemorph/core/ir/ir_optimizer.hpp"

#include <algorithm>
#include <cstdint>
#include <queue>
#include <unordered_map>

namespace bytemorph::core::ir {

namespace {

bool is_reg_operand(const IrOperand& op) noexcept {
    return op.kind == IrOperand::Kind::VirtualReg || op.kind == IrOperand::Kind::ArchReg;
}

std::string reg_key(const IrOperand& op) {
    if (op.kind == IrOperand::Kind::VirtualReg) return "v:" + op.name;
    if (op.kind == IrOperand::Kind::ArchReg) return "a:" + op.name;
    return {};
}

bool same_operand(const IrOperand& a, const IrOperand& b) noexcept {
    return a.kind == b.kind && a.name == b.name && a.imm == b.imm && a.bit_width == b.bit_width;
}

bool reads_flags(const IrInstruction& insn) noexcept {
    switch (insn.opcode) {
        case IrOpcode::JumpCond:
        case IrOpcode::SelectCc:
        case IrOpcode::SetCc:
        case IrOpcode::Adc:
        case IrOpcode::Sbb:
            return true;
        default:
            return false;
    }
}

bool writes_flags(const IrInstruction& insn) noexcept {
    switch (insn.opcode) {
        case IrOpcode::Add:
        case IrOpcode::Sub:
        case IrOpcode::Mul:
        case IrOpcode::Div:
        case IrOpcode::And:
        case IrOpcode::Or:
        case IrOpcode::Xor:
        case IrOpcode::Shl:
        case IrOpcode::Shr:
        case IrOpcode::Cmp:
        case IrOpcode::Adc:
        case IrOpcode::Sbb:
        case IrOpcode::FCmp:
            return true;
        default:
            return false;
    }
}

bool has_side_effects(const IrInstruction& insn) noexcept {
    switch (insn.opcode) {
        case IrOpcode::Store:
        case IrOpcode::Jump:
        case IrOpcode::JumpCond:
        case IrOpcode::Call:
        case IrOpcode::Ret:
        case IrOpcode::Syscall:
        case IrOpcode::Div: // may trap on zero
        case IrOpcode::Unknown:
            return true;
        default:
            return false;
    }
}

bool is_flags_live_after(const IrBasicBlock& bb, std::size_t idx) noexcept {
    for (std::size_t i = idx + 1; i < bb.instructions.size(); ++i) {
        if (reads_flags(bb.instructions[i])) return true;
        if (writes_flags(bb.instructions[i])) return false;
        if (bb.instructions[i].opcode == IrOpcode::Call ||
            bb.instructions[i].opcode == IrOpcode::Syscall ||
            bb.instructions[i].opcode == IrOpcode::Jump ||
            bb.instructions[i].opcode == IrOpcode::Ret) {
            return true; // conservative across block exit / calls
        }
    }
    return !bb.successors.empty();
}

std::size_t count_instructions(const IrFunction& fn) noexcept {
    std::size_t total = 0;
    for (const auto& bb : fn.blocks) total += bb.instructions.size();
    return total;
}

bool eval_static_cond(const std::string& cond, std::int64_t a, std::int64_t b) noexcept {
    const std::uint64_t ua = static_cast<std::uint64_t>(a);
    const std::uint64_t ub = static_cast<std::uint64_t>(b);
    if (cond == "e" || cond == "eq" || cond == "z") return a == b;
    if (cond == "ne" || cond == "nz") return a != b;
    if (cond == "l" || cond == "lt") return a < b;
    if (cond == "le") return a <= b;
    if (cond == "g" || cond == "gt") return a > b;
    if (cond == "ge") return a >= b;
    if (cond == "b" || cond == "c" || cond == "below") return ua < ub;
    if (cond == "be" || cond == "below_eq") return ua <= ub;
    if (cond == "a" || cond == "above") return ua > ub;
    if (cond == "ae" || cond == "nc" || cond == "above_eq") return ua >= ub;
    return false;
}

bool can_eval_static_cond(const std::string& cond) noexcept {
    return cond == "e" || cond == "eq" || cond == "z" ||
           cond == "ne" || cond == "nz" ||
           cond == "l" || cond == "lt" || cond == "le" ||
           cond == "g" || cond == "gt" || cond == "ge" ||
           cond == "b" || cond == "c" || cond == "below" ||
           cond == "be" || cond == "below_eq" ||
           cond == "a" || cond == "above" ||
           cond == "ae" || cond == "nc" || cond == "above_eq";
}

bool is_pure_alu(IrOpcode op) noexcept {
    switch (op) {
        case IrOpcode::Add:
        case IrOpcode::Sub:
        case IrOpcode::Mul:
        case IrOpcode::And:
        case IrOpcode::Or:
        case IrOpcode::Xor:
        case IrOpcode::Shl:
        case IrOpcode::Shr:
            return true;
        default:
            return false;
    }
}

} // namespace

std::size_t IrOptimizer::simplify_expressions(IrFunction& fn) {
    std::size_t count = 0;
    for (auto& bb : fn.blocks) {
        for (std::size_t i = 0; i < bb.instructions.size(); ++i) {
            auto& insn = bb.instructions[i];
            if (insn.opcode == IrOpcode::Mov && insn.dsts.size() == 1 && insn.srcs.size() == 1) {
                if (same_operand(insn.dsts[0], insn.srcs[0])) {
                    insn.opcode = IrOpcode::Nop;
                    insn.dsts.clear();
                    insn.srcs.clear();
                    ++count;
                }
                continue;
            }
            if (insn.dsts.size() != 1 || insn.srcs.size() != 2) continue;
            if (is_flags_live_after(bb, i)) continue;

            const auto& s0 = insn.srcs[0];
            const auto& s1 = insn.srcs[1];
            const std::uint8_t w = insn.dsts[0].bit_width;

            if (insn.opcode == IrOpcode::Add || insn.opcode == IrOpcode::Or || insn.opcode == IrOpcode::Xor) {
                if (s1.kind == IrOperand::Kind::Immediate && s1.imm == 0) {
                    insn.opcode = IrOpcode::Mov;
                    insn.srcs = {s0};
                    ++count;
                    continue;
                }
                if (s0.kind == IrOperand::Kind::Immediate && s0.imm == 0) {
                    insn.opcode = IrOpcode::Mov;
                    insn.srcs = {s1};
                    ++count;
                    continue;
                }
            }
            if (insn.opcode == IrOpcode::Sub || insn.opcode == IrOpcode::Shl || insn.opcode == IrOpcode::Shr) {
                if (s1.kind == IrOperand::Kind::Immediate && s1.imm == 0) {
                    insn.opcode = IrOpcode::Mov;
                    insn.srcs = {s0};
                    ++count;
                    continue;
                }
            }
            if ((insn.opcode == IrOpcode::Sub || insn.opcode == IrOpcode::Xor) &&
                is_reg_operand(s0) && same_operand(s0, s1)) {
                insn.opcode = IrOpcode::Mov;
                insn.srcs = {IrOperand::immediate(0, w)};
                ++count;
                continue;
            }
            if (insn.opcode == IrOpcode::Mul) {
                if (s1.kind == IrOperand::Kind::Immediate && s1.imm == 1) {
                    insn.opcode = IrOpcode::Mov;
                    insn.srcs = {s0};
                    ++count;
                    continue;
                }
                if (s0.kind == IrOperand::Kind::Immediate && s0.imm == 1) {
                    insn.opcode = IrOpcode::Mov;
                    insn.srcs = {s1};
                    ++count;
                    continue;
                }
                if ((s1.kind == IrOperand::Kind::Immediate && s1.imm == 0) ||
                    (s0.kind == IrOperand::Kind::Immediate && s0.imm == 0)) {
                    insn.opcode = IrOpcode::Mov;
                    insn.srcs = {IrOperand::immediate(0, w)};
                    ++count;
                    continue;
                }
            }
            if (insn.opcode == IrOpcode::And) {
                if ((s1.kind == IrOperand::Kind::Immediate && s1.imm == 0) ||
                    (s0.kind == IrOperand::Kind::Immediate && s0.imm == 0)) {
                    insn.opcode = IrOpcode::Mov;
                    insn.srcs = {IrOperand::immediate(0, w)};
                    ++count;
                    continue;
                }
            }
        }
    }
    return count;
}

std::size_t IrOptimizer::propagate_and_fold_constants(IrFunction& fn) {
    std::size_t folded = 0;
    for (auto& bb : fn.blocks) {
        std::unordered_map<std::string, std::int64_t> const_env;
        for (std::size_t i = 0; i < bb.instructions.size(); ++i) {
            auto& insn = bb.instructions[i];

            if (insn.opcode == IrOpcode::Call || insn.opcode == IrOpcode::Syscall) {
                const_env.clear();
                continue;
            }

            // Substitute known constants into source operands
            for (std::size_t si = 0; si < insn.srcs.size(); ++si) {
                if (!is_reg_operand(insn.srcs[si])) continue;
                // Do not replace base/index in memory operands; only pure register srcs
                auto it = const_env.find(reg_key(insn.srcs[si]));
                if (it != const_env.end()) {
                    const bool allow_imm =
                        (insn.opcode == IrOpcode::Mov) ||
                        (is_pure_alu(insn.opcode) && (si == 1 || (insn.srcs.size() == 2 && insn.srcs[1].kind == IrOperand::Kind::Immediate))) ||
                        (insn.opcode == IrOpcode::Cmp && si == 1) ||
                        (insn.opcode == IrOpcode::Store && si == 0);
                    if (allow_imm) {
                        insn.srcs[si] = IrOperand::immediate(it->second, insn.srcs[si].bit_width);
                        ++folded;
                    }
                }
            }

            // Fold constant binary ALU operations when flags are dead
            if (insn.dsts.size() == 1 && insn.srcs.size() == 2 &&
                insn.srcs[0].kind == IrOperand::Kind::Immediate &&
                insn.srcs[1].kind == IrOperand::Kind::Immediate &&
                !is_flags_live_after(bb, i)) {
                const std::uint64_t u1 = static_cast<std::uint64_t>(insn.srcs[0].imm);
                const std::uint64_t u2 = static_cast<std::uint64_t>(insn.srcs[1].imm);
                std::int64_t res = 0;
                bool can_fold = true;
                switch (insn.opcode) {
                    case IrOpcode::Add: res = static_cast<std::int64_t>(u1 + u2); break;
                    case IrOpcode::Sub: res = static_cast<std::int64_t>(u1 - u2); break;
                    case IrOpcode::Mul: res = static_cast<std::int64_t>(u1 * u2); break;
                    case IrOpcode::Div:
                        if (u2 == 0) can_fold = false;
                        else res = static_cast<std::int64_t>(u1 / u2);
                        break;
                    case IrOpcode::And: res = static_cast<std::int64_t>(u1 & u2); break;
                    case IrOpcode::Or:  res = static_cast<std::int64_t>(u1 | u2); break;
                    case IrOpcode::Xor: res = static_cast<std::int64_t>(u1 ^ u2); break;
                    case IrOpcode::Shl: res = static_cast<std::int64_t>(u1 << (u2 & 63ULL)); break;
                    case IrOpcode::Shr: res = static_cast<std::int64_t>(u1 >> (u2 & 63ULL)); break;
                    default: can_fold = false; break;
                }
                if (can_fold) {
                    const std::uint8_t w = insn.dsts[0].bit_width;
                    insn.opcode = IrOpcode::Mov;
                    insn.srcs = {IrOperand::immediate(res, w)};
                    ++folded;
                }
            }

            // Update constant environment for destination writes
            for (const auto& d : insn.dsts) {
                if (!is_reg_operand(d)) continue;
                const std::string key = reg_key(d);
                if (insn.opcode == IrOpcode::Mov && insn.srcs.size() == 1 &&
                    insn.srcs[0].kind == IrOperand::Kind::Immediate) {
                    const_env[key] = insn.srcs[0].imm;
                } else {
                    const_env.erase(key);
                }
            }
        }
    }
    return folded;
}

std::size_t IrOptimizer::propagate_copies(IrFunction& fn) {
    std::size_t propagated = 0;
    for (auto& bb : fn.blocks) {
        std::unordered_map<std::string, IrOperand> copy_env;

        auto invalidate_key = [&](const std::string& k) {
            copy_env.erase(k);
            for (auto it = copy_env.begin(); it != copy_env.end();) {
                if (reg_key(it->second) == k) {
                    it = copy_env.erase(it);
                } else {
                    ++it;
                }
            }
        };

        for (auto& insn : bb.instructions) {
            if (insn.opcode == IrOpcode::Call || insn.opcode == IrOpcode::Syscall) {
                copy_env.clear();
                continue;
            }

            for (auto& s : insn.srcs) {
                if (!is_reg_operand(s)) continue;
                auto it = copy_env.find(reg_key(s));
                if (it != copy_env.end() && it->second.bit_width == s.bit_width) {
                    s = it->second;
                    ++propagated;
                }
            }

            for (const auto& d : insn.dsts) {
                if (is_reg_operand(d)) {
                    invalidate_key(reg_key(d));
                }
            }

            if (insn.opcode == IrOpcode::Mov && insn.dsts.size() == 1 && insn.srcs.size() == 1 &&
                is_reg_operand(insn.dsts[0]) && is_reg_operand(insn.srcs[0]) &&
                insn.dsts[0].bit_width == insn.srcs[0].bit_width &&
                !same_operand(insn.dsts[0], insn.srcs[0])) {
                copy_env[reg_key(insn.dsts[0])] = insn.srcs[0];
            }
        }
    }
    return propagated;
}

std::size_t IrOptimizer::eliminate_redundant_instructions(IrFunction& fn) {
    std::size_t removed = 0;
    struct ExprEntry {
        IrOpcode opcode;
        IrOperand s0;
        IrOperand s1;
        IrOperand dst;
    };

    for (auto& bb : fn.blocks) {
        std::vector<ExprEntry> avail;
        for (std::size_t i = 0; i < bb.instructions.size(); ++i) {
            auto& insn = bb.instructions[i];
            if (insn.opcode == IrOpcode::Call || insn.opcode == IrOpcode::Syscall ||
                insn.opcode == IrOpcode::Store || insn.opcode == IrOpcode::Jump ||
                insn.opcode == IrOpcode::JumpCond || insn.opcode == IrOpcode::Ret) {
                avail.clear();
                continue;
            }

            bool replaced = false;
            if (is_pure_alu(insn.opcode) && insn.dsts.size() == 1 && insn.srcs.size() == 2 &&
                !is_flags_live_after(bb, i)) {
                for (const auto& e : avail) {
                    if (e.opcode == insn.opcode &&
                        same_operand(e.s0, insn.srcs[0]) &&
                        same_operand(e.s1, insn.srcs[1]) &&
                        e.dst.bit_width == insn.dsts[0].bit_width) {
                        if (same_operand(e.dst, insn.dsts[0])) {
                            insn.opcode = IrOpcode::Nop;
                            insn.dsts.clear();
                            insn.srcs.clear();
                        } else {
                            insn.opcode = IrOpcode::Mov;
                            insn.srcs = {e.dst};
                        }
                        ++removed;
                        replaced = true;
                        break;
                    }
                }
            }

            for (const auto& d : insn.dsts) {
                if (!is_reg_operand(d)) continue;
                const std::string dk = reg_key(d);
                avail.erase(std::remove_if(avail.begin(), avail.end(), [&](const ExprEntry& e) {
                    return reg_key(e.dst) == dk || reg_key(e.s0) == dk || reg_key(e.s1) == dk;
                }), avail.end());
            }

            if (!replaced && is_pure_alu(insn.opcode) && insn.dsts.size() == 1 && insn.srcs.size() == 2 &&
                is_reg_operand(insn.dsts[0])) {
                const std::string dk = reg_key(insn.dsts[0]);
                if (reg_key(insn.srcs[0]) != dk && reg_key(insn.srcs[1]) != dk) {
                    avail.push_back({insn.opcode, insn.srcs[0], insn.srcs[1], insn.dsts[0]});
                }
            }
        }
    }
    return removed;
}

std::size_t IrOptimizer::simplify_branches(IrFunction& fn) {
    std::size_t simplified = 0;

    for (auto& bb : fn.blocks) {
        // Constant Cmp followed by JumpCond
        for (std::size_t i = 0; i + 1 < bb.instructions.size(); ++i) {
            const auto& cmp = bb.instructions[i];
            auto& jcc = bb.instructions[i + 1];
            if (cmp.opcode == IrOpcode::Cmp && cmp.srcs.size() == 2 &&
                cmp.srcs[0].kind == IrOperand::Kind::Immediate &&
                cmp.srcs[1].kind == IrOperand::Kind::Immediate &&
                jcc.opcode == IrOpcode::JumpCond && can_eval_static_cond(jcc.cond)) {
                const bool taken = eval_static_cond(jcc.cond, cmp.srcs[0].imm, cmp.srcs[1].imm);
                if (taken) {
                    jcc.opcode = IrOpcode::Jump;
                    jcc.cond.clear();
                    if (!jcc.srcs.empty() && jcc.srcs[0].kind == IrOperand::Kind::Label) {
                        bb.successors = {static_cast<std::uint64_t>(jcc.srcs[0].imm)};
                    }
                } else {
                    const std::uint64_t skip_va = (!jcc.srcs.empty() && jcc.srcs[0].kind == IrOperand::Kind::Label)
                                                      ? static_cast<std::uint64_t>(jcc.srcs[0].imm)
                                                      : ~0ULL;
                    jcc.opcode = IrOpcode::Nop;
                    jcc.srcs.clear();
                    jcc.cond.clear();
                    if (skip_va != ~0ULL) {
                        bb.successors.erase(
                            std::remove(bb.successors.begin(), bb.successors.end(), skip_va),
                            bb.successors.end());
                    }
                }
                ++simplified;
            }
        }

        // Strip Nops
        const std::size_t before = bb.instructions.size();
        bb.instructions.erase(
            std::remove_if(bb.instructions.begin(), bb.instructions.end(),
                           [](const IrInstruction& insn) { return insn.opcode == IrOpcode::Nop; }),
            bb.instructions.end());
        simplified += (before - bb.instructions.size());
    }

    // Remove unreachable blocks when CFG has multiple blocks
    if (fn.blocks.size() > 1) {
        std::unordered_map<std::uint64_t, std::size_t> id_to_idx;
        std::unordered_map<std::uint64_t, std::size_t> va_to_idx;
        for (std::size_t i = 0; i < fn.blocks.size(); ++i) {
            id_to_idx[fn.blocks[i].id] = i;
            va_to_idx[fn.blocks[i].start_va] = i;
        }
        std::vector<bool> reachable(fn.blocks.size(), false);
        std::queue<std::size_t> q;
        reachable[0] = true;
        q.push(0);
        while (!q.empty()) {
            const std::size_t cur = q.front();
            q.pop();
            for (const std::uint64_t succ : fn.blocks[cur].successors) {
                auto it = id_to_idx.find(succ);
                if (it == id_to_idx.end()) it = va_to_idx.find(succ);
                if (it != id_to_idx.end() && it != va_to_idx.end()) {
                    if (!reachable[it->second]) {
                        reachable[it->second] = true;
                        q.push(it->second);
                    }
                }
            }
        }
        std::vector<IrBasicBlock> kept;
        kept.reserve(fn.blocks.size());
        for (std::size_t i = 0; i < fn.blocks.size(); ++i) {
            if (reachable[i]) kept.push_back(std::move(fn.blocks[i]));
            else ++simplified;
        }
        if (!kept.empty()) fn.blocks = std::move(kept);
    }

    return simplified;
}

std::vector<BlockLiveness> IrOptimizer::compute_liveness(const IrFunction& fn) {
    const std::size_t n = fn.blocks.size();
    std::vector<BlockLiveness> out(n);
    std::vector<std::unordered_set<std::string>> use_set(n), def_set(n);
    std::unordered_map<std::uint64_t, std::size_t> id_to_idx;
    std::unordered_map<std::uint64_t, std::size_t> va_to_idx;

    for (std::size_t i = 0; i < n; ++i) {
        out[i].block_id = fn.blocks[i].id;
        id_to_idx[fn.blocks[i].id] = i;
        va_to_idx[fn.blocks[i].start_va] = i;
        for (const auto& insn : fn.blocks[i].instructions) {
            for (const auto& s : insn.srcs) {
                if (is_reg_operand(s)) {
                    const std::string k = reg_key(s);
                    if (!def_set[i].count(k)) use_set[i].insert(k);
                }
            }
            for (const auto& d : insn.dsts) {
                if (is_reg_operand(d)) def_set[i].insert(reg_key(d));
            }
        }
    }

    bool changed = true;
    while (changed) {
        changed = false;
        for (std::size_t i = n; i-- > 0;) {
            std::unordered_set<std::string> new_out;
            for (const std::uint64_t succ : fn.blocks[i].successors) {
                auto it = id_to_idx.find(succ);
                if (it == id_to_idx.end()) it = va_to_idx.find(succ);
                if (it != id_to_idx.end() && it != va_to_idx.end()) {
                    new_out.insert(out[it->second].live_in.begin(), out[it->second].live_in.end());
                }
            }
            std::unordered_set<std::string> new_in = use_set[i];
            for (const auto& v : new_out) {
                if (!def_set[i].count(v)) new_in.insert(v);
            }
            if (new_out != out[i].live_out || new_in != out[i].live_in) {
                out[i].live_out = std::move(new_out);
                out[i].live_in = std::move(new_in);
                changed = true;
            }
        }
    }
    return out;
}

std::size_t IrOptimizer::eliminate_dead_code(IrFunction& fn) {
    std::size_t removed = 0;
    const auto liveness = compute_liveness(fn);

    for (std::size_t bi = 0; bi < fn.blocks.size(); ++bi) {
        auto& bb = fn.blocks[bi];
        std::unordered_set<std::string> live = liveness[bi].live_out;
        // Conservatively keep ArchRegs live at block exit
        for (const auto& insn : bb.instructions) {
            for (const auto& d : insn.dsts) {
                if (d.kind == IrOperand::Kind::ArchReg) live.insert(reg_key(d));
            }
        }

        std::vector<bool> keep(bb.instructions.size(), true);
        for (std::size_t i = bb.instructions.size(); i-- > 0;) {
            const auto& insn = bb.instructions[i];
            const bool only_vreg_dst =
                !insn.dsts.empty() &&
                std::all_of(insn.dsts.begin(), insn.dsts.end(),
                            [](const IrOperand& d) { return d.kind == IrOperand::Kind::VirtualReg; });

            if (only_vreg_dst && !has_side_effects(insn) &&
                (!writes_flags(insn) || !is_flags_live_after(bb, i))) {
                bool any_live = false;
                for (const auto& d : insn.dsts) {
                    if (live.count(reg_key(d))) {
                        any_live = true;
                        break;
                    }
                }
                if (!any_live) {
                    keep[i] = false;
                    ++removed;
                    continue;
                }
            }

            for (const auto& d : insn.dsts) {
                if (is_reg_operand(d)) live.erase(reg_key(d));
            }
            for (const auto& s : insn.srcs) {
                if (is_reg_operand(s)) live.insert(reg_key(s));
            }
        }

        std::vector<IrInstruction> filtered;
        filtered.reserve(bb.instructions.size());
        for (std::size_t i = 0; i < bb.instructions.size(); ++i) {
            if (keep[i]) filtered.push_back(std::move(bb.instructions[i]));
        }
        bb.instructions = std::move(filtered);
    }
    return removed;
}

std::size_t IrOptimizer::coalesce_virtual_registers(IrFunction& fn) {
    std::unordered_map<std::string, std::string> remap;
    std::size_t next_id = 0;

    auto map_vreg = [&](const std::string& name) -> std::string {
        auto it = remap.find(name);
        if (it != remap.end()) return it->second;
        std::string canonical = "v" + std::to_string(next_id++);
        remap.emplace(name, canonical);
        return canonical;
    };

    std::size_t changed = 0;
    for (auto& bb : fn.blocks) {
        for (auto& insn : bb.instructions) {
            for (auto& d : insn.dsts) {
                if (d.kind == IrOperand::Kind::VirtualReg) {
                    auto mapped = map_vreg(d.name);
                    if (mapped != d.name) {
                        d.name = std::move(mapped);
                        ++changed;
                    }
                }
            }
            for (auto& s : insn.srcs) {
                if (s.kind == IrOperand::Kind::VirtualReg) {
                    auto mapped = map_vreg(s.name);
                    if (mapped != s.name) {
                        s.name = std::move(mapped);
                        ++changed;
                    }
                }
            }
        }
    }
    return changed;
}

IrOptimizeStats IrOptimizer::optimize(IrFunction& fn, const IrOptimizeOptions& options) {
    IrOptimizeStats stats;
    stats.instructions_before = count_instructions(fn);
    if (options.level <= 0) {
        stats.instructions_after = stats.instructions_before;
        return stats;
    }

    const int max_iters = (options.level >= 3) ? 4 : (options.level == 2 ? 2 : 1);
    for (int iter = 0; iter < max_iters; ++iter) {
        std::size_t iter_changes = 0;
        ++stats.passes_run;

        if (options.enable_algebraic_simplification) {
            const auto c = simplify_expressions(fn);
            stats.algebraic_simplifications += c;
            iter_changes += c;
        }
        if (options.enable_constant_propagation || options.enable_constant_folding) {
            const auto c = propagate_and_fold_constants(fn);
            stats.constants_folded += c;
            iter_changes += c;
        }
        if (options.enable_copy_propagation && options.level >= 2) {
            const auto c = propagate_copies(fn);
            stats.copies_propagated += c;
            iter_changes += c;
        }
        if (options.enable_redundant_elim && options.level >= 2) {
            const auto c = eliminate_redundant_instructions(fn);
            stats.redundant_ops_removed += c;
            iter_changes += c;
        }
        if (options.enable_branch_simplification) {
            const auto c = simplify_branches(fn);
            stats.branches_simplified += c;
            iter_changes += c;
        }
        if (options.enable_dce) {
            const auto c = eliminate_dead_code(fn);
            stats.dead_instructions_removed += c;
            iter_changes += c;
        }
        if (iter_changes == 0) break;
    }

    if (options.enable_vreg_coalescing && options.level >= 2) {
        stats.vregs_coalesced = coalesce_virtual_registers(fn);
    }

    stats.instructions_after = count_instructions(fn);
    return stats;
}

IrOptimizeStats IrOptimizer::optimize(IrModule& mod, const IrOptimizeOptions& options) {
    IrOptimizeStats total;
    for (auto& fn : mod.functions) {
        const auto s = optimize(fn, options);
        total.instructions_before += s.instructions_before;
        total.instructions_after += s.instructions_after;
        total.constants_folded += s.constants_folded;
        total.copies_propagated += s.copies_propagated;
        total.algebraic_simplifications += s.algebraic_simplifications;
        total.dead_instructions_removed += s.dead_instructions_removed;
        total.redundant_ops_removed += s.redundant_ops_removed;
        total.branches_simplified += s.branches_simplified;
        total.vregs_coalesced += s.vregs_coalesced;
        total.passes_run += s.passes_run;
    }
    return total;
}

} // namespace bytemorph::core::ir
