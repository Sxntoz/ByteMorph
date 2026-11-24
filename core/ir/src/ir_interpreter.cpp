#include "bytemorph/core/ir/ir_interpreter.hpp"

#include <cmath>
#include <cstring>
#include <optional>
#include <unordered_map>

namespace bytemorph::core::ir {

namespace {

std::string canonical_reg_name(const std::string& name) {
    if (name == "eax" || name == "ax" || name == "al") return "rax";
    if (name == "ecx" || name == "cx" || name == "cl") return "rcx";
    if (name == "edx" || name == "dx" || name == "dl") return "rdx";
    if (name == "ebx" || name == "bx" || name == "bl") return "rbx";
    if (name == "esi" || name == "si" || name == "sil") return "rsi";
    if (name == "edi" || name == "di" || name == "dil") return "rdi";
    if (name == "esp") return "rsp";
    if (name == "ebp") return "rbp";
    if (name.size() >= 3 && name[0] == 'r' && std::isdigit(static_cast<unsigned char>(name[1])) &&
        (name.back() == 'd' || name.back() == 'w' || name.back() == 'b')) {
        return name.substr(0, name.size() - 1);
    }
    if (name.size() >= 2 && name[0] == 'w' && std::isdigit(static_cast<unsigned char>(name[1]))) {
        return "x" + name.substr(1);
    }
    if (name == "wzr" || name == "xzr") return "xzr";
    return name;
}

diagnostics::Result<std::uint64_t> eval_operand_checked(const IrOperand& op, const IrExecState& state) {
    using diagnostics::ErrorCode;
    switch (op.kind) {
        case IrOperand::Kind::Immediate:
            return static_cast<std::uint64_t>(op.imm);
        case IrOperand::Kind::VirtualReg:
        case IrOperand::Kind::ArchReg: {
            const auto cname = canonical_reg_name(op.name);
            if (cname == "xzr") return 0ULL;
            auto it = state.regs.find(cname);
            return (it != state.regs.end()) ? it->second : 0ULL;
        }
        case IrOperand::Kind::Memory: {
            if (state.memory.empty()) {
                return diagnostics::Result<std::uint64_t>::err(
                    ErrorCode::OutOfBounds, "IR virtual memory is empty", "IrInterpreter::execute");
            }
            const auto cname = canonical_reg_name(op.name);
            auto it = state.regs.find(cname);
            const std::uint64_t base_val = (it != state.regs.end()) ? it->second : 0ULL;
            const std::int64_t byte_addr = static_cast<std::int64_t>(base_val) + op.imm;
            const std::size_t width_bytes = (op.bit_width == 8) ? 1 : (op.bit_width == 16) ? 2 : (op.bit_width == 32) ? 4 : 8;
            const std::size_t total_bytes = state.memory.size() * sizeof(std::uint64_t);
            if (byte_addr < 0 || static_cast<std::size_t>(byte_addr) + width_bytes > total_bytes) {
                return diagnostics::Result<std::uint64_t>::err(
                    ErrorCode::OutOfBounds, "IR memory load out of bounds", "IrInterpreter::execute");
            }
            const auto* raw = reinterpret_cast<const std::uint8_t*>(state.memory.data()) + byte_addr;
            std::uint64_t out = 0;
            std::memcpy(&out, raw, width_bytes);
            return out;
        }
        default:
            return 0ULL;
    }
}

diagnostics::Result<void> write_operand_checked(const IrOperand& op, std::uint64_t val, IrExecState& state) {
    using diagnostics::ErrorCode;
    if (op.kind == IrOperand::Kind::VirtualReg || op.kind == IrOperand::Kind::ArchReg) {
        const auto cname = canonical_reg_name(op.name);
        if (cname != "xzr") {
            state.regs[cname] = val;
        }
        return diagnostics::Result<void>::ok();
    }
    if (op.kind == IrOperand::Kind::Memory) {
        if (state.memory.empty()) {
            return diagnostics::Result<void>::err(
                ErrorCode::OutOfBounds, "IR virtual memory is empty", "IrInterpreter::execute");
        }
        const auto cname = canonical_reg_name(op.name);
        auto it = state.regs.find(cname);
        const std::uint64_t base_val = (it != state.regs.end()) ? it->second : 0ULL;
        const std::int64_t byte_addr = static_cast<std::int64_t>(base_val) + op.imm;
        const std::size_t width_bytes = (op.bit_width == 8) ? 1 : (op.bit_width == 16) ? 2 : (op.bit_width == 32) ? 4 : 8;
        const std::size_t total_bytes = state.memory.size() * sizeof(std::uint64_t);
        if (byte_addr < 0 || static_cast<std::size_t>(byte_addr) + width_bytes > total_bytes) {
            return diagnostics::Result<void>::err(
                ErrorCode::OutOfBounds, "IR memory store out of bounds", "IrInterpreter::execute");
        }
        auto* raw = reinterpret_cast<std::uint8_t*>(state.memory.data()) + byte_addr;
        std::memcpy(raw, &val, width_bytes);
        return diagnostics::Result<void>::ok();
    }
    return diagnostics::Result<void>::ok();
}

std::optional<std::size_t> try_parse_vreg_index(const std::string& name) noexcept {
    if (name.size() >= 4 && (name.rfind("xmm", 0) == 0 || name.rfind("ymm", 0) == 0)) {
        std::size_t idx = 0;
        for (std::size_t i = 3; i < name.size(); ++i) {
            if (!std::isdigit(static_cast<unsigned char>(name[i]))) return std::nullopt;
            idx = idx * 10 + static_cast<std::size_t>(name[i] - '0');
        }
        return (idx < 32) ? std::optional<std::size_t>(idx) : std::nullopt;
    }
    if (name.size() >= 2 && (name[0] == 'v' || name[0] == 'd' || name[0] == 's' || name[0] == 'q')) {
        std::size_t idx = 0;
        for (std::size_t i = 1; i < name.size(); ++i) {
            if (name[i] == '.') break; // handle v0.16b / v0.4s
            if (!std::isdigit(static_cast<unsigned char>(name[i]))) return std::nullopt;
            idx = idx * 10 + static_cast<std::size_t>(name[i] - '0');
        }
        return (idx < 32) ? std::optional<std::size_t>(idx) : std::nullopt;
    }
    return std::nullopt;
}

bool eval_condition(const std::string& cond, const IrExecState& state) {
    if (cond == "eq" || cond == "je" || cond == "jz" || cond == "b.eq") return state.zf;
    if (cond == "ne" || cond == "jne" || cond == "jnz" || cond == "b.ne") return !state.zf;
    if (cond == "lt" || cond == "jl" || cond == "jnge" || cond == "b.lt") return state.sf != state.of;
    if (cond == "le" || cond == "jle" || cond == "jng" || cond == "b.le") return (state.sf != state.of) || state.zf;
    if (cond == "gt" || cond == "jg" || cond == "jnle" || cond == "b.gt") return (state.sf == state.of) && !state.zf;
    if (cond == "ge" || cond == "jge" || cond == "jnl" || cond == "b.ge") return state.sf == state.of;
    if (cond == "b" || cond == "jb" || cond == "jnae" || cond == "jc" || cond == "c" || cond == "b.lo" || cond == "b.cc" || cond == "lo" || cond == "cc") return state.cf;
    if (cond == "be" || cond == "jbe" || cond == "jna" || cond == "b.ls" || cond == "ls") return state.cf || state.zf;
    if (cond == "a" || cond == "ja" || cond == "jnbe" || cond == "b.hi" || cond == "hi") return !state.cf && !state.zf;
    if (cond == "ae" || cond == "jae" || cond == "jnb" || cond == "jnc" || cond == "nc" || cond == "b.hs" || cond == "b.cs" || cond == "hs" || cond == "cs") return !state.cf;
    if (cond == "s" || cond == "js" || cond == "b.mi" || cond == "mi") return state.sf;
    if (cond == "ns" || cond == "jns" || cond == "b.pl" || cond == "pl") return !state.sf;
    if (cond == "o" || cond == "jo" || cond == "b.vs" || cond == "vs") return state.of;
    if (cond == "no" || cond == "jno" || cond == "b.vc" || cond == "vc") return !state.of;
    if (cond == "p" || cond == "jp" || cond == "jpe") return state.pf;
    if (cond == "np" || cond == "jnp" || cond == "jpo") return !state.pf;
    return !state.zf;
}

} // namespace

diagnostics::Result<IrExecState>
IrInterpreter::execute(const IrFunction& fn, const IrExecOptions& options) {
    using diagnostics::ErrorCode;
    if (fn.blocks.empty()) {
        return diagnostics::Result<IrExecState>::err(
            ErrorCode::EmptyInput, "IrFunction has no basic blocks", "IrInterpreter::execute");
    }

    std::unordered_map<std::uint64_t, std::size_t> va_to_block;
    for (std::size_t i = 0; i < fn.blocks.size(); ++i) {
        va_to_block[fn.blocks[i].start_va] = i;
    }

    IrExecState state;
    state.vregs = options.initial_vregs;
    state.memory.assign(options.memory_slots, 0ULL);
    if (options.memory_slots > 0) {
        const std::uint64_t mid_stack = ((options.memory_slots * sizeof(std::uint64_t)) / 2) & ~15ULL;
        state.regs["rsp"] = mid_stack;
        state.regs["rbp"] = mid_stack;
        state.regs["sp"]  = mid_stack;
        state.regs["x29"] = mid_stack;
    }
    for (const auto& [k, v] : options.initial_regs) {
        state.regs[canonical_reg_name(k)] = v;
    }

    std::size_t block_idx = 0;
    if (va_to_block.contains(fn.entry_va)) {
        block_idx = va_to_block.at(fn.entry_va);
    }

    while (block_idx < fn.blocks.size()) {
        const auto& bb = fn.blocks[block_idx];
        bool jumped = false;

        for (std::size_t ip = 0; ip < bb.instructions.size(); ++ip) {
            if (state.steps_executed >= options.max_steps) {
                return diagnostics::Result<IrExecState>::err(
                    ErrorCode::OutOfBounds, "IR execution exceeded max_steps limit", "IrInterpreter::execute");
            }
            ++state.steps_executed;

            const auto& insn = bb.instructions[ip];
            switch (insn.opcode) {
                case IrOpcode::Nop:
                    break;
                case IrOpcode::Mov:
                case IrOpcode::Load:
                case IrOpcode::Store:
                    if (!insn.dsts.empty() && !insn.srcs.empty()) {
                        auto v = eval_operand_checked(insn.srcs[0], state);
                        if (!v) return diagnostics::Result<IrExecState>::err(v.error().code, v.error().message, v.error().context);
                        auto w = write_operand_checked(insn.dsts[0], v.value(), state);
                        if (!w) return diagnostics::Result<IrExecState>::err(w.error().code, w.error().message, w.error().context);
                    }
                    break;
                case IrOpcode::Add:
                case IrOpcode::Sub:
                case IrOpcode::Mul:
                case IrOpcode::Div:
                case IrOpcode::And:
                case IrOpcode::Or:
                case IrOpcode::Xor:
                case IrOpcode::Shl:
                case IrOpcode::Shr:
                case IrOpcode::Adc:
                case IrOpcode::Sbb:
                    if (!insn.dsts.empty() && insn.srcs.size() >= 2) {
                        auto v1 = eval_operand_checked(insn.srcs[0], state);
                        auto v2 = eval_operand_checked(insn.srcs[1], state);
                        if (!v1) return diagnostics::Result<IrExecState>::err(v1.error().code, v1.error().message, v1.error().context);
                        if (!v2) return diagnostics::Result<IrExecState>::err(v2.error().code, v2.error().message, v2.error().context);
                        const std::uint64_t u1 = v1.value();
                        const std::uint64_t u2 = v2.value();
                        std::uint64_t res = 0;
                        bool next_cf = state.cf;
                        bool next_of = state.of;
                        switch (insn.opcode) {
                            case IrOpcode::Add:
                                res = u1 + u2;
                                next_cf = (res < u1);
                                next_of = (((~(u1 ^ u2) & (u1 ^ res)) >> 63) != 0);
                                break;
                            case IrOpcode::Sub:
                                res = u1 - u2;
                                next_cf = (u1 < u2);
                                next_of = ((((u1 ^ u2) & (u1 ^ res)) >> 63) != 0);
                                break;
                            case IrOpcode::Adc: {
                                const std::uint64_t c = state.cf ? 1ULL : 0ULL;
                                res = u1 + u2 + c;
                                next_cf = (res < u1) || (c != 0 && res == u1);
                                next_of = (((~(u1 ^ u2) & (u1 ^ res)) >> 63) != 0);
                                break;
                            }
                            case IrOpcode::Sbb: {
                                const std::uint64_t c = state.cf ? 1ULL : 0ULL;
                                res = u1 - u2 - c;
                                next_cf = (u1 < u2) || (c != 0 && (u1 - u2) == 0);
                                next_of = ((((u1 ^ u2) & (u1 ^ res)) >> 63) != 0);
                                break;
                            }
                            case IrOpcode::Mul: res = u1 * u2; break;
                            case IrOpcode::Div:
                                if (u2 == 0) {
                                    return diagnostics::Result<IrExecState>::err(
                                        ErrorCode::InternalError, "Division by zero in IR interpreter", "IrInterpreter::execute");
                                }
                                res = u1 / u2;
                                break;
                            case IrOpcode::And: res = u1 & u2; next_cf = false; next_of = false; break;
                            case IrOpcode::Or:  res = u1 | u2; next_cf = false; next_of = false; break;
                            case IrOpcode::Xor: res = u1 ^ u2; next_cf = false; next_of = false; break;
                            case IrOpcode::Shl: res = u1 << (u2 & 63ULL); break;
                            case IrOpcode::Shr: res = u1 >> (u2 & 63ULL); break;
                            default: break;
                        }
                        auto w = write_operand_checked(insn.dsts[0], res, state);
                        if (!w) return diagnostics::Result<IrExecState>::err(w.error().code, w.error().message, w.error().context);
                        state.zf = (res == 0);
                        state.sf = (static_cast<std::int64_t>(res) < 0);
                        state.cf = next_cf;
                        state.of = next_of;
                    }
                    break;
                case IrOpcode::Cmp:
                    if (insn.srcs.size() >= 2) {
                        auto v1 = eval_operand_checked(insn.srcs[0], state);
                        auto v2 = eval_operand_checked(insn.srcs[1], state);
                        if (!v1) return diagnostics::Result<IrExecState>::err(v1.error().code, v1.error().message, v1.error().context);
                        if (!v2) return diagnostics::Result<IrExecState>::err(v2.error().code, v2.error().message, v2.error().context);
                        const std::uint64_t u1 = v1.value();
                        const std::uint64_t u2 = v2.value();
                        const std::uint64_t diff = u1 - u2;
                        state.zf = (diff == 0);
                        state.sf = (static_cast<std::int64_t>(diff) < 0);
                        state.cf = (u1 < u2);
                        state.of = ((((u1 ^ u2) & (u1 ^ diff)) >> 63) != 0);
                    }
                    break;
                case IrOpcode::LeaGlobal:
                    if (!insn.dsts.empty() && !insn.srcs.empty()) {
                        const std::uint64_t target_va = static_cast<std::uint64_t>(insn.srcs[0].imm) + options.pic_base_va;
                        auto w = write_operand_checked(insn.dsts[0], target_va, state);
                        if (!w) return diagnostics::Result<IrExecState>::err(w.error().code, w.error().message, w.error().context);
                    }
                    break;
                case IrOpcode::SelectCc: {
                    const std::string& c = insn.cond.empty() ? insn.comment : insn.cond;
                    if (!insn.dsts.empty() && !insn.srcs.empty() && eval_condition(c, state)) {
                        auto v = eval_operand_checked(insn.srcs[0], state);
                        if (!v) return diagnostics::Result<IrExecState>::err(v.error().code, v.error().message, v.error().context);
                        auto w = write_operand_checked(insn.dsts[0], v.value(), state);
                        if (!w) return diagnostics::Result<IrExecState>::err(w.error().code, w.error().message, w.error().context);
                    }
                    break;
                }
                case IrOpcode::SetCc: {
                    const std::string& c = insn.cond.empty() ? insn.comment : insn.cond;
                    if (!insn.dsts.empty()) {
                        const std::uint64_t val = eval_condition(c, state) ? 1ULL : 0ULL;
                        auto w = write_operand_checked(insn.dsts[0], val, state);
                        if (!w) return diagnostics::Result<IrExecState>::err(w.error().code, w.error().message, w.error().context);
                    }
                    break;
                }
                case IrOpcode::VMov: {
                    if (!insn.dsts.empty() && !insn.srcs.empty()) {
                        const auto d_v = try_parse_vreg_index(insn.dsts[0].name);
                        const auto s_v = try_parse_vreg_index(insn.srcs[0].name);
                        if (d_v && s_v) {
                            if (insn.dsts[0].bit_width == 32) {
                                state.vregs[*d_v][0] = (state.vregs[*d_v][0] & ~0xFFFFFFFFULL) | (state.vregs[*s_v][0] & 0xFFFFFFFFULL);
                            } else if (insn.dsts[0].bit_width == 64) {
                                state.vregs[*d_v][0] = state.vregs[*s_v][0];
                            } else {
                                state.vregs[*d_v] = state.vregs[*s_v];
                            }
                        } else if (d_v && insn.srcs[0].kind == IrOperand::Kind::Memory) {
                            auto v = eval_operand_checked(insn.srcs[0], state);
                            if (!v) return diagnostics::Result<IrExecState>::err(v.error().code, v.error().message, v.error().context);
                            state.vregs[*d_v][0] = v.value();
                        } else if (s_v && insn.dsts[0].kind == IrOperand::Kind::Memory) {
                            auto w = write_operand_checked(insn.dsts[0], state.vregs[*s_v][0], state);
                            if (!w) return diagnostics::Result<IrExecState>::err(w.error().code, w.error().message, w.error().context);
                        } else if (d_v && (insn.srcs[0].kind == IrOperand::Kind::ArchReg || insn.srcs[0].kind == IrOperand::Kind::VirtualReg || insn.srcs[0].kind == IrOperand::Kind::Immediate)) {
                            auto v = eval_operand_checked(insn.srcs[0], state);
                            if (!v) return diagnostics::Result<IrExecState>::err(v.error().code, v.error().message, v.error().context);
                            state.vregs[*d_v][0] = v.value();
                        } else if (s_v && (insn.dsts[0].kind == IrOperand::Kind::ArchReg || insn.dsts[0].kind == IrOperand::Kind::VirtualReg)) {
                            auto w = write_operand_checked(insn.dsts[0], state.vregs[*s_v][0], state);
                            if (!w) return diagnostics::Result<IrExecState>::err(w.error().code, w.error().message, w.error().context);
                        }
                    }
                    break;
                }
                case IrOpcode::FAdd:
                case IrOpcode::FSub:
                case IrOpcode::FMul:
                case IrOpcode::FDiv: {
                    if (!insn.dsts.empty() && insn.srcs.size() >= 2) {
                        const auto d_v = try_parse_vreg_index(insn.dsts[0].name);
                        const auto s1_v = try_parse_vreg_index(insn.srcs[0].name);
                        const auto s2_v = try_parse_vreg_index(insn.srcs[1].name);
                        if (d_v && s1_v && s2_v) {
                            const bool is_f32 = (insn.dsts[0].bit_width == 32);
                            if (is_f32) {
                                float a = 0.0f, b = 0.0f;
                                std::uint32_t ua = static_cast<std::uint32_t>(state.vregs[*s1_v][0]);
                                std::uint32_t ub = static_cast<std::uint32_t>(state.vregs[*s2_v][0]);
                                std::memcpy(&a, &ua, 4);
                                std::memcpy(&b, &ub, 4);
                                float r = 0.0f;
                                if (insn.opcode == IrOpcode::FAdd) r = a + b;
                                else if (insn.opcode == IrOpcode::FSub) r = a - b;
                                else if (insn.opcode == IrOpcode::FMul) r = a * b;
                                else r = a / b;
                                std::uint32_t ur = 0;
                                std::memcpy(&ur, &r, 4);
                                state.vregs[*d_v][0] = (state.vregs[*d_v][0] & ~0xFFFFFFFFULL) | static_cast<std::uint64_t>(ur);
                            } else {
                                double a = 0.0, b = 0.0;
                                std::memcpy(&a, &state.vregs[*s1_v][0], 8);
                                std::memcpy(&b, &state.vregs[*s2_v][0], 8);
                                double r = 0.0;
                                if (insn.opcode == IrOpcode::FAdd) r = a + b;
                                else if (insn.opcode == IrOpcode::FSub) r = a - b;
                                else if (insn.opcode == IrOpcode::FMul) r = a * b;
                                else r = a / b;
                                std::memcpy(&state.vregs[*d_v][0], &r, 8);
                            }
                        }
                    }
                    break;
                }
                case IrOpcode::FCmp: {
                    if (insn.srcs.size() >= 2) {
                        const auto s1_v = try_parse_vreg_index(insn.srcs[0].name);
                        const auto s2_v = try_parse_vreg_index(insn.srcs[1].name);
                        if (s1_v && s2_v) {
                            const bool is_f32 = (insn.srcs[0].bit_width == 32);
                            double a = 0.0, b = 0.0;
                            if (is_f32) {
                                float fa = 0.0f, fb = 0.0f;
                                std::uint32_t ua = static_cast<std::uint32_t>(state.vregs[*s1_v][0]);
                                std::uint32_t ub = static_cast<std::uint32_t>(state.vregs[*s2_v][0]);
                                std::memcpy(&fa, &ua, 4);
                                std::memcpy(&fb, &ub, 4);
                                a = static_cast<double>(fa);
                                b = static_cast<double>(fb);
                            } else {
                                std::memcpy(&a, &state.vregs[*s1_v][0], 8);
                                std::memcpy(&b, &state.vregs[*s2_v][0], 8);
                            }
                            if (std::isnan(a) || std::isnan(b)) {
                                state.zf = true; state.cf = true; state.pf = true;
                            } else if (a < b) {
                                state.zf = false; state.cf = true; state.pf = false;
                            } else if (a > b) {
                                state.zf = false; state.cf = false; state.pf = false;
                            } else {
                                state.zf = true; state.cf = false; state.pf = false;
                            }
                            state.sf = false;
                            state.of = false;
                        }
                    }
                    break;
                }
                case IrOpcode::Jump:
                    if (!insn.srcs.empty() && insn.srcs[0].kind == IrOperand::Kind::Label) {
                        const std::uint64_t target = static_cast<std::uint64_t>(insn.srcs[0].imm);
                        if (!va_to_block.contains(target)) {
                            return diagnostics::Result<IrExecState>::err(
                                ErrorCode::OutOfBounds, "Jump target block not found in IR", "IrInterpreter::execute");
                        }
                        block_idx = va_to_block.at(target);
                        jumped = true;
                    }
                    break;
                case IrOpcode::JumpCond: {
                    const std::string& c = insn.cond.empty() ? insn.comment : insn.cond;
                    if (eval_condition(c, state) && !insn.srcs.empty() && insn.srcs[0].kind == IrOperand::Kind::Label) {
                        const std::uint64_t target = static_cast<std::uint64_t>(insn.srcs[0].imm);
                        if (!va_to_block.contains(target)) {
                            return diagnostics::Result<IrExecState>::err(
                                ErrorCode::OutOfBounds, "JumpCond target block not found in IR", "IrInterpreter::execute");
                        }
                        block_idx = va_to_block.at(target);
                        jumped = true;
                    }
                    break;
                }
                case IrOpcode::Ret:
                    if (state.regs.contains("rax")) state.return_value = state.regs.at("rax");
                    else if (state.regs.contains("x0")) state.return_value = state.regs.at("x0");
                    else if (state.regs.contains("r0")) state.return_value = state.regs.at("r0");
                    return state;
                case IrOpcode::Call:
                case IrOpcode::Syscall:
                case IrOpcode::Unknown:
                    return diagnostics::Result<IrExecState>::err(
                        ErrorCode::UnsupportedFormat,
                        "Unsupported opcode in standalone IR interpreter",
                        "IrInterpreter::execute");
            }

            if (jumped) break;
        }

        if (!jumped) {
            std::optional<std::uint64_t> fallthrough_va;
            if (!bb.instructions.empty() && bb.instructions.back().opcode == IrOpcode::JumpCond &&
                !bb.instructions.back().srcs.empty() && bb.instructions.back().srcs[0].kind == IrOperand::Kind::Label) {
                const std::uint64_t branch_va = static_cast<std::uint64_t>(bb.instructions.back().srcs[0].imm);
                for (const auto succ : bb.successors) {
                    if (succ != branch_va) {
                        fallthrough_va = succ;
                        break;
                    }
                }
            } else if (!bb.successors.empty()) {
                fallthrough_va = bb.successors[0];
            }

            if (fallthrough_va && va_to_block.contains(*fallthrough_va)) {
                block_idx = va_to_block.at(*fallthrough_va);
            } else {
                ++block_idx;
            }
        }
    }

    if (state.regs.contains("rax")) state.return_value = state.regs.at("rax");
    else if (state.regs.contains("x0")) state.return_value = state.regs.at("x0");
    else if (state.regs.contains("r0")) state.return_value = state.regs.at("r0");
    return state;
}

} // namespace bytemorph::core::ir
