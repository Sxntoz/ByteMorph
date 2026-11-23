#include "bytemorph/core/ir/ir_interpreter.hpp"

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
    if (name.size() >= 2 && name[0] == 'r' && name.back() == 'd' && std::isdigit(static_cast<unsigned char>(name[1]))) {
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

bool eval_condition(const std::string& cond, const IrExecState& state) {
    if (cond == "je" || cond == "jz" || cond == "b.eq") return state.zf;
    if (cond == "jne" || cond == "jnz" || cond == "b.ne") return !state.zf;
    if (cond == "jl" || cond == "jnge" || cond == "jb" || cond == "jnae" || cond == "jc" || cond == "js" || cond == "b.lt" || cond == "b.lo" || cond == "b.cc" || cond == "b.mi") return state.sf;
    if (cond == "jle" || cond == "jng" || cond == "jbe" || cond == "jna" || cond == "b.le" || cond == "b.ls") return state.sf || state.zf;
    if (cond == "jg" || cond == "jnle" || cond == "ja" || cond == "jnbe" || cond == "b.gt" || cond == "b.hi") return !state.sf && !state.zf;
    if (cond == "jge" || cond == "jnl" || cond == "jae" || cond == "jnb" || cond == "jnc" || cond == "jns" || cond == "b.ge" || cond == "b.hs" || cond == "b.cs" || cond == "b.pl") return !state.sf;
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
                    if (!insn.dsts.empty() && insn.srcs.size() >= 2) {
                        auto v1 = eval_operand_checked(insn.srcs[0], state);
                        auto v2 = eval_operand_checked(insn.srcs[1], state);
                        if (!v1) return diagnostics::Result<IrExecState>::err(v1.error().code, v1.error().message, v1.error().context);
                        if (!v2) return diagnostics::Result<IrExecState>::err(v2.error().code, v2.error().message, v2.error().context);
                        std::uint64_t res = 0;
                        switch (insn.opcode) {
                            case IrOpcode::Add: res = v1.value() + v2.value(); break;
                            case IrOpcode::Sub: res = v1.value() - v2.value(); break;
                            case IrOpcode::Mul: res = v1.value() * v2.value(); break;
                            case IrOpcode::Div:
                                if (v2.value() == 0) {
                                    return diagnostics::Result<IrExecState>::err(
                                        ErrorCode::InternalError, "Division by zero in IR interpreter", "IrInterpreter::execute");
                                }
                                res = v1.value() / v2.value();
                                break;
                            case IrOpcode::And: res = v1.value() & v2.value(); break;
                            case IrOpcode::Or:  res = v1.value() | v2.value(); break;
                            case IrOpcode::Xor: res = v1.value() ^ v2.value(); break;
                            case IrOpcode::Shl: res = v1.value() << (v2.value() & 63ULL); break;
                            case IrOpcode::Shr: res = v1.value() >> (v2.value() & 63ULL); break;
                            default: break;
                        }
                        auto w = write_operand_checked(insn.dsts[0], res, state);
                        if (!w) return diagnostics::Result<IrExecState>::err(w.error().code, w.error().message, w.error().context);
                        state.zf = (res == 0);
                        state.sf = (static_cast<std::int64_t>(res) < 0);
                    }
                    break;
                case IrOpcode::Cmp:
                    if (insn.srcs.size() >= 2) {
                        auto v1 = eval_operand_checked(insn.srcs[0], state);
                        auto v2 = eval_operand_checked(insn.srcs[1], state);
                        if (!v1) return diagnostics::Result<IrExecState>::err(v1.error().code, v1.error().message, v1.error().context);
                        if (!v2) return diagnostics::Result<IrExecState>::err(v2.error().code, v2.error().message, v2.error().context);
                        const auto lhs = static_cast<std::int64_t>(v1.value());
                        const auto rhs = static_cast<std::int64_t>(v2.value());
                        state.zf = (lhs == rhs);
                        state.sf = (lhs < rhs);
                    }
                    break;
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
