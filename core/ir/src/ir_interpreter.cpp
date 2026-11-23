#include "bytemorph/core/ir/ir_interpreter.hpp"

#include <optional>
#include <unordered_map>

namespace bytemorph::core::ir {

namespace {

std::uint64_t eval_operand(const IrOperand& op, const IrExecState& state) {
    switch (op.kind) {
        case IrOperand::Kind::Immediate:
            return static_cast<std::uint64_t>(op.imm);
        case IrOperand::Kind::VirtualReg:
        case IrOperand::Kind::ArchReg: {
            auto it = state.regs.find(op.name);
            return (it != state.regs.end()) ? it->second : 0ULL;
        }
        case IrOperand::Kind::Memory: {
            auto it = state.regs.find(op.name);
            const std::uint64_t idx = (it != state.regs.end()) ? (it->second % state.memory.size()) : 0ULL;
            return state.memory.empty() ? 0ULL : state.memory[idx];
        }
        default:
            return 0ULL;
    }
}

void write_operand(const IrOperand& op, std::uint64_t val, IrExecState& state) {
    if (op.kind == IrOperand::Kind::VirtualReg || op.kind == IrOperand::Kind::ArchReg) {
        state.regs[op.name] = val;
    } else if (op.kind == IrOperand::Kind::Memory && !state.memory.empty()) {
        auto it = state.regs.find(op.name);
        const std::uint64_t idx = (it != state.regs.end()) ? (it->second % state.memory.size()) : 0ULL;
        state.memory[idx] = val;
    }
}

bool eval_condition(const std::string& cond, const IrExecState& state) {
    if (cond == "je" || cond == "jz" || cond == "b.eq") return state.zf;
    if (cond == "jne" || cond == "jnz" || cond == "b.ne") return !state.zf;
    if (cond == "jl" || cond == "b.lt") return state.sf;
    if (cond == "jle" || cond == "b.le") return state.sf || state.zf;
    if (cond == "jg" || cond == "b.gt") return !state.sf && !state.zf;
    if (cond == "jge" || cond == "b.ge") return !state.sf;
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
    state.regs = options.initial_regs;
    state.memory.assign(options.memory_slots, 0ULL);

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
                    if (!insn.dsts.empty() && !insn.srcs.empty()) {
                        write_operand(insn.dsts[0], eval_operand(insn.srcs[0], state), state);
                    }
                    break;
                case IrOpcode::Load:
                    if (!insn.dsts.empty() && !insn.srcs.empty()) {
                        write_operand(insn.dsts[0], eval_operand(insn.srcs[0], state), state);
                    }
                    break;
                case IrOpcode::Store:
                    if (!insn.dsts.empty() && !insn.srcs.empty()) {
                        write_operand(insn.dsts[0], eval_operand(insn.srcs[0], state), state);
                    }
                    break;
                case IrOpcode::Add:
                    if (!insn.dsts.empty() && insn.srcs.size() >= 2) {
                        const auto res = eval_operand(insn.srcs[0], state) + eval_operand(insn.srcs[1], state);
                        write_operand(insn.dsts[0], res, state);
                        state.zf = (res == 0);
                        state.sf = (static_cast<std::int64_t>(res) < 0);
                    }
                    break;
                case IrOpcode::Sub:
                    if (!insn.dsts.empty() && insn.srcs.size() >= 2) {
                        const auto res = eval_operand(insn.srcs[0], state) - eval_operand(insn.srcs[1], state);
                        write_operand(insn.dsts[0], res, state);
                        state.zf = (res == 0);
                        state.sf = (static_cast<std::int64_t>(res) < 0);
                    }
                    break;
                case IrOpcode::Mul:
                    if (!insn.dsts.empty() && insn.srcs.size() >= 2) {
                        const auto res = eval_operand(insn.srcs[0], state) * eval_operand(insn.srcs[1], state);
                        write_operand(insn.dsts[0], res, state);
                        state.zf = (res == 0);
                        state.sf = (static_cast<std::int64_t>(res) < 0);
                    }
                    break;
                case IrOpcode::Div:
                    if (!insn.dsts.empty() && insn.srcs.size() >= 2) {
                        const auto denom = eval_operand(insn.srcs[1], state);
                        if (denom == 0) {
                            return diagnostics::Result<IrExecState>::err(
                                ErrorCode::InternalError, "Division by zero in IR interpreter", "IrInterpreter::execute");
                        }
                        const auto res = eval_operand(insn.srcs[0], state) / denom;
                        write_operand(insn.dsts[0], res, state);
                        state.zf = (res == 0);
                        state.sf = (static_cast<std::int64_t>(res) < 0);
                    }
                    break;
                case IrOpcode::And:
                    if (!insn.dsts.empty() && insn.srcs.size() >= 2) {
                        const auto res = eval_operand(insn.srcs[0], state) & eval_operand(insn.srcs[1], state);
                        write_operand(insn.dsts[0], res, state);
                        state.zf = (res == 0);
                        state.sf = (static_cast<std::int64_t>(res) < 0);
                    }
                    break;
                case IrOpcode::Or:
                    if (!insn.dsts.empty() && insn.srcs.size() >= 2) {
                        const auto res = eval_operand(insn.srcs[0], state) | eval_operand(insn.srcs[1], state);
                        write_operand(insn.dsts[0], res, state);
                        state.zf = (res == 0);
                        state.sf = (static_cast<std::int64_t>(res) < 0);
                    }
                    break;
                case IrOpcode::Xor:
                    if (!insn.dsts.empty() && insn.srcs.size() >= 2) {
                        const auto res = eval_operand(insn.srcs[0], state) ^ eval_operand(insn.srcs[1], state);
                        write_operand(insn.dsts[0], res, state);
                        state.zf = (res == 0);
                        state.sf = (static_cast<std::int64_t>(res) < 0);
                    }
                    break;
                case IrOpcode::Shl:
                    if (!insn.dsts.empty() && insn.srcs.size() >= 2) {
                        const auto sh = eval_operand(insn.srcs[1], state) & 63ULL;
                        const auto res = eval_operand(insn.srcs[0], state) << sh;
                        write_operand(insn.dsts[0], res, state);
                        state.zf = (res == 0);
                        state.sf = (static_cast<std::int64_t>(res) < 0);
                    }
                    break;
                case IrOpcode::Shr:
                    if (!insn.dsts.empty() && insn.srcs.size() >= 2) {
                        const auto sh = eval_operand(insn.srcs[1], state) & 63ULL;
                        const auto res = eval_operand(insn.srcs[0], state) >> sh;
                        write_operand(insn.dsts[0], res, state);
                        state.zf = (res == 0);
                        state.sf = (static_cast<std::int64_t>(res) < 0);
                    }
                    break;
                case IrOpcode::Cmp:
                    if (insn.srcs.size() >= 2) {
                        const auto lhs = static_cast<std::int64_t>(eval_operand(insn.srcs[0], state));
                        const auto rhs = static_cast<std::int64_t>(eval_operand(insn.srcs[1], state));
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
