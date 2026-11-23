#include "bytemorph/virt/vm_interpreter.hpp"

#include <cstring>

namespace bytemorph::virt {

core::diagnostics::Result<VmExecState>
VmInterpreter::execute(const BvmProgram& program, const VmExecOptions& options) {
    using core::diagnostics::ErrorCode;

    if (program.instructions.empty()) {
        return core::diagnostics::Result<VmExecState>::err(
            ErrorCode::EmptyInput, "BvmProgram has no instructions", "VmInterpreter::execute");
    }

    VmExecState state;
    state.regs = options.initial_regs;
    state.memory.assign(options.memory_slots, 0ULL);
    if (options.memory_slots > 0 && state.regs[4] == 0 && state.regs[5] == 0) {
        const std::uint64_t mid_stack = ((options.memory_slots * sizeof(std::uint64_t)) / 2) & ~15ULL;
        state.regs[4] = mid_stack;
        state.regs[5] = mid_stack;
    }

    const std::size_t code_len = program.instructions.size();

    while (state.pc < code_len) {
        if (state.steps_executed >= options.max_steps) {
            return core::diagnostics::Result<VmExecState>::err(
                ErrorCode::OutOfBounds, "VM execution exceeded max_steps limit", "VmInterpreter::execute");
        }
        ++state.steps_executed;

        const auto& insn = program.instructions[state.pc];
        if (insn.opcode == VmOpcode::Halt && insn.dst == 0xFF) {
            return core::diagnostics::Result<VmExecState>::err(
                ErrorCode::OutOfBounds, "Unauthorized indirect control-flow target at runtime", "VmInterpreter::execute");
        }
        const bool src2_is_width = (insn.opcode == VmOpcode::Load || insn.opcode == VmOpcode::Store);
        if (insn.dst >= BvmProgram::kNumRegisters ||
            insn.src1 >= BvmProgram::kNumRegisters ||
            (!src2_is_width && insn.src2 >= BvmProgram::kNumRegisters)) {
            return core::diagnostics::Result<VmExecState>::err(
                ErrorCode::OutOfBounds, "Register index out of bounds", "VmInterpreter::execute");
        }

        auto check_target = [&](std::int64_t target) -> core::diagnostics::Result<std::size_t> {
            if (target < 0 || static_cast<std::size_t>(target) >= code_len) {
                return core::diagnostics::Result<std::size_t>::err(
                    ErrorCode::OutOfBounds, "VM branch/call target out of bounds", "VmInterpreter::execute");
            }
            return static_cast<std::size_t>(target);
        };

        switch (insn.opcode) {
            case VmOpcode::Nop:
                ++state.pc;
                break;
            case VmOpcode::MovReg:
                state.regs[insn.dst] = state.regs[insn.src1];
                ++state.pc;
                break;
            case VmOpcode::MovImm:
                state.regs[insn.dst] = static_cast<std::uint64_t>(insn.imm);
                ++state.pc;
                break;
            case VmOpcode::Load: {
                if (state.memory.empty()) {
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::OutOfBounds, "VM memory is empty", "VmInterpreter::execute");
                }
                if (insn.src2 == 0) {
                    const std::uint64_t addr = state.regs[insn.src1] + static_cast<std::uint64_t>(insn.imm);
                    if (addr >= state.memory.size()) {
                        return core::diagnostics::Result<VmExecState>::err(
                            ErrorCode::OutOfBounds, "VM memory load out of bounds", "VmInterpreter::execute");
                    }
                    state.regs[insn.dst] = state.memory[addr];
                } else {
                    const std::size_t width_bytes = (insn.src2 == 8) ? 1 : (insn.src2 == 16) ? 2 : (insn.src2 == 32) ? 4 : 8;
                    const std::int64_t byte_addr = static_cast<std::int64_t>(state.regs[insn.src1]) + insn.imm;
                    const std::size_t total_bytes = state.memory.size() * sizeof(std::uint64_t);
                    if (byte_addr < 0 || static_cast<std::size_t>(byte_addr) + width_bytes > total_bytes) {
                        return core::diagnostics::Result<VmExecState>::err(
                            ErrorCode::OutOfBounds, "VM memory load out of bounds", "VmInterpreter::execute");
                    }
                    std::uint64_t val = 0;
                    std::memcpy(&val, reinterpret_cast<const std::uint8_t*>(state.memory.data()) + byte_addr, width_bytes);
                    state.regs[insn.dst] = val;
                }
                ++state.pc;
                break;
            }
            case VmOpcode::Store: {
                if (state.memory.empty()) {
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::OutOfBounds, "VM memory is empty", "VmInterpreter::execute");
                }
                if (insn.src2 == 0) {
                    const std::uint64_t addr = state.regs[insn.dst] + static_cast<std::uint64_t>(insn.imm);
                    if (addr >= state.memory.size()) {
                        return core::diagnostics::Result<VmExecState>::err(
                            ErrorCode::OutOfBounds, "VM memory store out of bounds", "VmInterpreter::execute");
                    }
                    state.memory[addr] = state.regs[insn.src1];
                } else {
                    const std::size_t width_bytes = (insn.src2 == 8) ? 1 : (insn.src2 == 16) ? 2 : (insn.src2 == 32) ? 4 : 8;
                    const std::int64_t byte_addr = static_cast<std::int64_t>(state.regs[insn.dst]) + insn.imm;
                    const std::size_t total_bytes = state.memory.size() * sizeof(std::uint64_t);
                    if (byte_addr < 0 || static_cast<std::size_t>(byte_addr) + width_bytes > total_bytes) {
                        return core::diagnostics::Result<VmExecState>::err(
                            ErrorCode::OutOfBounds, "VM memory store out of bounds", "VmInterpreter::execute");
                    }
                    const std::uint64_t val = state.regs[insn.src1];
                    std::memcpy(reinterpret_cast<std::uint8_t*>(state.memory.data()) + byte_addr, &val, width_bytes);
                }
                ++state.pc;
                break;
            }
            case VmOpcode::Add: {
                const auto res = state.regs[insn.src1] + state.regs[insn.src2];
                state.regs[insn.dst] = res;
                state.zf = (res == 0);
                state.sf = (static_cast<std::int64_t>(res) < 0);
                ++state.pc;
                break;
            }
            case VmOpcode::Sub: {
                const auto res = state.regs[insn.src1] - state.regs[insn.src2];
                state.regs[insn.dst] = res;
                state.zf = (res == 0);
                state.sf = (static_cast<std::int64_t>(res) < 0);
                ++state.pc;
                break;
            }
            case VmOpcode::Mul: {
                const auto res = state.regs[insn.src1] * state.regs[insn.src2];
                state.regs[insn.dst] = res;
                state.zf = (res == 0);
                state.sf = (static_cast<std::int64_t>(res) < 0);
                ++state.pc;
                break;
            }
            case VmOpcode::Div: {
                if (state.regs[insn.src2] == 0) {
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::InternalError, "Division by zero in VM", "VmInterpreter::execute");
                }
                const auto res = state.regs[insn.src1] / state.regs[insn.src2];
                state.regs[insn.dst] = res;
                state.zf = (res == 0);
                state.sf = (static_cast<std::int64_t>(res) < 0);
                ++state.pc;
                break;
            }
            case VmOpcode::And: {
                const auto res = state.regs[insn.src1] & state.regs[insn.src2];
                state.regs[insn.dst] = res;
                state.zf = (res == 0);
                state.sf = (static_cast<std::int64_t>(res) < 0);
                ++state.pc;
                break;
            }
            case VmOpcode::Or: {
                const auto res = state.regs[insn.src1] | state.regs[insn.src2];
                state.regs[insn.dst] = res;
                state.zf = (res == 0);
                state.sf = (static_cast<std::int64_t>(res) < 0);
                ++state.pc;
                break;
            }
            case VmOpcode::Xor: {
                const auto res = state.regs[insn.src1] ^ state.regs[insn.src2];
                state.regs[insn.dst] = res;
                state.zf = (res == 0);
                state.sf = (static_cast<std::int64_t>(res) < 0);
                ++state.pc;
                break;
            }
            case VmOpcode::Shl: {
                const auto sh = state.regs[insn.src2] & 63ULL;
                const auto res = state.regs[insn.src1] << sh;
                state.regs[insn.dst] = res;
                state.zf = (res == 0);
                state.sf = (static_cast<std::int64_t>(res) < 0);
                ++state.pc;
                break;
            }
            case VmOpcode::Shr: {
                const auto sh = state.regs[insn.src2] & 63ULL;
                const auto res = state.regs[insn.src1] >> sh;
                state.regs[insn.dst] = res;
                state.zf = (res == 0);
                state.sf = (static_cast<std::int64_t>(res) < 0);
                ++state.pc;
                break;
            }
            case VmOpcode::Cmp: {
                const auto lhs = static_cast<std::int64_t>(state.regs[insn.src1]);
                const auto rhs = static_cast<std::int64_t>(state.regs[insn.src2]);
                state.zf = (lhs == rhs);
                state.sf = (lhs < rhs);
                ++state.pc;
                break;
            }
            case VmOpcode::Jmp: {
                auto t = check_target(insn.imm);
                if (!t) return core::diagnostics::Result<VmExecState>::err(t.error().code, t.error().message, t.error().context);
                state.pc = t.value();
                break;
            }
            case VmOpcode::Jeq:
                if (state.zf) {
                    auto t = check_target(insn.imm);
                    if (!t) return core::diagnostics::Result<VmExecState>::err(t.error().code, t.error().message, t.error().context);
                    state.pc = t.value();
                } else {
                    ++state.pc;
                }
                break;
            case VmOpcode::Jne:
                if (!state.zf) {
                    auto t = check_target(insn.imm);
                    if (!t) return core::diagnostics::Result<VmExecState>::err(t.error().code, t.error().message, t.error().context);
                    state.pc = t.value();
                } else {
                    ++state.pc;
                }
                break;
            case VmOpcode::Jlt:
                if (state.sf) {
                    auto t = check_target(insn.imm);
                    if (!t) return core::diagnostics::Result<VmExecState>::err(t.error().code, t.error().message, t.error().context);
                    state.pc = t.value();
                } else {
                    ++state.pc;
                }
                break;
            case VmOpcode::Jle:
                if (state.sf || state.zf) {
                    auto t = check_target(insn.imm);
                    if (!t) return core::diagnostics::Result<VmExecState>::err(t.error().code, t.error().message, t.error().context);
                    state.pc = t.value();
                } else {
                    ++state.pc;
                }
                break;
            case VmOpcode::Jgt:
                if (!state.sf && !state.zf) {
                    auto t = check_target(insn.imm);
                    if (!t) return core::diagnostics::Result<VmExecState>::err(t.error().code, t.error().message, t.error().context);
                    state.pc = t.value();
                } else {
                    ++state.pc;
                }
                break;
            case VmOpcode::Jge:
                if (!state.sf) {
                    auto t = check_target(insn.imm);
                    if (!t) return core::diagnostics::Result<VmExecState>::err(t.error().code, t.error().message, t.error().context);
                    state.pc = t.value();
                } else {
                    ++state.pc;
                }
                break;
            case VmOpcode::Call: {
                if (state.call_stack.size() >= options.max_call_depth) {
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::OutOfBounds, "VM call stack overflow", "VmInterpreter::execute");
                }
                auto t = check_target(insn.imm);
                if (!t) return core::diagnostics::Result<VmExecState>::err(t.error().code, t.error().message, t.error().context);
                state.call_stack.push_back(state.pc + 1);
                state.pc = t.value();
                break;
            }
            case VmOpcode::Ret:
                if (state.call_stack.empty()) {
                    state.return_value = state.regs[0];
                    return state;
                }
                state.pc = state.call_stack.back();
                state.call_stack.pop_back();
                break;
            case VmOpcode::Halt:
                state.return_value = state.regs[0];
                return state;
            case VmOpcode::CallExt: {
                if (!options.external_call_handler) {
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::UnsupportedFormat,
                        "External call (vm.callext) requires native runtime or external_call_handler",
                        "VmInterpreter::execute");
                }
                auto res = options.external_call_handler(insn.imm, state.regs);
                if (!res.has_value()) {
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::UnsupportedFormat,
                        "Unauthorized or failed external call target",
                        "VmInterpreter::execute");
                }
                state.regs[0] = *res;
                ++state.pc;
                break;
            }
            case VmOpcode::MaxOpcode:
                return core::diagnostics::Result<VmExecState>::err(
                    ErrorCode::ParseError, "Invalid VM opcode during execution", "VmInterpreter::execute");
        }
    }

    state.return_value = state.regs[0];
    return state;
}

} // namespace bytemorph::virt
