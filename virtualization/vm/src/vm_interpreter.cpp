#include "bytemorph/virt/vm_interpreter.hpp"

#include <cstring>

namespace bytemorph::virt {

namespace {

core::diagnostics::Result<bool> validate_program(const BvmProgram& program) {
    using core::diagnostics::ErrorCode;
    const std::size_t code_len = program.instructions.size();
    bool has_mem_ops = false;
    for (const auto& insn : program.instructions) {
        if (insn.opcode == VmOpcode::Halt && insn.dst == 0xFF) {
            continue; // Runtime trap sentinel
        }
        const bool src2_is_width = (insn.opcode == VmOpcode::Load || insn.opcode == VmOpcode::Store);
        if (src2_is_width) {
            has_mem_ops = true;
        }
        if (insn.dst >= BvmProgram::kNumRegisters ||
            insn.src1 >= BvmProgram::kNumRegisters ||
            (!src2_is_width && insn.src2 >= BvmProgram::kNumRegisters)) {
            return core::diagnostics::Result<bool>::err(
                ErrorCode::OutOfBounds, "Register index out of bounds", "VmInterpreter::execute");
        }
        switch (insn.opcode) {
            case VmOpcode::Jmp:
            case VmOpcode::Jeq:
            case VmOpcode::Jne:
            case VmOpcode::Jlt:
            case VmOpcode::Jle:
            case VmOpcode::Jgt:
            case VmOpcode::Jge:
            case VmOpcode::Call:
                if (insn.imm < 0 || static_cast<std::size_t>(insn.imm) >= code_len) {
                    return core::diagnostics::Result<bool>::err(
                        ErrorCode::OutOfBounds, "VM branch/call target out of bounds", "VmInterpreter::execute");
                }
                break;
            case VmOpcode::MaxOpcode:
                return core::diagnostics::Result<bool>::err(
                    ErrorCode::ParseError, "Invalid VM opcode during execution", "VmInterpreter::execute");
            default:
                break;
        }
    }
    return has_mem_ops;
}

} // namespace

core::diagnostics::Result<VmExecState>
VmInterpreter::execute(const BvmProgram& program, const VmExecOptions& options) {
    using core::diagnostics::ErrorCode;

    if (program.instructions.empty()) {
        return core::diagnostics::Result<VmExecState>::err(
            ErrorCode::EmptyInput, "BvmProgram has no instructions", "VmInterpreter::execute");
    }

    auto val = validate_program(program);
    if (!val) {
        return core::diagnostics::Result<VmExecState>::err(
            val.error().code, val.error().message, val.error().context);
    }
    const bool has_mem_ops = val.value();

    VmExecState state;
    state.regs = options.initial_regs;
    if (has_mem_ops && options.memory_slots > 0) {
        state.memory.assign(options.memory_slots, 0ULL);
        if (state.regs[4] == 0 && state.regs[5] == 0) {
            const std::uint64_t mid_stack = ((options.memory_slots * sizeof(std::uint64_t)) / 2) & ~15ULL;
            state.regs[4] = mid_stack;
            state.regs[5] = mid_stack;
        }
    }

    const std::size_t code_len = program.instructions.size();
    const VmInstruction* insns = program.instructions.data();
    std::uint64_t* regs = state.regs.data();
    const std::size_t mem_slots = state.memory.size();
    const std::size_t total_mem_bytes = mem_slots * sizeof(std::uint64_t);
    std::uint64_t* mem_data = state.memory.data();
    auto* mem_bytes = reinterpret_cast<std::uint8_t*>(mem_data);

    std::size_t pc = state.pc;
    std::uint64_t steps = 0;
    const std::uint64_t max_steps = options.max_steps;
    bool zf = state.zf;
    bool sf = state.sf;

    while (pc < code_len) {
        if (steps >= max_steps) {
            state.pc = pc;
            state.steps_executed = steps;
            return core::diagnostics::Result<VmExecState>::err(
                ErrorCode::OutOfBounds, "VM execution exceeded max_steps limit", "VmInterpreter::execute");
        }
        ++steps;

        const auto& insn = insns[pc];

        switch (insn.opcode) {
            case VmOpcode::Nop:
                ++pc;
                break;
            case VmOpcode::MovReg:
                regs[insn.dst] = regs[insn.src1];
                ++pc;
                break;
            case VmOpcode::MovImm:
                regs[insn.dst] = static_cast<std::uint64_t>(insn.imm);
                ++pc;
                break;
            case VmOpcode::Load: {
                if (mem_slots == 0) {
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::OutOfBounds, "VM memory is empty", "VmInterpreter::execute");
                }
                if (insn.src2 == 0) {
                    const std::uint64_t addr = regs[insn.src1] + static_cast<std::uint64_t>(insn.imm);
                    if (addr >= mem_slots) {
                        return core::diagnostics::Result<VmExecState>::err(
                            ErrorCode::OutOfBounds, "VM memory load out of bounds", "VmInterpreter::execute");
                    }
                    regs[insn.dst] = mem_data[addr];
                } else {
                    const std::size_t width_bytes = (insn.src2 == 8) ? 1 : (insn.src2 == 16) ? 2 : (insn.src2 == 32) ? 4 : 8;
                    const std::int64_t byte_addr = static_cast<std::int64_t>(regs[insn.src1]) + insn.imm;
                    if (byte_addr < 0 || static_cast<std::size_t>(byte_addr) + width_bytes > total_mem_bytes) {
                        return core::diagnostics::Result<VmExecState>::err(
                            ErrorCode::OutOfBounds, "VM memory load out of bounds", "VmInterpreter::execute");
                    }
                    std::uint64_t loaded_val = 0;
                    std::memcpy(&loaded_val, mem_bytes + byte_addr, width_bytes);
                    regs[insn.dst] = loaded_val;
                }
                ++pc;
                break;
            }
            case VmOpcode::Store: {
                if (mem_slots == 0) {
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::OutOfBounds, "VM memory is empty", "VmInterpreter::execute");
                }
                if (insn.src2 == 0) {
                    const std::uint64_t addr = regs[insn.dst] + static_cast<std::uint64_t>(insn.imm);
                    if (addr >= mem_slots) {
                        return core::diagnostics::Result<VmExecState>::err(
                            ErrorCode::OutOfBounds, "VM memory store out of bounds", "VmInterpreter::execute");
                    }
                    mem_data[addr] = regs[insn.src1];
                } else {
                    const std::size_t width_bytes = (insn.src2 == 8) ? 1 : (insn.src2 == 16) ? 2 : (insn.src2 == 32) ? 4 : 8;
                    const std::int64_t byte_addr = static_cast<std::int64_t>(regs[insn.dst]) + insn.imm;
                    if (byte_addr < 0 || static_cast<std::size_t>(byte_addr) + width_bytes > total_mem_bytes) {
                        return core::diagnostics::Result<VmExecState>::err(
                            ErrorCode::OutOfBounds, "VM memory store out of bounds", "VmInterpreter::execute");
                    }
                    const std::uint64_t store_val = regs[insn.src1];
                    std::memcpy(mem_bytes + byte_addr, &store_val, width_bytes);
                }
                ++pc;
                break;
            }
            case VmOpcode::Add: {
                const auto res = regs[insn.src1] + regs[insn.src2];
                regs[insn.dst] = res;
                zf = (res == 0);
                sf = (static_cast<std::int64_t>(res) < 0);
                ++pc;
                break;
            }
            case VmOpcode::Sub: {
                const auto res = regs[insn.src1] - regs[insn.src2];
                regs[insn.dst] = res;
                zf = (res == 0);
                sf = (static_cast<std::int64_t>(res) < 0);
                ++pc;
                break;
            }
            case VmOpcode::Mul: {
                const auto res = regs[insn.src1] * regs[insn.src2];
                regs[insn.dst] = res;
                zf = (res == 0);
                sf = (static_cast<std::int64_t>(res) < 0);
                ++pc;
                break;
            }
            case VmOpcode::Div: {
                if (regs[insn.src2] == 0) {
                    state.pc = pc;
                    state.steps_executed = steps;
                    state.zf = zf;
                    state.sf = sf;
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::InternalError, "Division by zero in VM", "VmInterpreter::execute");
                }
                const auto res = regs[insn.src1] / regs[insn.src2];
                regs[insn.dst] = res;
                zf = (res == 0);
                sf = (static_cast<std::int64_t>(res) < 0);
                ++pc;
                break;
            }
            case VmOpcode::And: {
                const auto res = regs[insn.src1] & regs[insn.src2];
                regs[insn.dst] = res;
                zf = (res == 0);
                sf = (static_cast<std::int64_t>(res) < 0);
                ++pc;
                break;
            }
            case VmOpcode::Or: {
                const auto res = regs[insn.src1] | regs[insn.src2];
                regs[insn.dst] = res;
                zf = (res == 0);
                sf = (static_cast<std::int64_t>(res) < 0);
                ++pc;
                break;
            }
            case VmOpcode::Xor: {
                const auto res = regs[insn.src1] ^ regs[insn.src2];
                regs[insn.dst] = res;
                zf = (res == 0);
                sf = (static_cast<std::int64_t>(res) < 0);
                ++pc;
                break;
            }
            case VmOpcode::Shl: {
                const auto sh = regs[insn.src2] & 63ULL;
                const auto res = regs[insn.src1] << sh;
                regs[insn.dst] = res;
                zf = (res == 0);
                sf = (static_cast<std::int64_t>(res) < 0);
                ++pc;
                break;
            }
            case VmOpcode::Shr: {
                const auto sh = regs[insn.src2] & 63ULL;
                const auto res = regs[insn.src1] >> sh;
                regs[insn.dst] = res;
                zf = (res == 0);
                sf = (static_cast<std::int64_t>(res) < 0);
                ++pc;
                break;
            }
            case VmOpcode::Cmp: {
                const auto lhs = static_cast<std::int64_t>(regs[insn.src1]);
                const auto rhs = static_cast<std::int64_t>(regs[insn.src2]);
                zf = (lhs == rhs);
                sf = (lhs < rhs);
                ++pc;
                break;
            }
            case VmOpcode::Jmp:
                pc = static_cast<std::size_t>(insn.imm);
                break;
            case VmOpcode::Jeq:
                pc = zf ? static_cast<std::size_t>(insn.imm) : (pc + 1);
                break;
            case VmOpcode::Jne:
                pc = !zf ? static_cast<std::size_t>(insn.imm) : (pc + 1);
                break;
            case VmOpcode::Jlt:
                pc = sf ? static_cast<std::size_t>(insn.imm) : (pc + 1);
                break;
            case VmOpcode::Jle:
                pc = (sf || zf) ? static_cast<std::size_t>(insn.imm) : (pc + 1);
                break;
            case VmOpcode::Jgt:
                pc = (!sf && !zf) ? static_cast<std::size_t>(insn.imm) : (pc + 1);
                break;
            case VmOpcode::Jge:
                pc = !sf ? static_cast<std::size_t>(insn.imm) : (pc + 1);
                break;
            case VmOpcode::Call:
                if (state.call_stack.size() >= options.max_call_depth) {
                    state.pc = pc;
                    state.steps_executed = steps;
                    state.zf = zf;
                    state.sf = sf;
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::OutOfBounds, "VM call stack overflow", "VmInterpreter::execute");
                }
                state.call_stack.push_back(pc + 1);
                pc = static_cast<std::size_t>(insn.imm);
                break;
            case VmOpcode::Ret:
                if (state.call_stack.empty()) {
                    state.pc = pc;
                    state.steps_executed = steps;
                    state.zf = zf;
                    state.sf = sf;
                    state.return_value = regs[0];
                    return state;
                }
                pc = state.call_stack.back();
                state.call_stack.pop_back();
                break;
            case VmOpcode::Halt:
                state.pc = pc;
                state.steps_executed = steps;
                state.zf = zf;
                state.sf = sf;
                if (insn.dst == 0xFF) {
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::OutOfBounds, "Unauthorized indirect control-flow target at runtime", "VmInterpreter::execute");
                }
                state.return_value = regs[0];
                return state;
            case VmOpcode::CallExt: {
                if (!options.external_call_handler) {
                    state.pc = pc;
                    state.steps_executed = steps;
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::UnsupportedFormat,
                        "External call (vm.callext) requires native runtime or external_call_handler",
                        "VmInterpreter::execute");
                }
                auto res = options.external_call_handler(insn.imm, state.regs);
                if (!res.has_value()) {
                    state.pc = pc;
                    state.steps_executed = steps;
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::UnsupportedFormat,
                        "Unauthorized or failed external call target",
                        "VmInterpreter::execute");
                }
                regs[0] = *res;
                ++pc;
                break;
            }
            case VmOpcode::MaxOpcode:
                state.pc = pc;
                state.steps_executed = steps;
                return core::diagnostics::Result<VmExecState>::err(
                    ErrorCode::ParseError, "Invalid VM opcode during execution", "VmInterpreter::execute");
        }
    }

    state.pc = pc;
    state.steps_executed = steps;
    state.zf = zf;
    state.sf = sf;
    state.return_value = regs[0];
    return state;
}

} // namespace bytemorph::virt
