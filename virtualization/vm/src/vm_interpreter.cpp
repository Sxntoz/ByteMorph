#include "bytemorph/virt/vm_interpreter.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace bytemorph::virt {

namespace {

inline bool eval_vm_cc(std::uint8_t cc, bool zf, bool sf, bool cf, bool of) noexcept {
    switch (static_cast<VmCondCode>(cc)) {
        case VmCondCode::Eq:          return zf;
        case VmCondCode::Ne:          return !zf;
        case VmCondCode::Lt:          return sf != of;
        case VmCondCode::Le:          return (sf != of) || zf;
        case VmCondCode::Gt:          return (sf == of) && !zf;
        case VmCondCode::Ge:          return sf == of;
        case VmCondCode::Below:       return cf;
        case VmCondCode::BelowEq:     return cf || zf;
        case VmCondCode::Above:       return !cf && !zf;
        case VmCondCode::AboveEq:     return !cf;
        case VmCondCode::Sign:        return sf;
        case VmCondCode::NotSign:     return !sf;
        case VmCondCode::Overflow:    return of;
        case VmCondCode::NotOverflow: return !of;
        default:                      return false;
    }
}

inline std::uint64_t compute_program_fingerprint(const BvmProgram& program) noexcept {
    std::uint64_t h = 14695981039346656037ULL ^ program.build_seed;
    h = (h ^ program.instructions.size()) * 1099511628211ULL;
    for (const auto& insn : program.instructions) {
        const std::uint64_t packed =
            static_cast<std::uint64_t>(insn.opcode) |
            (static_cast<std::uint64_t>(insn.dst) << 8) |
            (static_cast<std::uint64_t>(insn.src1) << 16) |
            (static_cast<std::uint64_t>(insn.src2) << 24);
        h ^= packed;
        h *= 1099511628211ULL;
        h ^= static_cast<std::uint64_t>(insn.imm);
        h *= 1099511628211ULL;
    }
    return h;
}

inline bool is_simd_opcode(VmOpcode op) noexcept {
    const auto v = static_cast<std::uint8_t>(op);
    return v >= static_cast<std::uint8_t>(VmOpcode::VMovReg) &&
           v <= static_cast<std::uint8_t>(VmOpcode::VOr);
}

struct CachedProgramEntry {
    const VmInstruction* ptr{nullptr};
    std::size_t len{0};
    std::uint64_t seed{0};
    std::uint64_t fingerprint{0};
    PreparedBvmProgram prepared;
};

} // namespace

core::diagnostics::Result<PreparedBvmProgram>
VmInterpreter::prepare(const BvmProgram& program) {
    using core::diagnostics::ErrorCode;

    if (program.instructions.empty()) {
        return core::diagnostics::Result<PreparedBvmProgram>::err(
            ErrorCode::EmptyInput, "BvmProgram has no instructions", "VmInterpreter::prepare");
    }

    PreparedBvmProgram out;
    out.code_len = program.instructions.size();
    out.build_seed = program.build_seed;
    out.fingerprint = compute_program_fingerprint(program);
    out.insns.reserve(out.code_len + 1);

    for (const auto& insn : program.instructions) {
        FastVmInstruction fast{};
        fast.opcode = insn.opcode;
        fast.dst = insn.dst;
        fast.src1 = insn.src1;
        fast.src2 = insn.src2;
        fast.imm = insn.imm;

        if (insn.opcode == VmOpcode::Halt && insn.dst == 0xFF) {
            out.insns.push_back(fast);
            continue;
        }

        const bool is_scalar_mem = (insn.opcode == VmOpcode::Load || insn.opcode == VmOpcode::Store);
        const bool is_vec_mem = (insn.opcode == VmOpcode::VLoad || insn.opcode == VmOpcode::VStore);
        const bool src2_is_width = is_scalar_mem || is_vec_mem;
        const bool src2_is_cc = (insn.opcode == VmOpcode::SelectCc || insn.opcode == VmOpcode::SetCc);

        if (src2_is_width) {
            out.has_mem_ops = true;
            if (is_scalar_mem) {
                fast.aux = (insn.src2 == 0) ? 0u :
                           (insn.src2 == 8) ? 1u :
                           (insn.src2 == 16) ? 2u :
                           (insn.src2 == 32) ? 4u : 8u;
            } else {
                fast.aux = (insn.src2 == 32) ? 4u : (insn.src2 == 64) ? 8u : 16u;
            }
        }
        if (is_simd_opcode(insn.opcode)) {
            out.has_simd_ops = true;
        }

        if (insn.dst >= BvmProgram::kNumRegisters ||
            insn.src1 >= BvmProgram::kNumRegisters ||
            (!src2_is_width && !src2_is_cc && insn.src2 >= BvmProgram::kNumRegisters)) {
            return core::diagnostics::Result<PreparedBvmProgram>::err(
                ErrorCode::OutOfBounds, "Register index out of bounds", "VmInterpreter::execute");
        }
        if (src2_is_cc && insn.src2 > static_cast<std::uint8_t>(VmCondCode::NotOverflow)) {
            return core::diagnostics::Result<PreparedBvmProgram>::err(
                ErrorCode::ParseError, "Invalid VM condition code", "VmInterpreter::execute");
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
                if (insn.imm < 0 || static_cast<std::size_t>(insn.imm) >= out.code_len) {
                    return core::diagnostics::Result<PreparedBvmProgram>::err(
                        ErrorCode::OutOfBounds, "VM branch/call target out of bounds", "VmInterpreter::execute");
                }
                break;
            default:
                if (static_cast<std::uint8_t>(insn.opcode) >= static_cast<std::uint8_t>(VmOpcode::MaxOpcode)) {
                    return core::diagnostics::Result<PreparedBvmProgram>::err(
                        ErrorCode::ParseError, "Invalid VM opcode during execution", "VmInterpreter::execute");
                }
                break;
        }
        out.insns.push_back(fast);
    }

    // Sentinel Halt at code_len eliminates per-instruction pc < code_len bounds check.
    FastVmInstruction sentinel{};
    sentinel.opcode = VmOpcode::Halt;
    sentinel.dst = 0;
    out.insns.push_back(sentinel);

    return out;
}

core::diagnostics::Result<VmExecState>
VmInterpreter::execute_prepared(const PreparedBvmProgram& prepared, const VmExecOptions& options) {
    using core::diagnostics::ErrorCode;

    if (prepared.code_len == 0 || prepared.insns.size() <= prepared.code_len) {
        return core::diagnostics::Result<VmExecState>::err(
            ErrorCode::EmptyInput, "PreparedBvmProgram has no instructions", "VmInterpreter::execute");
    }

    VmExecState state;
    alignas(64) std::uint64_t regs[BvmProgram::kNumRegisters];
    std::memcpy(regs, options.initial_regs.data(), sizeof(regs));
    if (prepared.has_simd_ops) {
        std::memcpy(state.vregs.data(), options.initial_vregs.data(), sizeof(state.vregs));
    }

    thread_local std::vector<std::uint64_t> tls_memory_pool;
    thread_local std::size_t tls_dirty_min = 0;
    thread_local std::size_t tls_dirty_max = 0;
    thread_local std::vector<std::size_t> tls_call_stack;
    tls_call_stack.clear();

    std::size_t mem_slots = 0;
    std::uint64_t* mem_data = nullptr;
    std::size_t total_mem_bytes = 0;
    std::uint8_t* mem_bytes = nullptr;
    std::size_t dirty_min = 0;
    std::size_t dirty_max = 0;
    bool using_tls_pool = false;

    if (prepared.has_mem_ops && options.memory_slots > 0) {
        mem_slots = options.memory_slots;
        total_mem_bytes = mem_slots * sizeof(std::uint64_t);
        if (options.use_memory_pool) {
            using_tls_pool = true;
            if (tls_memory_pool.size() < options.memory_slots) {
                const std::size_t old_size = tls_memory_pool.size();
                tls_memory_pool.resize(options.memory_slots, 0ULL);
                if (tls_dirty_max > tls_dirty_min && old_size > 0) {
                    const std::size_t clamped_max = std::min(tls_dirty_max, old_size * sizeof(std::uint64_t));
                    if (clamped_max > tls_dirty_min) {
                        std::memset(reinterpret_cast<std::uint8_t*>(tls_memory_pool.data()) + tls_dirty_min,
                                    0, clamped_max - tls_dirty_min);
                    }
                }
                state.allocations_count = 1;
            } else {
                state.allocations_count = 0;
                if (tls_dirty_max > tls_dirty_min) {
                    const std::size_t clamped_max = std::min(tls_dirty_max, total_mem_bytes);
                    if (clamped_max > tls_dirty_min) {
                        std::memset(reinterpret_cast<std::uint8_t*>(tls_memory_pool.data()) + tls_dirty_min,
                                    0, clamped_max - tls_dirty_min);
                    }
                }
            }
            tls_dirty_min = 0;
            tls_dirty_max = 0;
            mem_data = tls_memory_pool.data();
        } else {
            state.memory.assign(options.memory_slots, 0ULL);
            state.allocations_count = 1;
            mem_data = state.memory.data();
        }
        mem_bytes = reinterpret_cast<std::uint8_t*>(mem_data);
        dirty_min = total_mem_bytes;
        dirty_max = 0;
        if (regs[4] == 0 && regs[5] == 0) {
            const std::uint64_t mid_stack = ((options.memory_slots * sizeof(std::uint64_t)) / 2) & ~15ULL;
            regs[4] = mid_stack;
            regs[5] = mid_stack;
        }
    }

    const FastVmInstruction* insns = prepared.insns.data();
    std::size_t pc = state.pc;
    std::uint64_t steps = 0;
    const std::uint64_t max_steps = options.max_steps;
    bool zf = state.zf;
    bool sf = state.sf;
    bool cf = state.cf;
    bool of = state.of;

    auto commit_dirty = [&]() noexcept {
        if (using_tls_pool && dirty_max > dirty_min) {
            tls_dirty_min = dirty_min;
            tls_dirty_max = dirty_max;
        }
    };

    auto finalize_state = [&](bool reached_sentinel) noexcept {
        commit_dirty();
        std::memcpy(state.regs.data(), regs, sizeof(regs));
        state.pc = (reached_sentinel && pc > prepared.code_len) ? prepared.code_len : pc;
        state.steps_executed = steps;
        state.zf = zf;
        state.sf = sf;
        state.cf = cf;
        state.of = of;
        state.return_value = regs[0];
    };

#if defined(__GNUC__) || defined(__clang__)
    static constexpr void* kDispatchTable[] = {
        &&op_Nop,          // 0x00
        &&op_MovReg,       // 0x01
        &&op_MovImm,       // 0x02
        &&op_Load,         // 0x03
        &&op_Store,        // 0x04
        &&op_Add,          // 0x05
        &&op_Sub,          // 0x06
        &&op_Mul,          // 0x07
        &&op_Div,          // 0x08
        &&op_And,          // 0x09
        &&op_Or,           // 0x0A
        &&op_Xor,          // 0x0B
        &&op_Shl,          // 0x0C
        &&op_Shr,          // 0x0D
        &&op_Cmp,          // 0x0E
        &&op_Jmp,          // 0x0F
        &&op_Jeq,          // 0x10
        &&op_Jne,          // 0x11
        &&op_Jlt,          // 0x12
        &&op_Jle,          // 0x13
        &&op_Jgt,          // 0x14
        &&op_Jge,          // 0x15
        &&op_Call,         // 0x16
        &&op_Ret,          // 0x17
        &&op_Halt,         // 0x18
        &&op_CallExt,      // 0x19
        &&op_LeaPic,       // 0x1A
        &&op_SelectCc,     // 0x1B
        &&op_SetCc,        // 0x1C
        &&op_VMovReg,      // 0x1D
        &&op_VAddF32,      // 0x1E
        &&op_VAddF64,      // 0x1F
        &&op_VSubF32,      // 0x20
        &&op_VSubF64,      // 0x21
        &&op_VMulF32,      // 0x22
        &&op_VMulF64,      // 0x23
        &&op_VDivF32,      // 0x24
        &&op_VDivF64,      // 0x25
        &&op_VCmpF32,      // 0x26
        &&op_VCmpF64,      // 0x27
        &&op_VLoad,        // 0x28
        &&op_VStore,       // 0x29
        &&op_VXor,         // 0x2A
        &&op_VCvtI2F,      // 0x2B
        &&op_VCvtF2I,      // 0x2C
        &&op_VCvtF2F,      // 0x2D
        &&op_VMovGprToVec, // 0x2E
        &&op_VMovVecToGpr, // 0x2F
        &&op_VPAdd32,      // 0x30
        &&op_VPAdd64,      // 0x31
        &&op_VPSub32,      // 0x32
        &&op_VPSub64,      // 0x33
        &&op_VAnd,         // 0x34
        &&op_VOr           // 0x35
    };
    static_assert(sizeof(kDispatchTable) / sizeof(kDispatchTable[0]) == static_cast<std::size_t>(VmOpcode::MaxOpcode));

    const FastVmInstruction* insn = &insns[pc];
    #define VM_DISPATCH_NEXT()                                                      \
        do {                                                                        \
            if (pc == prepared.code_len) [[unlikely]] {                             \
                finalize_state(true);                                               \
                return state;                                                       \
            }                                                                       \
            if (steps >= max_steps) [[unlikely]] {                                  \
                finalize_state(false);                                              \
                return core::diagnostics::Result<VmExecState>::err(                 \
                    ErrorCode::OutOfBounds, "VM execution exceeded max_steps limit", \
                    "VmInterpreter::execute");                                      \
            }                                                                       \
            ++steps;                                                                \
            insn = &insns[pc];                                                      \
            goto *kDispatchTable[static_cast<std::uint8_t>(insn->opcode)];          \
        } while (0)

    VM_DISPATCH_NEXT();

    op_Nop:
        ++pc;
        VM_DISPATCH_NEXT();
    op_MovReg:
        regs[insn->dst] = regs[insn->src1];
        ++pc;
        VM_DISPATCH_NEXT();
    op_MovImm:
        regs[insn->dst] = static_cast<std::uint64_t>(insn->imm);
        ++pc;
        VM_DISPATCH_NEXT();
    op_Load: {
        if (mem_slots == 0) [[unlikely]] {
            finalize_state(false);
            return core::diagnostics::Result<VmExecState>::err(
                ErrorCode::OutOfBounds, "VM memory is empty", "VmInterpreter::execute");
        }
        if (insn->aux == 0) {
            const std::uint64_t addr = regs[insn->src1] + static_cast<std::uint64_t>(insn->imm);
            if (addr >= mem_slots) [[unlikely]] {
                finalize_state(false);
                return core::diagnostics::Result<VmExecState>::err(
                    ErrorCode::OutOfBounds, "VM memory load out of bounds", "VmInterpreter::execute");
            }
            regs[insn->dst] = mem_data[addr];
        } else {
            const std::size_t width_bytes = insn->aux;
            const std::int64_t byte_addr = static_cast<std::int64_t>(regs[insn->src1]) + insn->imm;
            if (byte_addr < 0 || static_cast<std::size_t>(byte_addr) + width_bytes > total_mem_bytes) [[unlikely]] {
                finalize_state(false);
                return core::diagnostics::Result<VmExecState>::err(
                    ErrorCode::OutOfBounds, "VM memory load out of bounds", "VmInterpreter::execute");
            }
            std::uint64_t loaded_val = 0;
            std::memcpy(&loaded_val, mem_bytes + byte_addr, width_bytes);
            regs[insn->dst] = loaded_val;
        }
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_Store: {
        if (mem_slots == 0) [[unlikely]] {
            finalize_state(false);
            return core::diagnostics::Result<VmExecState>::err(
                ErrorCode::OutOfBounds, "VM memory is empty", "VmInterpreter::execute");
        }
        if (insn->aux == 0) {
            const std::uint64_t addr = regs[insn->dst] + static_cast<std::uint64_t>(insn->imm);
            if (addr >= mem_slots) [[unlikely]] {
                finalize_state(false);
                return core::diagnostics::Result<VmExecState>::err(
                    ErrorCode::OutOfBounds, "VM memory store out of bounds", "VmInterpreter::execute");
            }
            mem_data[addr] = regs[insn->src1];
            const std::size_t b_start = static_cast<std::size_t>(addr) * sizeof(std::uint64_t);
            const std::size_t b_end = b_start + sizeof(std::uint64_t);
            if (b_start < dirty_min) dirty_min = b_start;
            if (b_end > dirty_max) dirty_max = b_end;
        } else {
            const std::size_t width_bytes = insn->aux;
            const std::int64_t byte_addr = static_cast<std::int64_t>(regs[insn->dst]) + insn->imm;
            if (byte_addr < 0 || static_cast<std::size_t>(byte_addr) + width_bytes > total_mem_bytes) [[unlikely]] {
                finalize_state(false);
                return core::diagnostics::Result<VmExecState>::err(
                    ErrorCode::OutOfBounds, "VM memory store out of bounds", "VmInterpreter::execute");
            }
            const std::uint64_t store_val = regs[insn->src1];
            const std::size_t b_start = static_cast<std::size_t>(byte_addr);
            std::memcpy(mem_bytes + b_start, &store_val, width_bytes);
            if (b_start < dirty_min) dirty_min = b_start;
            if (b_start + width_bytes > dirty_max) dirty_max = b_start + width_bytes;
        }
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_Add: {
        const std::uint64_t u1 = regs[insn->src1];
        const std::uint64_t u2 = regs[insn->src2];
        const std::uint64_t res = u1 + u2;
        regs[insn->dst] = res;
        zf = (res == 0);
        sf = (static_cast<std::int64_t>(res) < 0);
        cf = (res < u1);
        of = (((~(u1 ^ u2) & (u1 ^ res)) >> 63) != 0);
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_Sub: {
        const std::uint64_t u1 = regs[insn->src1];
        const std::uint64_t u2 = regs[insn->src2];
        const std::uint64_t res = u1 - u2;
        regs[insn->dst] = res;
        zf = (res == 0);
        sf = (static_cast<std::int64_t>(res) < 0);
        cf = (u1 < u2);
        of = ((((u1 ^ u2) & (u1 ^ res)) >> 63) != 0);
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_Mul: {
        const auto res = regs[insn->src1] * regs[insn->src2];
        regs[insn->dst] = res;
        zf = (res == 0);
        sf = (static_cast<std::int64_t>(res) < 0);
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_Div: {
        if (regs[insn->src2] == 0) [[unlikely]] {
            finalize_state(false);
            return core::diagnostics::Result<VmExecState>::err(
                ErrorCode::InternalError, "Division by zero in VM", "VmInterpreter::execute");
        }
        const auto res = regs[insn->src1] / regs[insn->src2];
        regs[insn->dst] = res;
        zf = (res == 0);
        sf = (static_cast<std::int64_t>(res) < 0);
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_And: {
        const auto res = regs[insn->src1] & regs[insn->src2];
        regs[insn->dst] = res;
        zf = (res == 0);
        sf = (static_cast<std::int64_t>(res) < 0);
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_Or: {
        const auto res = regs[insn->src1] | regs[insn->src2];
        regs[insn->dst] = res;
        zf = (res == 0);
        sf = (static_cast<std::int64_t>(res) < 0);
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_Xor: {
        const auto res = regs[insn->src1] ^ regs[insn->src2];
        regs[insn->dst] = res;
        zf = (res == 0);
        sf = (static_cast<std::int64_t>(res) < 0);
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_Shl: {
        const auto sh = regs[insn->src2] & 63ULL;
        const auto res = regs[insn->src1] << sh;
        regs[insn->dst] = res;
        zf = (res == 0);
        sf = (static_cast<std::int64_t>(res) < 0);
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_Shr: {
        const auto sh = regs[insn->src2] & 63ULL;
        const auto res = regs[insn->src1] >> sh;
        regs[insn->dst] = res;
        zf = (res == 0);
        sf = (static_cast<std::int64_t>(res) < 0);
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_Cmp: {
        const std::uint64_t u1 = regs[insn->src1];
        const std::uint64_t u2 = regs[insn->src2];
        const std::uint64_t diff = u1 - u2;
        zf = (diff == 0);
        sf = (static_cast<std::int64_t>(diff) < 0);
        cf = (u1 < u2);
        of = ((((u1 ^ u2) & (u1 ^ diff)) >> 63) != 0);
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_Jmp:
        pc = static_cast<std::size_t>(insn->imm);
        VM_DISPATCH_NEXT();
    op_Jeq:
        pc = zf ? static_cast<std::size_t>(insn->imm) : (pc + 1);
        VM_DISPATCH_NEXT();
    op_Jne:
        pc = !zf ? static_cast<std::size_t>(insn->imm) : (pc + 1);
        VM_DISPATCH_NEXT();
    op_Jlt:
        pc = (sf != of) ? static_cast<std::size_t>(insn->imm) : (pc + 1);
        VM_DISPATCH_NEXT();
    op_Jle:
        pc = ((sf != of) || zf) ? static_cast<std::size_t>(insn->imm) : (pc + 1);
        VM_DISPATCH_NEXT();
    op_Jgt:
        pc = ((sf == of) && !zf) ? static_cast<std::size_t>(insn->imm) : (pc + 1);
        VM_DISPATCH_NEXT();
    op_Jge:
        pc = (sf == of) ? static_cast<std::size_t>(insn->imm) : (pc + 1);
        VM_DISPATCH_NEXT();
    op_Call:
        if (tls_call_stack.size() >= options.max_call_depth) [[unlikely]] {
            finalize_state(false);
            state.call_stack = tls_call_stack;
            return core::diagnostics::Result<VmExecState>::err(
                ErrorCode::OutOfBounds, "VM call stack overflow", "VmInterpreter::execute");
        }
        tls_call_stack.push_back(pc + 1);
        pc = static_cast<std::size_t>(insn->imm);
        VM_DISPATCH_NEXT();
    op_Ret:
        if (tls_call_stack.empty()) {
            finalize_state(false);
            return state;
        }
        pc = tls_call_stack.back();
        tls_call_stack.pop_back();
        VM_DISPATCH_NEXT();
    op_Halt:
        finalize_state(false);
        if (insn->dst == 0xFF) [[unlikely]] {
            return core::diagnostics::Result<VmExecState>::err(
                ErrorCode::OutOfBounds, "Unauthorized indirect control-flow target at runtime", "VmInterpreter::execute");
        }
        return state;
    op_CallExt: {
        if (!options.external_call_handler) [[unlikely]] {
            finalize_state(false);
            return core::diagnostics::Result<VmExecState>::err(
                ErrorCode::UnsupportedFormat,
                "External call (vm.callext) requires native runtime or external_call_handler",
                "VmInterpreter::execute");
        }
        std::memcpy(state.regs.data(), regs, sizeof(regs));
        auto res = options.external_call_handler(insn->imm, state.regs);
        if (!res.has_value()) [[unlikely]] {
            finalize_state(false);
            return core::diagnostics::Result<VmExecState>::err(
                ErrorCode::UnsupportedFormat,
                "Unauthorized or failed external call target",
                "VmInterpreter::execute");
        }
        regs[0] = *res;
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_LeaPic:
        regs[insn->dst] = static_cast<std::uint64_t>(static_cast<std::int64_t>(options.pic_base_va) + insn->imm);
        ++pc;
        VM_DISPATCH_NEXT();
    op_SelectCc:
        if (eval_vm_cc(insn->src2, zf, sf, cf, of)) {
            regs[insn->dst] = regs[insn->src1];
        }
        ++pc;
        VM_DISPATCH_NEXT();
    op_SetCc:
        regs[insn->dst] = eval_vm_cc(insn->src2, zf, sf, cf, of) ? 1ULL : 0ULL;
        ++pc;
        VM_DISPATCH_NEXT();
    op_VMovReg:
        if (insn->imm == 32) {
            state.vregs[insn->dst][0] = (state.vregs[insn->dst][0] & ~0xFFFFFFFFULL) |
                                        (state.vregs[insn->src1][0] & 0xFFFFFFFFULL);
        } else if (insn->imm == 64) {
            state.vregs[insn->dst][0] = state.vregs[insn->src1][0];
        } else {
            state.vregs[insn->dst] = state.vregs[insn->src1];
        }
        ++pc;
        VM_DISPATCH_NEXT();
    op_VAddF32:
    op_VSubF32:
    op_VMulF32:
    op_VDivF32: {
        float a = 0.0f, b = 0.0f;
        const std::uint32_t ua = static_cast<std::uint32_t>(state.vregs[insn->src1][0]);
        const std::uint32_t ub = static_cast<std::uint32_t>(state.vregs[insn->src2][0]);
        std::memcpy(&a, &ua, 4);
        std::memcpy(&b, &ub, 4);
        float r = 0.0f;
        if (insn->opcode == VmOpcode::VAddF32) r = a + b;
        else if (insn->opcode == VmOpcode::VSubF32) r = a - b;
        else if (insn->opcode == VmOpcode::VMulF32) r = a * b;
        else r = a / b;
        std::uint32_t ur = 0;
        std::memcpy(&ur, &r, 4);
        state.vregs[insn->dst][0] = (state.vregs[insn->dst][0] & ~0xFFFFFFFFULL) | static_cast<std::uint64_t>(ur);
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_VAddF64:
    op_VSubF64:
    op_VMulF64:
    op_VDivF64: {
        double a = 0.0, b = 0.0;
        std::memcpy(&a, &state.vregs[insn->src1][0], 8);
        std::memcpy(&b, &state.vregs[insn->src2][0], 8);
        double r = 0.0;
        if (insn->opcode == VmOpcode::VAddF64) r = a + b;
        else if (insn->opcode == VmOpcode::VSubF64) r = a - b;
        else if (insn->opcode == VmOpcode::VMulF64) r = a * b;
        else r = a / b;
        std::memcpy(&state.vregs[insn->dst][0], &r, 8);
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_VCmpF32:
    op_VCmpF64: {
        double a = 0.0, b = 0.0;
        if (insn->opcode == VmOpcode::VCmpF32) {
            float fa = 0.0f, fb = 0.0f;
            const std::uint32_t ua = static_cast<std::uint32_t>(state.vregs[insn->src1][0]);
            const std::uint32_t ub = static_cast<std::uint32_t>(state.vregs[insn->src2][0]);
            std::memcpy(&fa, &ua, 4);
            std::memcpy(&fb, &ub, 4);
            a = static_cast<double>(fa);
            b = static_cast<double>(fb);
        } else {
            std::memcpy(&a, &state.vregs[insn->src1][0], 8);
            std::memcpy(&b, &state.vregs[insn->src2][0], 8);
        }
        if (std::isnan(a) || std::isnan(b)) {
            zf = true; cf = true; state.pf = true;
        } else if (a < b) {
            zf = false; cf = true; state.pf = false;
        } else if (a > b) {
            zf = false; cf = false; state.pf = false;
        } else {
            zf = true; cf = false; state.pf = false;
        }
        sf = false;
        of = false;
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_VLoad: {
        if (mem_slots == 0) [[unlikely]] {
            finalize_state(false);
            return core::diagnostics::Result<VmExecState>::err(
                ErrorCode::OutOfBounds, "VM memory is empty", "VmInterpreter::execute");
        }
        const std::size_t width_bytes = insn->aux;
        const std::int64_t byte_addr = static_cast<std::int64_t>(regs[insn->src1]) + insn->imm;
        if (byte_addr < 0 || static_cast<std::size_t>(byte_addr) + width_bytes > total_mem_bytes) [[unlikely]] {
            finalize_state(false);
            return core::diagnostics::Result<VmExecState>::err(
                ErrorCode::OutOfBounds, "VM vector memory load out of bounds", "VmInterpreter::execute");
        }
        if (width_bytes <= 8) {
            std::uint64_t tmp = 0;
            std::memcpy(&tmp, mem_bytes + byte_addr, width_bytes);
            state.vregs[insn->dst][0] = tmp;
            state.vregs[insn->dst][1] = 0;
        } else {
            std::memcpy(state.vregs[insn->dst].data(), mem_bytes + byte_addr, 16);
        }
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_VStore: {
        if (mem_slots == 0) [[unlikely]] {
            finalize_state(false);
            return core::diagnostics::Result<VmExecState>::err(
                ErrorCode::OutOfBounds, "VM memory is empty", "VmInterpreter::execute");
        }
        const std::size_t width_bytes = insn->aux;
        const std::int64_t byte_addr = static_cast<std::int64_t>(regs[insn->dst]) + insn->imm;
        if (byte_addr < 0 || static_cast<std::size_t>(byte_addr) + width_bytes > total_mem_bytes) [[unlikely]] {
            finalize_state(false);
            return core::diagnostics::Result<VmExecState>::err(
                ErrorCode::OutOfBounds, "VM vector memory store out of bounds", "VmInterpreter::execute");
        }
        const std::size_t b_start = static_cast<std::size_t>(byte_addr);
        std::memcpy(mem_bytes + b_start, state.vregs[insn->src1].data(), width_bytes);
        if (b_start < dirty_min) dirty_min = b_start;
        if (b_start + width_bytes > dirty_max) dirty_max = b_start + width_bytes;
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_VXor:
        state.vregs[insn->dst][0] = state.vregs[insn->src1][0] ^ state.vregs[insn->src2][0];
        state.vregs[insn->dst][1] = state.vregs[insn->src1][1] ^ state.vregs[insn->src2][1];
        ++pc;
        VM_DISPATCH_NEXT();
    op_VAnd:
        state.vregs[insn->dst][0] = state.vregs[insn->src1][0] & state.vregs[insn->src2][0];
        state.vregs[insn->dst][1] = state.vregs[insn->src1][1] & state.vregs[insn->src2][1];
        ++pc;
        VM_DISPATCH_NEXT();
    op_VOr:
        state.vregs[insn->dst][0] = state.vregs[insn->src1][0] | state.vregs[insn->src2][0];
        state.vregs[insn->dst][1] = state.vregs[insn->src1][1] | state.vregs[insn->src2][1];
        ++pc;
        VM_DISPATCH_NEXT();
    op_VMovGprToVec:
        state.vregs[insn->dst][0] = (insn->imm == 32) ? (regs[insn->src1] & 0xFFFFFFFFULL) : regs[insn->src1];
        state.vregs[insn->dst][1] = 0;
        ++pc;
        VM_DISPATCH_NEXT();
    op_VMovVecToGpr:
        regs[insn->dst] = (insn->imm == 32) ? (state.vregs[insn->src1][0] & 0xFFFFFFFFULL) : state.vregs[insn->src1][0];
        ++pc;
        VM_DISPATCH_NEXT();
    op_VCvtI2F: {
        const bool is_unsigned = (insn->imm & 1) != 0;
        const bool dst_f64 = (insn->imm & 2) != 0;
        const bool src_64 = (insn->imm & 4) != 0;
        const std::uint64_t raw = regs[insn->src1];
        if (dst_f64) {
            const double d = is_unsigned
                ? (src_64 ? static_cast<double>(raw) : static_cast<double>(static_cast<std::uint32_t>(raw)))
                : (src_64 ? static_cast<double>(static_cast<std::int64_t>(raw)) : static_cast<double>(static_cast<std::int32_t>(raw)));
            std::memcpy(&state.vregs[insn->dst][0], &d, 8);
        } else {
            const float f = is_unsigned
                ? (src_64 ? static_cast<float>(raw) : static_cast<float>(static_cast<std::uint32_t>(raw)))
                : (src_64 ? static_cast<float>(static_cast<std::int64_t>(raw)) : static_cast<float>(static_cast<std::int32_t>(raw)));
            std::uint32_t uf = 0;
            std::memcpy(&uf, &f, 4);
            state.vregs[insn->dst][0] = (state.vregs[insn->dst][0] & ~0xFFFFFFFFULL) | static_cast<std::uint64_t>(uf);
        }
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_VCvtF2I: {
        const bool is_unsigned = (insn->imm & 1) != 0;
        const bool src_f64 = (insn->imm & 2) != 0;
        const bool dst_64 = (insn->imm & 4) != 0;
        double dv = 0.0;
        if (src_f64) {
            std::memcpy(&dv, &state.vregs[insn->src1][0], 8);
        } else {
            float fv = 0.0f;
            const std::uint32_t uf = static_cast<std::uint32_t>(state.vregs[insn->src1][0]);
            std::memcpy(&fv, &uf, 4);
            dv = static_cast<double>(fv);
        }
        if (is_unsigned) {
            regs[insn->dst] = dst_64 ? static_cast<std::uint64_t>(dv) : static_cast<std::uint64_t>(static_cast<std::uint32_t>(dv));
        } else {
            regs[insn->dst] = dst_64
                ? static_cast<std::uint64_t>(static_cast<std::int64_t>(dv))
                : static_cast<std::uint64_t>(static_cast<std::uint32_t>(static_cast<std::int32_t>(dv)));
        }
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_VCvtF2F: {
        if (insn->imm == 64) {
            float fv = 0.0f;
            const std::uint32_t uf = static_cast<std::uint32_t>(state.vregs[insn->src1][0]);
            std::memcpy(&fv, &uf, 4);
            const double dv = static_cast<double>(fv);
            std::memcpy(&state.vregs[insn->dst][0], &dv, 8);
        } else {
            double dv = 0.0;
            std::memcpy(&dv, &state.vregs[insn->src1][0], 8);
            const float fv = static_cast<float>(dv);
            std::uint32_t uf = 0;
            std::memcpy(&uf, &fv, 4);
            state.vregs[insn->dst][0] = (state.vregs[insn->dst][0] & ~0xFFFFFFFFULL) | static_cast<std::uint64_t>(uf);
        }
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_VPAdd32:
    op_VPSub32: {
        const bool is_sub = (insn->opcode == VmOpcode::VPSub32);
        for (int half = 0; half < 2; ++half) {
            const std::uint64_t a = state.vregs[insn->src1][half];
            const std::uint64_t b = state.vregs[insn->src2][half];
            const std::uint32_t lo = is_sub ? (static_cast<std::uint32_t>(a) - static_cast<std::uint32_t>(b))
                                            : (static_cast<std::uint32_t>(a) + static_cast<std::uint32_t>(b));
            const std::uint32_t hi = is_sub ? (static_cast<std::uint32_t>(a >> 32) - static_cast<std::uint32_t>(b >> 32))
                                            : (static_cast<std::uint32_t>(a >> 32) + static_cast<std::uint32_t>(b >> 32));
            state.vregs[insn->dst][half] = static_cast<std::uint64_t>(lo) | (static_cast<std::uint64_t>(hi) << 32);
        }
        ++pc;
        VM_DISPATCH_NEXT();
    }
    op_VPAdd64:
        state.vregs[insn->dst][0] = state.vregs[insn->src1][0] + state.vregs[insn->src2][0];
        state.vregs[insn->dst][1] = state.vregs[insn->src1][1] + state.vregs[insn->src2][1];
        ++pc;
        VM_DISPATCH_NEXT();
    op_VPSub64:
        state.vregs[insn->dst][0] = state.vregs[insn->src1][0] - state.vregs[insn->src2][0];
        state.vregs[insn->dst][1] = state.vregs[insn->src1][1] - state.vregs[insn->src2][1];
        ++pc;
        VM_DISPATCH_NEXT();

    #undef VM_DISPATCH_NEXT
#else
    const std::size_t code_len = prepared.code_len;
    while (pc < code_len) {
        if (steps >= max_steps) [[unlikely]] {
            finalize_state(false);
            return core::diagnostics::Result<VmExecState>::err(
                ErrorCode::OutOfBounds, "VM execution exceeded max_steps limit", "VmInterpreter::execute");
        }
        ++steps;

        const auto& insn = insns[pc];
#if defined(_MSC_VER)
        __assume(static_cast<std::uint8_t>(insn.opcode) < static_cast<std::uint8_t>(VmOpcode::MaxOpcode));
#endif
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
                if (mem_slots == 0) [[unlikely]] {
                    finalize_state(false);
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::OutOfBounds, "VM memory is empty", "VmInterpreter::execute");
                }
                if (insn.aux == 0) {
                    const std::uint64_t addr = regs[insn.src1] + static_cast<std::uint64_t>(insn.imm);
                    if (addr >= mem_slots) [[unlikely]] {
                        finalize_state(false);
                        return core::diagnostics::Result<VmExecState>::err(
                            ErrorCode::OutOfBounds, "VM memory load out of bounds", "VmInterpreter::execute");
                    }
                    regs[insn.dst] = mem_data[addr];
                } else {
                    const std::size_t width_bytes = insn.aux;
                    const std::int64_t byte_addr = static_cast<std::int64_t>(regs[insn.src1]) + insn.imm;
                    if (byte_addr < 0 || static_cast<std::size_t>(byte_addr) + width_bytes > total_mem_bytes) [[unlikely]] {
                        finalize_state(false);
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
                if (mem_slots == 0) [[unlikely]] {
                    finalize_state(false);
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::OutOfBounds, "VM memory is empty", "VmInterpreter::execute");
                }
                if (insn.aux == 0) {
                    const std::uint64_t addr = regs[insn.dst] + static_cast<std::uint64_t>(insn.imm);
                    if (addr >= mem_slots) [[unlikely]] {
                        finalize_state(false);
                        return core::diagnostics::Result<VmExecState>::err(
                            ErrorCode::OutOfBounds, "VM memory store out of bounds", "VmInterpreter::execute");
                    }
                    mem_data[addr] = regs[insn.src1];
                    const std::size_t b_start = static_cast<std::size_t>(addr) * sizeof(std::uint64_t);
                    const std::size_t b_end = b_start + sizeof(std::uint64_t);
                    if (b_start < dirty_min) dirty_min = b_start;
                    if (b_end > dirty_max) dirty_max = b_end;
                } else {
                    const std::size_t width_bytes = insn.aux;
                    const std::int64_t byte_addr = static_cast<std::int64_t>(regs[insn.dst]) + insn.imm;
                    if (byte_addr < 0 || static_cast<std::size_t>(byte_addr) + width_bytes > total_mem_bytes) [[unlikely]] {
                        finalize_state(false);
                        return core::diagnostics::Result<VmExecState>::err(
                            ErrorCode::OutOfBounds, "VM memory store out of bounds", "VmInterpreter::execute");
                    }
                    const std::uint64_t store_val = regs[insn.src1];
                    const std::size_t b_start = static_cast<std::size_t>(byte_addr);
                    std::memcpy(mem_bytes + b_start, &store_val, width_bytes);
                    if (b_start < dirty_min) dirty_min = b_start;
                    if (b_start + width_bytes > dirty_max) dirty_max = b_start + width_bytes;
                }
                ++pc;
                break;
            }
            case VmOpcode::Add: {
                const std::uint64_t u1 = regs[insn.src1];
                const std::uint64_t u2 = regs[insn.src2];
                const std::uint64_t res = u1 + u2;
                regs[insn.dst] = res;
                zf = (res == 0);
                sf = (static_cast<std::int64_t>(res) < 0);
                cf = (res < u1);
                of = (((~(u1 ^ u2) & (u1 ^ res)) >> 63) != 0);
                ++pc;
                break;
            }
            case VmOpcode::Sub: {
                const std::uint64_t u1 = regs[insn.src1];
                const std::uint64_t u2 = regs[insn.src2];
                const std::uint64_t res = u1 - u2;
                regs[insn.dst] = res;
                zf = (res == 0);
                sf = (static_cast<std::int64_t>(res) < 0);
                cf = (u1 < u2);
                of = ((((u1 ^ u2) & (u1 ^ res)) >> 63) != 0);
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
                if (regs[insn.src2] == 0) [[unlikely]] {
                    finalize_state(false);
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
                const std::uint64_t u1 = regs[insn.src1];
                const std::uint64_t u2 = regs[insn.src2];
                const std::uint64_t diff = u1 - u2;
                zf = (diff == 0);
                sf = (static_cast<std::int64_t>(diff) < 0);
                cf = (u1 < u2);
                of = ((((u1 ^ u2) & (u1 ^ diff)) >> 63) != 0);
                ++pc;
                break;
            }
            case VmOpcode::LeaPic:
                regs[insn.dst] = static_cast<std::uint64_t>(static_cast<std::int64_t>(options.pic_base_va) + insn.imm);
                ++pc;
                break;
            case VmOpcode::SelectCc:
                if (eval_vm_cc(insn.src2, zf, sf, cf, of)) {
                    regs[insn.dst] = regs[insn.src1];
                }
                ++pc;
                break;
            case VmOpcode::SetCc:
                regs[insn.dst] = eval_vm_cc(insn.src2, zf, sf, cf, of) ? 1ULL : 0ULL;
                ++pc;
                break;
            case VmOpcode::VMovReg:
                if (insn.imm == 32) {
                    state.vregs[insn.dst][0] = (state.vregs[insn.dst][0] & ~0xFFFFFFFFULL) |
                                               (state.vregs[insn.src1][0] & 0xFFFFFFFFULL);
                } else if (insn.imm == 64) {
                    state.vregs[insn.dst][0] = state.vregs[insn.src1][0];
                } else {
                    state.vregs[insn.dst] = state.vregs[insn.src1];
                }
                ++pc;
                break;
            case VmOpcode::VAddF32:
            case VmOpcode::VSubF32:
            case VmOpcode::VMulF32:
            case VmOpcode::VDivF32: {
                float a = 0.0f, b = 0.0f;
                const std::uint32_t ua = static_cast<std::uint32_t>(state.vregs[insn.src1][0]);
                const std::uint32_t ub = static_cast<std::uint32_t>(state.vregs[insn.src2][0]);
                std::memcpy(&a, &ua, 4);
                std::memcpy(&b, &ub, 4);
                float r = 0.0f;
                if (insn.opcode == VmOpcode::VAddF32) r = a + b;
                else if (insn.opcode == VmOpcode::VSubF32) r = a - b;
                else if (insn.opcode == VmOpcode::VMulF32) r = a * b;
                else r = a / b;
                std::uint32_t ur = 0;
                std::memcpy(&ur, &r, 4);
                state.vregs[insn.dst][0] = (state.vregs[insn.dst][0] & ~0xFFFFFFFFULL) | static_cast<std::uint64_t>(ur);
                ++pc;
                break;
            }
            case VmOpcode::VAddF64:
            case VmOpcode::VSubF64:
            case VmOpcode::VMulF64:
            case VmOpcode::VDivF64: {
                double a = 0.0, b = 0.0;
                std::memcpy(&a, &state.vregs[insn.src1][0], 8);
                std::memcpy(&b, &state.vregs[insn.src2][0], 8);
                double r = 0.0;
                if (insn.opcode == VmOpcode::VAddF64) r = a + b;
                else if (insn.opcode == VmOpcode::VSubF64) r = a - b;
                else if (insn.opcode == VmOpcode::VMulF64) r = a * b;
                else r = a / b;
                std::memcpy(&state.vregs[insn.dst][0], &r, 8);
                ++pc;
                break;
            }
            case VmOpcode::VCmpF32:
            case VmOpcode::VCmpF64: {
                double a = 0.0, b = 0.0;
                if (insn.opcode == VmOpcode::VCmpF32) {
                    float fa = 0.0f, fb = 0.0f;
                    const std::uint32_t ua = static_cast<std::uint32_t>(state.vregs[insn.src1][0]);
                    const std::uint32_t ub = static_cast<std::uint32_t>(state.vregs[insn.src2][0]);
                    std::memcpy(&fa, &ua, 4);
                    std::memcpy(&fb, &ub, 4);
                    a = static_cast<double>(fa);
                    b = static_cast<double>(fb);
                } else {
                    std::memcpy(&a, &state.vregs[insn.src1][0], 8);
                    std::memcpy(&b, &state.vregs[insn.src2][0], 8);
                }
                if (std::isnan(a) || std::isnan(b)) {
                    zf = true; cf = true; state.pf = true;
                } else if (a < b) {
                    zf = false; cf = true; state.pf = false;
                } else if (a > b) {
                    zf = false; cf = false; state.pf = false;
                } else {
                    zf = true; cf = false; state.pf = false;
                }
                sf = false;
                of = false;
                ++pc;
                break;
            }
            case VmOpcode::VLoad: {
                if (mem_slots == 0) [[unlikely]] {
                    finalize_state(false);
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::OutOfBounds, "VM memory is empty", "VmInterpreter::execute");
                }
                const std::size_t width_bytes = insn.aux;
                const std::int64_t byte_addr = static_cast<std::int64_t>(regs[insn.src1]) + insn.imm;
                if (byte_addr < 0 || static_cast<std::size_t>(byte_addr) + width_bytes > total_mem_bytes) [[unlikely]] {
                    finalize_state(false);
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::OutOfBounds, "VM vector memory load out of bounds", "VmInterpreter::execute");
                }
                if (width_bytes <= 8) {
                    std::uint64_t tmp = 0;
                    std::memcpy(&tmp, mem_bytes + byte_addr, width_bytes);
                    state.vregs[insn.dst][0] = tmp;
                    state.vregs[insn.dst][1] = 0;
                } else {
                    std::memcpy(state.vregs[insn.dst].data(), mem_bytes + byte_addr, 16);
                }
                ++pc;
                break;
            }
            case VmOpcode::VStore: {
                if (mem_slots == 0) [[unlikely]] {
                    finalize_state(false);
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::OutOfBounds, "VM memory is empty", "VmInterpreter::execute");
                }
                const std::size_t width_bytes = insn.aux;
                const std::int64_t byte_addr = static_cast<std::int64_t>(regs[insn.dst]) + insn.imm;
                if (byte_addr < 0 || static_cast<std::size_t>(byte_addr) + width_bytes > total_mem_bytes) [[unlikely]] {
                    finalize_state(false);
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::OutOfBounds, "VM vector memory store out of bounds", "VmInterpreter::execute");
                }
                const std::size_t b_start = static_cast<std::size_t>(byte_addr);
                std::memcpy(mem_bytes + b_start, state.vregs[insn.src1].data(), width_bytes);
                if (b_start < dirty_min) dirty_min = b_start;
                if (b_start + width_bytes > dirty_max) dirty_max = b_start + width_bytes;
                ++pc;
                break;
            }
            case VmOpcode::VXor:
                state.vregs[insn.dst][0] = state.vregs[insn.src1][0] ^ state.vregs[insn.src2][0];
                state.vregs[insn.dst][1] = state.vregs[insn.src1][1] ^ state.vregs[insn.src2][1];
                ++pc;
                break;
            case VmOpcode::VAnd:
                state.vregs[insn.dst][0] = state.vregs[insn.src1][0] & state.vregs[insn.src2][0];
                state.vregs[insn.dst][1] = state.vregs[insn.src1][1] & state.vregs[insn.src2][1];
                ++pc;
                break;
            case VmOpcode::VOr:
                state.vregs[insn.dst][0] = state.vregs[insn.src1][0] | state.vregs[insn.src2][0];
                state.vregs[insn.dst][1] = state.vregs[insn.src1][1] | state.vregs[insn.src2][1];
                ++pc;
                break;
            case VmOpcode::VMovGprToVec:
                state.vregs[insn.dst][0] = (insn.imm == 32) ? (regs[insn.src1] & 0xFFFFFFFFULL) : regs[insn.src1];
                state.vregs[insn.dst][1] = 0;
                ++pc;
                break;
            case VmOpcode::VMovVecToGpr:
                regs[insn.dst] = (insn.imm == 32) ? (state.vregs[insn.src1][0] & 0xFFFFFFFFULL) : state.vregs[insn.src1][0];
                ++pc;
                break;
            case VmOpcode::VCvtI2F: {
                const bool is_unsigned = (insn.imm & 1) != 0;
                const bool dst_f64 = (insn.imm & 2) != 0;
                const bool src_64 = (insn.imm & 4) != 0;
                const std::uint64_t raw = regs[insn.src1];
                if (dst_f64) {
                    const double d = is_unsigned
                        ? (src_64 ? static_cast<double>(raw) : static_cast<double>(static_cast<std::uint32_t>(raw)))
                        : (src_64 ? static_cast<double>(static_cast<std::int64_t>(raw)) : static_cast<double>(static_cast<std::int32_t>(raw)));
                    std::memcpy(&state.vregs[insn.dst][0], &d, 8);
                } else {
                    const float f = is_unsigned
                        ? (src_64 ? static_cast<float>(raw) : static_cast<float>(static_cast<std::uint32_t>(raw)))
                        : (src_64 ? static_cast<float>(static_cast<std::int64_t>(raw)) : static_cast<float>(static_cast<std::int32_t>(raw)));
                    std::uint32_t uf = 0;
                    std::memcpy(&uf, &f, 4);
                    state.vregs[insn.dst][0] = (state.vregs[insn.dst][0] & ~0xFFFFFFFFULL) | static_cast<std::uint64_t>(uf);
                }
                ++pc;
                break;
            }
            case VmOpcode::VCvtF2I: {
                const bool is_unsigned = (insn.imm & 1) != 0;
                const bool src_f64 = (insn.imm & 2) != 0;
                const bool dst_64 = (insn.imm & 4) != 0;
                double dv = 0.0;
                if (src_f64) {
                    std::memcpy(&dv, &state.vregs[insn.src1][0], 8);
                } else {
                    float fv = 0.0f;
                    const std::uint32_t uf = static_cast<std::uint32_t>(state.vregs[insn.src1][0]);
                    std::memcpy(&fv, &uf, 4);
                    dv = static_cast<double>(fv);
                }
                if (is_unsigned) {
                    regs[insn.dst] = dst_64 ? static_cast<std::uint64_t>(dv) : static_cast<std::uint64_t>(static_cast<std::uint32_t>(dv));
                } else {
                    regs[insn.dst] = dst_64
                        ? static_cast<std::uint64_t>(static_cast<std::int64_t>(dv))
                        : static_cast<std::uint64_t>(static_cast<std::uint32_t>(static_cast<std::int32_t>(dv)));
                }
                ++pc;
                break;
            }
            case VmOpcode::VCvtF2F: {
                if (insn.imm == 64) {
                    float fv = 0.0f;
                    const std::uint32_t uf = static_cast<std::uint32_t>(state.vregs[insn.src1][0]);
                    std::memcpy(&fv, &uf, 4);
                    const double dv = static_cast<double>(fv);
                    std::memcpy(&state.vregs[insn.dst][0], &dv, 8);
                } else {
                    double dv = 0.0;
                    std::memcpy(&dv, &state.vregs[insn.src1][0], 8);
                    const float fv = static_cast<float>(dv);
                    std::uint32_t uf = 0;
                    std::memcpy(&uf, &fv, 4);
                    state.vregs[insn.dst][0] = (state.vregs[insn.dst][0] & ~0xFFFFFFFFULL) | static_cast<std::uint64_t>(uf);
                }
                ++pc;
                break;
            }
            case VmOpcode::VPAdd32:
            case VmOpcode::VPSub32: {
                const bool is_sub = (insn.opcode == VmOpcode::VPSub32);
                for (int half = 0; half < 2; ++half) {
                    const std::uint64_t a = state.vregs[insn.src1][half];
                    const std::uint64_t b = state.vregs[insn.src2][half];
                    const std::uint32_t lo = is_sub ? (static_cast<std::uint32_t>(a) - static_cast<std::uint32_t>(b))
                                                    : (static_cast<std::uint32_t>(a) + static_cast<std::uint32_t>(b));
                    const std::uint32_t hi = is_sub ? (static_cast<std::uint32_t>(a >> 32) - static_cast<std::uint32_t>(b >> 32))
                                                    : (static_cast<std::uint32_t>(a >> 32) + static_cast<std::uint32_t>(b >> 32));
                    state.vregs[insn.dst][half] = static_cast<std::uint64_t>(lo) | (static_cast<std::uint64_t>(hi) << 32);
                }
                ++pc;
                break;
            }
            case VmOpcode::VPAdd64:
                state.vregs[insn.dst][0] = state.vregs[insn.src1][0] + state.vregs[insn.src2][0];
                state.vregs[insn.dst][1] = state.vregs[insn.src1][1] + state.vregs[insn.src2][1];
                ++pc;
                break;
            case VmOpcode::VPSub64:
                state.vregs[insn.dst][0] = state.vregs[insn.src1][0] - state.vregs[insn.src2][0];
                state.vregs[insn.dst][1] = state.vregs[insn.src1][1] - state.vregs[insn.src2][1];
                ++pc;
                break;
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
                pc = (sf != of) ? static_cast<std::size_t>(insn.imm) : (pc + 1);
                break;
            case VmOpcode::Jle:
                pc = ((sf != of) || zf) ? static_cast<std::size_t>(insn.imm) : (pc + 1);
                break;
            case VmOpcode::Jgt:
                pc = ((sf == of) && !zf) ? static_cast<std::size_t>(insn.imm) : (pc + 1);
                break;
            case VmOpcode::Jge:
                pc = (sf == of) ? static_cast<std::size_t>(insn.imm) : (pc + 1);
                break;
            case VmOpcode::Call:
                if (tls_call_stack.size() >= options.max_call_depth) [[unlikely]] {
                    finalize_state(false);
                    state.call_stack = tls_call_stack;
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::OutOfBounds, "VM call stack overflow", "VmInterpreter::execute");
                }
                tls_call_stack.push_back(pc + 1);
                pc = static_cast<std::size_t>(insn.imm);
                break;
            case VmOpcode::Ret:
                if (tls_call_stack.empty()) {
                    finalize_state(false);
                    return state;
                }
                pc = tls_call_stack.back();
                tls_call_stack.pop_back();
                break;
            case VmOpcode::Halt:
                finalize_state(false);
                if (insn.dst == 0xFF) [[unlikely]] {
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::OutOfBounds, "Unauthorized indirect control-flow target at runtime", "VmInterpreter::execute");
                }
                return state;
            case VmOpcode::CallExt: {
                if (!options.external_call_handler) [[unlikely]] {
                    finalize_state(false);
                    return core::diagnostics::Result<VmExecState>::err(
                        ErrorCode::UnsupportedFormat,
                        "External call (vm.callext) requires native runtime or external_call_handler",
                        "VmInterpreter::execute");
                }
                std::memcpy(state.regs.data(), regs, sizeof(regs));
                auto res = options.external_call_handler(insn.imm, state.regs);
                if (!res.has_value()) [[unlikely]] {
                    finalize_state(false);
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
                finalize_state(false);
                return core::diagnostics::Result<VmExecState>::err(
                    ErrorCode::ParseError, "Invalid VM opcode during execution", "VmInterpreter::execute");
        }
    }
#endif

    finalize_state(false);
    return state;
}

core::diagnostics::Result<VmExecState>
VmInterpreter::execute(const BvmProgram& program, const VmExecOptions& options) {
    using core::diagnostics::ErrorCode;

    if (program.instructions.empty()) {
        return core::diagnostics::Result<VmExecState>::err(
            ErrorCode::EmptyInput, "BvmProgram has no instructions", "VmInterpreter::execute");
    }

    constexpr std::size_t kCacheSize = 8;
    thread_local std::array<CachedProgramEntry, kCacheSize> tls_prog_cache{};
    thread_local std::size_t tls_cache_next = 0;

    const VmInstruction* ptr = program.instructions.data();
    const std::size_t len = program.instructions.size();
    const std::uint64_t fp = compute_program_fingerprint(program);

    for (const auto& entry : tls_prog_cache) {
        if (entry.ptr == ptr && entry.len == len &&
            entry.seed == program.build_seed && entry.fingerprint == fp) {
            return execute_prepared(entry.prepared, options);
        }
    }

    auto prep = prepare(program);
    if (!prep) {
        return core::diagnostics::Result<VmExecState>::err(
            prep.error().code, prep.error().message, prep.error().context);
    }

    auto& slot = tls_prog_cache[tls_cache_next];
    tls_cache_next = (tls_cache_next + 1) % kCacheSize;
    slot.ptr = ptr;
    slot.len = len;
    slot.seed = program.build_seed;
    slot.fingerprint = fp;
    slot.prepared = std::move(prep.value());

    return execute_prepared(slot.prepared, options);
}

} // namespace bytemorph::virt
