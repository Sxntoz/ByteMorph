#pragma once

#include "bytemorph/core/diagnostics/error.hpp"
#include "bytemorph/virt/bvm_format.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace bytemorph::virt {

struct VmExecOptions {
    std::uint64_t max_steps{1000000};
    std::size_t memory_slots{4096};
    std::size_t max_call_depth{256};
    bool use_memory_pool{true};
    std::uint64_t pic_base_va{0};
    std::array<std::uint64_t, BvmProgram::kNumRegisters> initial_regs{};
    std::array<std::array<std::uint64_t, 2>, BvmProgram::kNumRegisters> initial_vregs{};
    std::function<std::optional<std::uint64_t>(std::int64_t, const std::array<std::uint64_t, BvmProgram::kNumRegisters>&)> external_call_handler;
};

struct VmExecState {
    std::array<std::uint64_t, BvmProgram::kNumRegisters> regs{};
    std::array<std::array<std::uint64_t, 2>, BvmProgram::kNumRegisters> vregs{};
    std::vector<std::uint64_t> memory;
    std::vector<std::size_t> call_stack;
    std::size_t pc{0};
    bool zf{false};
    bool sf{false};
    bool cf{false};
    bool of{false};
    bool pf{false};
    std::uint32_t mxcsr{0x1F80};
    std::uint32_t fpcr{0};
    std::uint32_t fpsr{0};
    std::uint64_t steps_executed{0};
    std::uint64_t allocations_count{0};
    std::uint64_t return_value{0};
};

struct FastVmInstruction {
    VmOpcode opcode{VmOpcode::Nop};
    std::uint8_t dst{0};
    std::uint8_t src1{0};
    std::uint8_t src2{0};
    std::uint32_t aux{0};
    std::int64_t imm{0};
};

struct PreparedBvmProgram {
    std::vector<FastVmInstruction> insns;
    std::size_t code_len{0};
    std::uint64_t build_seed{0};
    std::uint64_t fingerprint{0};
    bool has_mem_ops{false};
    bool has_simd_ops{false};
};

/// Register-based 64-bit ByteMorph Virtual Machine interpreter.
class VmInterpreter {
public:
    [[nodiscard]] static core::diagnostics::Result<PreparedBvmProgram>
    prepare(const BvmProgram& program);

    [[nodiscard]] static core::diagnostics::Result<VmExecState>
    execute_prepared(const PreparedBvmProgram& prepared, const VmExecOptions& options = {});

    [[nodiscard]] static core::diagnostics::Result<VmExecState>
    execute(const BvmProgram& program, const VmExecOptions& options = {});
};

} // namespace bytemorph::virt
