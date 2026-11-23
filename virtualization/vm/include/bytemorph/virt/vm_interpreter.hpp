#pragma once

#include "bytemorph/core/diagnostics/error.hpp"
#include "bytemorph/virt/bvm_format.hpp"

#include <array>
#include <cstdint>
#include <vector>

namespace bytemorph::virt {

struct VmExecOptions {
    std::uint64_t max_steps{1000000};
    std::size_t memory_slots{4096};
    std::size_t max_call_depth{256};
    std::array<std::uint64_t, BvmProgram::kNumRegisters> initial_regs{};
};

struct VmExecState {
    std::array<std::uint64_t, BvmProgram::kNumRegisters> regs{};
    std::vector<std::uint64_t> memory;
    std::vector<std::size_t> call_stack;
    std::size_t pc{0};
    bool zf{false};
    bool sf{false};
    std::uint64_t steps_executed{0};
    std::uint64_t return_value{0};
};

/// Register-based 64-bit ByteMorph Virtual Machine interpreter.
class VmInterpreter {
public:
    [[nodiscard]] static core::diagnostics::Result<VmExecState>
    execute(const BvmProgram& program, const VmExecOptions& options = {});
};

} // namespace bytemorph::virt
