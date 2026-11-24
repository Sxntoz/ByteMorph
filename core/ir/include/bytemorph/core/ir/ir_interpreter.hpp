#pragma once

#include "bytemorph/core/diagnostics/error.hpp"
#include "bytemorph/core/ir/ir.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace bytemorph::core::ir {

struct IrExecState {
    std::unordered_map<std::string, std::uint64_t> regs;
    std::array<std::array<std::uint64_t, 2>, 32> vregs{};
    std::vector<std::uint64_t> memory; // indexed in 64-bit slots for bounded safe execution
    bool zf{false};
    bool sf{false};
    bool cf{false};
    bool of{false};
    bool pf{false};
    std::uint64_t steps_executed{0};
    std::uint64_t return_value{0};
};

struct IrExecOptions {
    std::uint64_t max_steps{100000};
    std::size_t memory_slots{1024};
    std::unordered_map<std::string, std::uint64_t> initial_regs;
    std::array<std::array<std::uint64_t, 2>, 32> initial_vregs{};
    std::uint64_t pic_base_va{0};
};

/// Reference deterministic interpreter for ByteMorph IR functions.
/// Used for differential testing (IR vs obfuscated IR, and IR vs ByteMorph VM).
class IrInterpreter {
public:
    [[nodiscard]] static diagnostics::Result<IrExecState>
    execute(const IrFunction& fn, const IrExecOptions& options = {});
};

} // namespace bytemorph::core::ir
