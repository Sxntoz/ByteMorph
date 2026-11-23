#pragma once

#include "bytemorph/core/analysis/cfg.hpp"
#include "bytemorph/core/ir/ir.hpp"

namespace bytemorph::arch::aarch64 {

class AArch64Lifter {
public:
    [[nodiscard]] core::ir::IrInstruction
    lift_instruction(const core::analysis::DisassembledInstruction& insn) const;

    [[nodiscard]] core::ir::IrFunction
    lift_function(const core::analysis::FunctionInfo& fn) const;
};

} // namespace bytemorph::arch::aarch64
