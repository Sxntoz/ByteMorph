#pragma once

#include "bytemorph/core/analysis/analyzer.hpp"

namespace bytemorph::arch::aarch64 {

/// Interface/placeholder for ARM64 (AArch64) disassembler planned for v0.2+.
/// Returns ErrorCode::NotImplemented cleanly in v0.1.
class AArch64Disassembler final : public core::analysis::IDisassemblerEngine {
public:
    [[nodiscard]] core::binary::Architecture architecture() const noexcept override {
        return core::binary::Architecture::ARM64;
    }

    [[nodiscard]] core::diagnostics::Result<std::vector<core::analysis::DisassembledInstruction>>
    disassemble(std::span<const std::uint8_t> code,
                std::uint64_t base_va,
                std::size_t max_instructions = 0) const override;
};

} // namespace bytemorph::arch::aarch64
