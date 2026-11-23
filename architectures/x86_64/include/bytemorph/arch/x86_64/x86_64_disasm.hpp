#pragma once

#include "bytemorph/core/analysis/analyzer.hpp"

namespace bytemorph::arch::x86_64 {

class X86_64Disassembler final : public core::analysis::IDisassemblerEngine {
public:
    [[nodiscard]] core::binary::Architecture architecture() const noexcept override {
        return core::binary::Architecture::X86_64;
    }

    [[nodiscard]] core::diagnostics::Result<std::vector<core::analysis::DisassembledInstruction>>
    disassemble(std::span<const std::uint8_t> code,
                std::uint64_t base_va,
                std::size_t max_instructions = 0) const override;
};

} // namespace bytemorph::arch::x86_64
