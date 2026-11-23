#pragma once

#include "bytemorph/core/analysis/cfg.hpp"
#include "bytemorph/core/binary/binary_file.hpp"
#include "bytemorph/core/diagnostics/error.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace bytemorph::core::analysis {

class IDisassemblerEngine {
public:
    virtual ~IDisassemblerEngine() = default;

    [[nodiscard]] virtual binary::Architecture architecture() const noexcept = 0;

    [[nodiscard]] virtual diagnostics::Result<std::vector<DisassembledInstruction>>
    disassemble(std::span<const std::uint8_t> code,
                std::uint64_t base_va,
                std::size_t max_instructions = 0) const = 0;
};

class BinaryAnalyzer {
public:
    struct Options {
        std::size_t max_instructions_per_section{100000};
        std::size_t max_functions{4096};
    };

    [[nodiscard]] diagnostics::Result<AnalysisResult>
    analyze(const binary::IBinaryFile& binary,
            const IDisassemblerEngine& disasm,
            const Options& options) const;

    [[nodiscard]] diagnostics::Result<AnalysisResult>
    analyze(const binary::IBinaryFile& binary,
            const IDisassemblerEngine& disasm) const {
        return analyze(binary, disasm, Options{});
    }
};

} // namespace bytemorph::core::analysis
