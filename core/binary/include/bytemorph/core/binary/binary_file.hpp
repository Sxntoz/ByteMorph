#pragma once

#include "bytemorph/core/binary/types.hpp"
#include "bytemorph/core/diagnostics/error.hpp"

#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <vector>

namespace bytemorph::core::binary {

[[nodiscard]] inline std::optional<std::uint64_t> checked_add(std::uint64_t a, std::uint64_t b) noexcept {
    if (a > (std::numeric_limits<std::uint64_t>::max)() - b) {
        return std::nullopt;
    }
    return a + b;
}

class IBinaryFile {
public:
    virtual ~IBinaryFile() = default;

    [[nodiscard]] virtual const BinaryInfo& info() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<SectionInfo>& sections() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<SegmentInfo>& segments() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<SymbolInfo>& symbols() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ImportInfo>& imports() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<ExportInfo>& exports() const noexcept = 0;
    [[nodiscard]] virtual const std::vector<RelocationInfo>& relocations() const noexcept = 0;

    /// Returns a read-only view of the raw file bytes.
    [[nodiscard]] virtual std::span<const std::uint8_t> raw_bytes() const noexcept = 0;

    /// Returns a bounds-checked slice of bytes corresponding to a virtual address range.
    [[nodiscard]] virtual diagnostics::Result<std::span<const std::uint8_t>>
    read_virtual(std::uint64_t va, std::size_t size) const = 0;

    /// Translates a virtual address to a file offset if mapped in a section/segment.
    [[nodiscard]] virtual std::optional<std::uint64_t> va_to_offset(std::uint64_t va) const noexcept = 0;
};

} // namespace bytemorph::core::binary
