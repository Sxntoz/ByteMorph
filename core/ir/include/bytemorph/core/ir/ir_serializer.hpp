#pragma once

#include "bytemorph/core/diagnostics/error.hpp"
#include "bytemorph/core/ir/ir.hpp"

#include <cstdint>
#include <filesystem>
#include <span>
#include <vector>

namespace bytemorph::core::ir {

/// Versioned binary container for ByteMorph IR modules (.ir).
/// Header: Magic "BMIR" (4B) | Version u16 (1) | Flags u16 (0) | Arch u32 | PayloadSize u32 | CRC32-like FNV1a u32
class IrSerializer {
public:
    static constexpr std::uint32_t kMagic = 0x52494D42u; // "BMIR" LE
    static constexpr std::uint16_t kVersion = 1;
    static constexpr std::size_t kMaxFunctions = 65536;
    static constexpr std::size_t kMaxBlocksPerFn = 65536;
    static constexpr std::size_t kMaxInsnsPerBlock = 262144;

    [[nodiscard]] static diagnostics::Result<std::vector<std::uint8_t>>
    serialize(const IrModule& mod);

    [[nodiscard]] static diagnostics::Result<IrModule>
    deserialize(std::span<const std::uint8_t> data);

    [[nodiscard]] static diagnostics::Result<void>
    save_to_file(const IrModule& mod, const std::filesystem::path& path);

    [[nodiscard]] static diagnostics::Result<IrModule>
    load_from_file(const std::filesystem::path& path);
};

} // namespace bytemorph::core::ir
