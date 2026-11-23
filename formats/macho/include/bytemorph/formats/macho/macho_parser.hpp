#pragma once

#include "bytemorph/core/binary/loader.hpp"

namespace bytemorph::formats::macho {

/// Interface/placeholder for Mach-O (macOS) parser planned for v0.2+.
/// Returns ErrorCode::NotImplemented cleanly in v0.1.
class MachOParser final : public core::binary::IBinaryParser {
public:
    [[nodiscard]] bool supports(core::binary::BinaryFormat format) const noexcept override;
    [[nodiscard]] core::diagnostics::Result<std::unique_ptr<core::binary::IBinaryFile>>
    parse(std::vector<std::uint8_t> buffer) const override;
};

} // namespace bytemorph::formats::macho
