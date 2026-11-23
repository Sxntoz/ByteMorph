#pragma once

#include "bytemorph/core/binary/loader.hpp"

namespace bytemorph::formats::pe {

class PeParser final : public core::binary::IBinaryParser {
public:
    [[nodiscard]] bool supports(core::binary::BinaryFormat format) const noexcept override;
    [[nodiscard]] core::diagnostics::Result<std::unique_ptr<core::binary::IBinaryFile>>
    parse(std::vector<std::uint8_t> buffer) const override;
};

} // namespace bytemorph::formats::pe
