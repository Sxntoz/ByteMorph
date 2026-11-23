#pragma once

#include "bytemorph/core/binary/binary_file.hpp"
#include "bytemorph/core/diagnostics/error.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <vector>

namespace bytemorph::core::binary {

class IBinaryParser {
public:
    virtual ~IBinaryParser() = default;

    [[nodiscard]] virtual bool supports(BinaryFormat format) const noexcept = 0;
    [[nodiscard]] virtual diagnostics::Result<std::unique_ptr<IBinaryFile>>
    parse(std::vector<std::uint8_t> buffer) const = 0;
};

class BinaryLoader {
public:
    static constexpr std::size_t kDefaultMaxFileSize = 512ULL * 1024ULL * 1024ULL;

    void register_parser(std::unique_ptr<IBinaryParser> parser);

    /// Performs fast, bounds-checked format/arch/endianness detection on raw bytes.
    [[nodiscard]] static diagnostics::Result<DetectedSignature>
    detect_signature(std::span<const std::uint8_t> data);

    /// Safely reads a file into memory with size bounds and parses it.
    [[nodiscard]] diagnostics::Result<std::unique_ptr<IBinaryFile>>
    load_file(const std::filesystem::path& path, std::size_t max_bytes = kDefaultMaxFileSize) const;

    /// Parses an already-loaded byte buffer (treats input as untrusted).
    [[nodiscard]] diagnostics::Result<std::unique_ptr<IBinaryFile>>
    load_buffer(std::vector<std::uint8_t> buffer) const;

private:
    std::vector<std::unique_ptr<IBinaryParser>> parsers_;
};

} // namespace bytemorph::core::binary
