#include "bytemorph/core/binary/loader.hpp"

#include "bytemorph/core/diagnostics/logger.hpp"

#include <cstring>
#include <fstream>

namespace bytemorph::core::binary {

namespace {

[[nodiscard]] std::uint16_t read_u16_le(std::span<const std::uint8_t> data, std::size_t off) noexcept {
    return static_cast<std::uint16_t>(data[off]) |
           (static_cast<std::uint16_t>(data[off + 1]) << 8);
}

[[nodiscard]] std::uint32_t read_u32_le(std::span<const std::uint8_t> data, std::size_t off) noexcept {
    return static_cast<std::uint32_t>(data[off]) |
           (static_cast<std::uint32_t>(data[off + 1]) << 8) |
           (static_cast<std::uint32_t>(data[off + 2]) << 16) |
           (static_cast<std::uint32_t>(data[off + 3]) << 24);
}

[[nodiscard]] std::uint16_t read_u16_be(std::span<const std::uint8_t> data, std::size_t off) noexcept {
    return (static_cast<std::uint16_t>(data[off]) << 8) |
           static_cast<std::uint16_t>(data[off + 1]);
}

[[nodiscard]] std::uint32_t read_u32_be(std::span<const std::uint8_t> data, std::size_t off) noexcept {
    return (static_cast<std::uint32_t>(data[off]) << 24) |
           (static_cast<std::uint32_t>(data[off + 1]) << 16) |
           (static_cast<std::uint32_t>(data[off + 2]) << 8) |
           static_cast<std::uint32_t>(data[off + 3]);
}

} // namespace

void BinaryLoader::register_parser(std::unique_ptr<IBinaryParser> parser) {
    if (parser) {
        parsers_.push_back(std::move(parser));
    }
}

diagnostics::Result<DetectedSignature>
BinaryLoader::detect_signature(std::span<const std::uint8_t> data) {
    using diagnostics::ErrorCode;
    if (data.empty()) {
        return diagnostics::Result<DetectedSignature>::err(
            ErrorCode::EmptyInput, "Input binary buffer is empty", "BinaryLoader::detect_signature");
    }
    if (data.size() < 4) {
        return diagnostics::Result<DetectedSignature>::err(
            ErrorCode::TruncatedData, "Buffer smaller than 4-byte magic header", "BinaryLoader::detect_signature");
    }

    DetectedSignature sig;

    // ELF: 0x7F 'E' 'L' 'F'
    if (data[0] == 0x7F && data[1] == 'E' && data[2] == 'L' && data[3] == 'F') {
        if (data.size() < 20) {
            return diagnostics::Result<DetectedSignature>::err(
                ErrorCode::TruncatedData, "Truncated ELF identification header", "BinaryLoader::detect_signature");
        }
        const std::uint8_t ei_class = data[4];
        const std::uint8_t ei_data = data[5];

        sig.target_os = TargetOS::Linux;
        if (ei_class == 1) {
            sig.format = BinaryFormat::ELF32;
        } else if (ei_class == 2) {
            sig.format = BinaryFormat::ELF64;
        } else {
            return diagnostics::Result<DetectedSignature>::err(
                ErrorCode::ParseError, "Invalid ELF EI_CLASS value", "BinaryLoader::detect_signature");
        }

        if (ei_data == 1) {
            sig.endianness = Endianness::Little;
        } else if (ei_data == 2) {
            sig.endianness = Endianness::Big;
        } else {
            return diagnostics::Result<DetectedSignature>::err(
                ErrorCode::ParseError, "Invalid ELF EI_DATA value", "BinaryLoader::detect_signature");
        }

        const std::uint16_t e_machine = (sig.endianness == Endianness::Little)
            ? read_u16_le(data, 18)
            : read_u16_be(data, 18);

        switch (e_machine) {
            case 3:   sig.architecture = Architecture::X86; break;
            case 62:  sig.architecture = Architecture::X86_64; break;
            case 183: sig.architecture = Architecture::ARM64; break;
            default:  sig.architecture = Architecture::Unknown; break;
        }
        return sig;
    }

    // PE: 'M' 'Z'
    if (data[0] == 'M' && data[1] == 'Z') {
        if (data.size() < 0x40) {
            return diagnostics::Result<DetectedSignature>::err(
                ErrorCode::TruncatedData, "Truncated DOS header in PE file", "BinaryLoader::detect_signature");
        }
        const std::uint32_t e_lfanew = read_u32_le(data, 0x3C);
        const auto pe_end = checked_add(e_lfanew, 24);
        if (!pe_end || *pe_end > data.size()) {
            return diagnostics::Result<DetectedSignature>::err(
                ErrorCode::TruncatedData, "Invalid or out-of-bounds e_lfanew offset", "BinaryLoader::detect_signature");
        }
        if (data[e_lfanew] != 'P' || data[e_lfanew + 1] != 'E' ||
            data[e_lfanew + 2] != 0 || data[e_lfanew + 3] != 0) {
            return diagnostics::Result<DetectedSignature>::err(
                ErrorCode::InvalidMagic, "Missing PE\\0\\0 signature at e_lfanew", "BinaryLoader::detect_signature");
        }

        sig.endianness = Endianness::Little;
        sig.target_os = TargetOS::Windows;

        const std::uint16_t machine = read_u16_le(data, e_lfanew + 4);
        switch (machine) {
            case 0x014C: sig.architecture = Architecture::X86; break;
            case 0x8664: sig.architecture = Architecture::X86_64; break;
            case 0xAA64: sig.architecture = Architecture::ARM64; break;
            default:     sig.architecture = Architecture::Unknown; break;
        }

        const auto opt_magic_off = checked_add(e_lfanew, 26);
        if (!opt_magic_off || *opt_magic_off > data.size()) {
            return diagnostics::Result<DetectedSignature>::err(
                ErrorCode::TruncatedData, "Truncated PE optional header", "BinaryLoader::detect_signature");
        }
        const std::uint16_t opt_magic = read_u16_le(data, e_lfanew + 24);
        if (opt_magic == 0x10B) {
            sig.format = BinaryFormat::PE32;
        } else if (opt_magic == 0x20B) {
            sig.format = BinaryFormat::PE32Plus;
        } else {
            return diagnostics::Result<DetectedSignature>::err(
                ErrorCode::ParseError, "Unknown PE OptionalHeader magic", "BinaryLoader::detect_signature");
        }
        return sig;
    }

    const std::uint32_t magic_be = read_u32_be(data, 0);
    const std::uint32_t magic_le = read_u32_le(data, 0);

    // Mach-O Fat/Universal: 0xCAFEBABE (32-bit arch headers) / 0xCAFEBABF (64-bit arch headers)
    if (magic_be == 0xCAFEBABE || magic_be == 0xCAFEBABF) {
        if (data.size() < 8) {
            return diagnostics::Result<DetectedSignature>::err(
                ErrorCode::TruncatedData, "Truncated Mach-O Fat header", "BinaryLoader::detect_signature");
        }
        const std::uint32_t nfat_arch = read_u32_be(data, 4);
        const std::size_t entry_size = (magic_be == 0xCAFEBABF) ? 32 : 20;
        const auto needed = checked_add(8, static_cast<std::uint64_t>(nfat_arch) * entry_size);
        if (nfat_arch == 0 || nfat_arch > 32 || !needed || *needed > data.size()) {
            return diagnostics::Result<DetectedSignature>::err(
                ErrorCode::InvalidMagic, "Invalid or truncated Mach-O Fat/Universal header", "BinaryLoader::detect_signature");
        }
        sig.format = BinaryFormat::MachOFat;
        sig.target_os = TargetOS::MacOS;
        sig.endianness = Endianness::Little;
        const std::uint32_t first_cputype = read_u32_be(data, 8);
        if (first_cputype == 0x01000007) {
            sig.architecture = Architecture::X86_64;
        } else if (first_cputype == 0x0100000C) {
            sig.architecture = Architecture::ARM64;
        } else if (first_cputype == 0x00000007) {
            sig.architecture = Architecture::X86;
        }
        return sig;
    }

    // Mach-O: 0xFEEDFACE / 0xCEFAEDFE (32), 0xFEEDFACF / 0xCFFAEDFE (64)
    if (magic_be == 0xFEEDFACE || magic_le == 0xFEEDFACE ||
        magic_be == 0xFEEDFACF || magic_le == 0xFEEDFACF) {
        if (data.size() < 8) {
            return diagnostics::Result<DetectedSignature>::err(
                ErrorCode::TruncatedData, "Truncated Mach-O header", "BinaryLoader::detect_signature");
        }
        const bool is_64 = (magic_be == 0xFEEDFACF || magic_le == 0xFEEDFACF);
        const bool is_le = (magic_le == 0xFEEDFACE || magic_le == 0xFEEDFACF);
        const std::size_t min_hdr = is_64 ? 32 : 28;
        if (data.size() < min_hdr) {
            return diagnostics::Result<DetectedSignature>::err(
                ErrorCode::TruncatedData, "Truncated Mach-O header", "BinaryLoader::detect_signature");
        }
        sig.target_os = TargetOS::MacOS;
        sig.format = is_64 ? BinaryFormat::MachO64 : BinaryFormat::MachO32;
        sig.endianness = is_le ? Endianness::Little : Endianness::Big;

        const std::uint32_t cputype = is_le ? read_u32_le(data, 4) : read_u32_be(data, 4);
        if (cputype == 0x01000007) {
            sig.architecture = Architecture::X86_64;
        } else if (cputype == 0x0100000C) {
            sig.architecture = Architecture::ARM64;
        } else if (cputype == 0x00000007) {
            sig.architecture = Architecture::X86;
        }
        return sig;
    }

    return diagnostics::Result<DetectedSignature>::err(
        ErrorCode::InvalidMagic, "Unrecognized binary format magic", "BinaryLoader::detect_signature");
}

diagnostics::Result<std::unique_ptr<IBinaryFile>>
BinaryLoader::load_file(const std::filesystem::path& path, std::size_t max_bytes) const {
    using diagnostics::ErrorCode;
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || ec) {
        return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
            ErrorCode::FileNotFound, "File does not exist: " + path.string(), "BinaryLoader::load_file");
    }

    const auto fsize = std::filesystem::file_size(path, ec);
    if (ec) {
        return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
            ErrorCode::IoError, "Unable to query file size: " + ec.message(), "BinaryLoader::load_file");
    }
    if (fsize == 0) {
        return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
            ErrorCode::EmptyInput, "File is empty: " + path.string(), "BinaryLoader::load_file");
    }
    if (fsize > max_bytes) {
        return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
            ErrorCode::OutOfBounds, "File exceeds maximum allowed size", "BinaryLoader::load_file");
    }

    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
        return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
            ErrorCode::IoError, "Failed to open file for reading", "BinaryLoader::load_file");
    }

    std::vector<std::uint8_t> buffer(static_cast<std::size_t>(fsize));
    if (!ifs.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(buffer.size()))) {
        return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
            ErrorCode::IoError, "Failed to read complete file bytes", "BinaryLoader::load_file");
    }

    diagnostics::Logger::instance().info("BinaryLoader", "Loaded " + std::to_string(buffer.size()) + " bytes from " + path.string());
    return load_buffer(std::move(buffer));
}

diagnostics::Result<std::unique_ptr<IBinaryFile>>
BinaryLoader::load_buffer(std::vector<std::uint8_t> buffer) const {
    using diagnostics::ErrorCode;
    auto sig_res = detect_signature(buffer);
    if (!sig_res) {
        return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
            sig_res.error().code, sig_res.error().message, sig_res.error().context);
    }

    const auto sig = sig_res.value();
    for (const auto& parser : parsers_) {
        if (parser->supports(sig.format)) {
            return parser->parse(std::move(buffer));
        }
    }

    return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
        ErrorCode::UnsupportedFormat,
        std::string("No registered parser for format: ") + std::string(to_string(sig.format)),
        "BinaryLoader::load_buffer");
}

} // namespace bytemorph::core::binary
