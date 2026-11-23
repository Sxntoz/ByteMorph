#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace bytemorph::core::binary {

enum class BinaryFormat {
    Unknown = 0,
    PE32,
    PE32Plus,
    ELF32,
    ELF64,
    MachO32,
    MachO64,
    MachOFat
};

enum class Architecture {
    Unknown = 0,
    X86,
    X86_64,
    ARM64
};

enum class Endianness {
    Unknown = 0,
    Little,
    Big
};

enum class TargetOS {
    Unknown = 0,
    Windows,
    Linux,
    MacOS
};

enum class BinaryType {
    Unknown = 0,
    Executable,
    SharedLibrary,
    Object,
    Core
};

[[nodiscard]] inline std::string_view to_string(BinaryFormat fmt) noexcept {
    switch (fmt) {
        case BinaryFormat::Unknown: return "Unknown";
        case BinaryFormat::PE32: return "PE32";
        case BinaryFormat::PE32Plus: return "PE32+";
        case BinaryFormat::ELF32: return "ELF32";
        case BinaryFormat::ELF64: return "ELF64";
        case BinaryFormat::MachO32: return "Mach-O 32";
        case BinaryFormat::MachO64: return "Mach-O 64";
        case BinaryFormat::MachOFat: return "Mach-O Fat/Universal";
    }
    return "Unknown";
}

[[nodiscard]] inline std::string_view to_string(Architecture arch) noexcept {
    switch (arch) {
        case Architecture::Unknown: return "Unknown";
        case Architecture::X86: return "x86";
        case Architecture::X86_64: return "x86-64";
        case Architecture::ARM64: return "ARM64";
    }
    return "Unknown";
}

[[nodiscard]] inline std::string_view to_string(Endianness e) noexcept {
    switch (e) {
        case Endianness::Unknown: return "Unknown";
        case Endianness::Little: return "Little-Endian";
        case Endianness::Big: return "Big-Endian";
    }
    return "Unknown";
}

[[nodiscard]] inline std::string_view to_string(TargetOS os) noexcept {
    switch (os) {
        case TargetOS::Unknown: return "Unknown";
        case TargetOS::Windows: return "Windows";
        case TargetOS::Linux: return "Linux";
        case TargetOS::MacOS: return "macOS";
    }
    return "Unknown";
}

[[nodiscard]] inline std::string_view to_string(BinaryType t) noexcept {
    switch (t) {
        case BinaryType::Unknown: return "Unknown";
        case BinaryType::Executable: return "Executable";
        case BinaryType::SharedLibrary: return "Shared Library";
        case BinaryType::Object: return "Relocatable Object";
        case BinaryType::Core: return "Core Dump";
    }
    return "Unknown";
}

struct SectionInfo {
    std::string name;
    std::uint64_t virtual_address{0};
    std::uint64_t virtual_size{0};
    std::uint64_t raw_offset{0};
    std::uint64_t raw_size{0};
    std::uint64_t characteristics{0};
    bool readable{false};
    bool writable{false};
    bool executable{false};
};

struct SegmentInfo {
    std::string name;
    std::uint64_t virtual_address{0};
    std::uint64_t virtual_size{0};
    std::uint64_t file_offset{0};
    std::uint64_t file_size{0};
    std::uint32_t flags{0};
    bool readable{false};
    bool writable{false};
    bool executable{false};
};

struct SymbolInfo {
    std::string name;
    std::uint64_t address{0};
    std::uint64_t size{0};
    bool is_function{false};
    bool is_exported{false};
    bool is_imported{false};
};

struct ImportInfo {
    std::string library;
    std::string symbol;
    std::uint64_t address{0};
    std::uint16_t ordinal{0};
    bool by_ordinal{false};
};

struct ExportInfo {
    std::string name;
    std::uint64_t address{0};
    std::uint32_t ordinal{0};
    bool is_forwarded{false};
    std::string forward_name;
};

struct RelocationInfo {
    std::uint64_t address{0};
    std::uint32_t type{0};
    std::string type_name;
    std::string symbol_name;
};

struct FunctionHint {
    std::uint64_t start_va{0};
    std::uint64_t end_va{0}; // 0 if unknown (e.g. LC_FUNCTION_STARTS)
    std::string source;      // e.g. ".pdata", ".eh_frame", "LC_FUNCTION_STARTS"
};

struct BinaryInfo {
    BinaryFormat format{BinaryFormat::Unknown};
    Architecture architecture{Architecture::Unknown};
    Endianness endianness{Endianness::Unknown};
    TargetOS target_os{TargetOS::Unknown};
    BinaryType binary_type{BinaryType::Unknown};
    std::uint64_t image_base{0};
    std::uint64_t entry_point{0};
    std::uint64_t file_size{0};
    bool is_pie{false};
    bool has_nx{false};
    bool is_fat_binary{false};
    std::vector<Architecture> fat_architectures;
    std::vector<FunctionHint> function_hints;
    std::vector<std::string> warnings;
};

struct DetectedSignature {
    BinaryFormat format{BinaryFormat::Unknown};
    Architecture architecture{Architecture::Unknown};
    Endianness endianness{Endianness::Unknown};
    TargetOS target_os{TargetOS::Unknown};
};

} // namespace bytemorph::core::binary
