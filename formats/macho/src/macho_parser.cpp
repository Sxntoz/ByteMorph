#include "bytemorph/formats/macho/macho_parser.hpp"

#include <LIEF/MachO.hpp>

namespace bytemorph::formats::macho {

namespace {

using namespace bytemorph::core;
using namespace bytemorph::core::binary;

class MachOBinaryFile final : public IBinaryFile {
public:
    MachOBinaryFile(std::vector<std::uint8_t> buffer,
                    BinaryInfo info,
                    std::vector<SectionInfo> sections,
                    std::vector<SegmentInfo> segments,
                    std::vector<SymbolInfo> symbols,
                    std::vector<ImportInfo> imports,
                    std::vector<ExportInfo> exports,
                    std::vector<RelocationInfo> relocations)
        : buffer_(std::move(buffer)),
          info_(std::move(info)),
          sections_(std::move(sections)),
          segments_(std::move(segments)),
          symbols_(std::move(symbols)),
          imports_(std::move(imports)),
          exports_(std::move(exports)),
          relocations_(std::move(relocations)) {}

    [[nodiscard]] const BinaryInfo& info() const noexcept override { return info_; }
    [[nodiscard]] const std::vector<SectionInfo>& sections() const noexcept override { return sections_; }
    [[nodiscard]] const std::vector<SegmentInfo>& segments() const noexcept override { return segments_; }
    [[nodiscard]] const std::vector<SymbolInfo>& symbols() const noexcept override { return symbols_; }
    [[nodiscard]] const std::vector<ImportInfo>& imports() const noexcept override { return imports_; }
    [[nodiscard]] const std::vector<ExportInfo>& exports() const noexcept override { return exports_; }
    [[nodiscard]] const std::vector<RelocationInfo>& relocations() const noexcept override { return relocations_; }
    [[nodiscard]] std::span<const std::uint8_t> raw_bytes() const noexcept override { return buffer_; }

    [[nodiscard]] std::optional<std::uint64_t> va_to_offset(std::uint64_t va) const noexcept override {
        for (const auto& sec : sections_) {
            if (sec.raw_size == 0) continue;
            const auto sec_end = checked_add(sec.virtual_address, sec.raw_size);
            if (!sec_end) continue;
            if (va >= sec.virtual_address && va < *sec_end) {
                const auto off = checked_add(sec.raw_offset, va - sec.virtual_address);
                if (off && *off < buffer_.size()) {
                    return off;
                }
            }
        }
        for (const auto& seg : segments_) {
            if (seg.file_size == 0) continue;
            const auto seg_end = checked_add(seg.virtual_address, seg.file_size);
            if (!seg_end) continue;
            if (va >= seg.virtual_address && va < *seg_end) {
                const auto off = checked_add(seg.file_offset, va - seg.virtual_address);
                if (off && *off < buffer_.size()) {
                    return off;
                }
            }
        }
        return std::nullopt;
    }

    [[nodiscard]] diagnostics::Result<std::span<const std::uint8_t>>
    read_virtual(std::uint64_t va, std::size_t size) const override {
        if (size == 0) {
            return std::span<const std::uint8_t>{};
        }
        const auto req_end = checked_add(va, size);
        if (!req_end) {
            return diagnostics::Result<std::span<const std::uint8_t>>::err(
                diagnostics::ErrorCode::IntegerOverflow, "Virtual address + size overflow", "MachOBinaryFile::read_virtual");
        }
        for (const auto& sec : sections_) {
            if (sec.raw_size == 0) continue;
            const auto sec_end = checked_add(sec.virtual_address, sec.raw_size);
            if (!sec_end) continue;
            if (va >= sec.virtual_address && *req_end <= *sec_end) {
                const auto file_off = checked_add(sec.raw_offset, va - sec.virtual_address);
                if (!file_off) {
                    return diagnostics::Result<std::span<const std::uint8_t>>::err(
                        diagnostics::ErrorCode::IntegerOverflow, "File offset overflow", "MachOBinaryFile::read_virtual");
                }
                const auto file_end = checked_add(*file_off, size);
                if (!file_end || *file_end > buffer_.size()) {
                    return diagnostics::Result<std::span<const std::uint8_t>>::err(
                        diagnostics::ErrorCode::OutOfBounds, "Section raw data exceeds file size", "MachOBinaryFile::read_virtual");
                }
                return std::span<const std::uint8_t>(buffer_.data() + *file_off, size);
            }
        }
        return diagnostics::Result<std::span<const std::uint8_t>>::err(
            diagnostics::ErrorCode::OutOfBounds, "Virtual address range is not mapped in raw file", "MachOBinaryFile::read_virtual");
    }

private:
    std::vector<std::uint8_t> buffer_;
    BinaryInfo info_;
    std::vector<SectionInfo> sections_;
    std::vector<SegmentInfo> segments_;
    std::vector<SymbolInfo> symbols_;
    std::vector<ImportInfo> imports_;
    std::vector<ExportInfo> exports_;
    std::vector<RelocationInfo> relocations_;
};

[[nodiscard]] Architecture map_macho_arch(LIEF::MachO::Header::CPU_TYPE cpu) noexcept {
    switch (cpu) {
        case LIEF::MachO::Header::CPU_TYPE::X86: return Architecture::X86;
        case LIEF::MachO::Header::CPU_TYPE::X86_64: return Architecture::X86_64;
        case LIEF::MachO::Header::CPU_TYPE::ARM64: return Architecture::ARM64;
        default: return Architecture::Unknown;
    }
}

[[nodiscard]] BinaryType map_macho_type(LIEF::MachO::Header::FILE_TYPE ft) noexcept {
    switch (ft) {
        case LIEF::MachO::Header::FILE_TYPE::EXECUTE: return BinaryType::Executable;
        case LIEF::MachO::Header::FILE_TYPE::DYLIB:
        case LIEF::MachO::Header::FILE_TYPE::BUNDLE:
        case LIEF::MachO::Header::FILE_TYPE::FVMLIB:
            return BinaryType::SharedLibrary;
        case LIEF::MachO::Header::FILE_TYPE::OBJECT: return BinaryType::Object;
        case LIEF::MachO::Header::FILE_TYPE::CORE: return BinaryType::Core;
        default: return BinaryType::Unknown;
    }
}

} // namespace

bool MachOParser::supports(BinaryFormat format) const noexcept {
    return format == BinaryFormat::MachO32 ||
           format == BinaryFormat::MachO64 ||
           format == BinaryFormat::MachOFat;
}

diagnostics::Result<std::unique_ptr<IBinaryFile>>
MachOParser::parse(std::vector<std::uint8_t> buffer) const {
    using diagnostics::ErrorCode;

    auto sig_res = BinaryLoader::detect_signature(buffer);
    if (!sig_res) {
        return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
            sig_res.error().code, sig_res.error().message, "MachOParser::parse");
    }

    std::unique_ptr<LIEF::MachO::FatBinary> fat;
    try {
        fat = LIEF::MachO::Parser::parse(buffer);
    } catch (const std::exception& ex) {
        return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
            ErrorCode::ParseError, std::string("LIEF Mach-O parse exception: ") + ex.what(), "MachOParser::parse");
    }

    if (!fat || fat->empty()) {
        return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
            ErrorCode::ParseError, "Failed to parse Mach-O binary with LIEF", "MachOParser::parse");
    }

    std::vector<Architecture> fat_archs;
    const LIEF::MachO::Binary* selected = nullptr;

    auto is_header_64 = [](const LIEF::MachO::Header& h) noexcept -> bool {
        const auto m = static_cast<std::uint32_t>(h.magic());
        return m == 0xFEEDFACFu || m == 0xCFFAEDFEu;
    };

    for (const auto& slice : *fat) {
        const auto arch = map_macho_arch(slice.header().cpu_type());
        fat_archs.push_back(arch);
        if (!selected) {
            selected = &slice;
        } else if (is_header_64(slice.header()) && (arch == Architecture::ARM64 || arch == Architecture::X86_64)) {
            if (!is_header_64(selected->header())) {
                selected = &slice;
            }
        }
    }

    if (!selected) {
        return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
            ErrorCode::ParseError, "No valid Mach-O slice found", "MachOParser::parse");
    }

    const auto& macho = *selected;
    const std::uint64_t slice_offset = macho.fat_offset();

    BinaryInfo info;
    info.format = is_header_64(macho.header()) ? BinaryFormat::MachO64 : BinaryFormat::MachO32;
    info.architecture = map_macho_arch(macho.header().cpu_type());
    info.endianness = Endianness::Little;
    info.target_os = TargetOS::MacOS;
    info.binary_type = map_macho_type(macho.header().file_type());
    info.image_base = macho.imagebase();
    info.entry_point = macho.entrypoint();
    info.file_size = buffer.size();
    info.is_pie = macho.is_pie();
    info.has_nx = macho.has_nx();
    info.is_fat_binary = (fat->size() > 1);
    info.fat_architectures = std::move(fat_archs);

    if (info.is_fat_binary) {
        info.warnings.emplace_back(
            "Fat/Universal Mach-O detected (" + std::to_string(fat->size()) +
            " slices); selected primary slice: " + std::string(to_string(info.architecture)) + ".");
    }
    if (info.format == BinaryFormat::MachO32) {
        info.warnings.emplace_back("Mach-O 32-bit detected; v0.2 prioritizes 64-bit Mach-O.");
    }

    std::vector<SegmentInfo> segments;
    segments.reserve(macho.segments().size());
    for (const auto& seg : macho.segments()) {
        SegmentInfo sgi;
        sgi.name = seg.name();
        sgi.virtual_address = seg.virtual_address();
        sgi.virtual_size = seg.virtual_size();
        sgi.file_offset = slice_offset + seg.file_offset();
        sgi.file_size = seg.file_size();
        sgi.flags = seg.init_protection();
        const auto prot = seg.init_protection();
        sgi.readable = (prot & 1u) != 0;
        sgi.writable = (prot & 2u) != 0;
        sgi.executable = (prot & 4u) != 0;
        segments.push_back(std::move(sgi));
    }

    std::vector<SectionInfo> sections;
    sections.reserve(macho.sections().size());
    for (const auto& s : macho.sections()) {
        SectionInfo si;
        si.name = s.segment_name() + "," + s.name();
        si.virtual_address = s.virtual_address();
        si.virtual_size = s.size();
        si.raw_offset = slice_offset + s.offset();
        si.raw_size = (s.type() == LIEF::MachO::Section::TYPE::ZEROFILL ||
                       s.type() == LIEF::MachO::Section::TYPE::GB_ZEROFILL)
            ? 0
            : s.size();
        si.characteristics = static_cast<std::uint64_t>(s.flags());
        const bool is_instr = s.has(LIEF::MachO::Section::FLAGS::PURE_INSTRUCTIONS) ||
                              s.has(LIEF::MachO::Section::FLAGS::SOME_INSTRUCTIONS);
        si.readable = true;
        si.executable = is_instr;
        if (s.has_segment()) {
            const auto seg_prot = s.segment()->init_protection();
            si.readable = (seg_prot & 1u) != 0;
            si.writable = (seg_prot & 2u) != 0;
            si.executable = si.executable || ((seg_prot & 4u) != 0 && s.name() == "__text");
        }
        sections.push_back(std::move(si));
    }

    std::vector<SymbolInfo> symbols;
    std::vector<ImportInfo> imports;
    std::vector<ExportInfo> exports;
    for (const auto& sym : macho.symbols()) {
        SymbolInfo si;
        si.name = sym.name();
        si.address = sym.value();
        si.is_exported = sym.has_export_info();
        si.is_imported = sym.has_binding_info() ||
                         sym.category() == LIEF::MachO::Symbol::CATEGORY::UNDEFINED;
        si.is_function = (sym.value() != 0 && !si.is_imported);
        symbols.push_back(si);

        if (si.is_imported && !si.name.empty()) {
            ImportInfo ii;
            ii.symbol = si.name;
            ii.address = si.address;
            if (sym.has_binding_info() && sym.binding_info() != nullptr && sym.binding_info()->has_library()) {
                ii.library = sym.binding_info()->library()->name();
            }
            imports.push_back(std::move(ii));
        }
        if (si.is_exported && !si.name.empty() && si.address != 0) {
            ExportInfo ei;
            ei.name = si.name;
            ei.address = si.address;
            exports.push_back(std::move(ei));
        }
    }

    std::vector<RelocationInfo> relocations;
    for (const auto& rel : macho.relocations()) {
        RelocationInfo ri;
        ri.address = rel.address();
        ri.type = rel.type();
        ri.type_name = LIEF::MachO::to_string(static_cast<LIEF::MachO::X86_64_RELOCATION>(rel.type()));
        if (rel.has_symbol() && rel.symbol() != nullptr) {
            ri.symbol_name = rel.symbol()->name();
        }
        relocations.push_back(std::move(ri));
    }

    // LC_FUNCTION_STARTS metadata
    if (macho.has_function_starts()) {
        if (const auto* fstarts = macho.function_starts()) {
            for (const auto rel_addr : fstarts->functions()) {
                const auto va = checked_add(info.image_base, rel_addr);
                if (va) {
                    info.function_hints.push_back(FunctionHint{
                        *va, 0, "LC_FUNCTION_STARTS"
                    });
                }
            }
        }
    }

    return std::unique_ptr<IBinaryFile>(new MachOBinaryFile(
        std::move(buffer),
        std::move(info),
        std::move(sections),
        std::move(segments),
        std::move(symbols),
        std::move(imports),
        std::move(exports),
        std::move(relocations)));
}

} // namespace bytemorph::formats::macho
