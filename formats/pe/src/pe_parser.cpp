#include "bytemorph/formats/pe/pe_parser.hpp"

#include <LIEF/PE.hpp>

#include <sstream>

namespace bytemorph::formats::pe {

namespace {

using namespace bytemorph::core;
using namespace bytemorph::core::binary;

class PeBinaryFile final : public IBinaryFile {
public:
    PeBinaryFile(std::vector<std::uint8_t> buffer,
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
            const auto sec_end = checked_add(sec.virtual_address, sec.raw_size);
            if (!sec_end) {
                continue;
            }
            if (va >= sec.virtual_address && va < *sec_end) {
                const auto delta = va - sec.virtual_address;
                const auto off = checked_add(sec.raw_offset, delta);
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
                diagnostics::ErrorCode::IntegerOverflow, "Virtual address + size overflow", "PeBinaryFile::read_virtual");
        }
        for (const auto& sec : sections_) {
            const auto sec_end = checked_add(sec.virtual_address, sec.raw_size);
            if (!sec_end) {
                continue;
            }
            if (va >= sec.virtual_address && *req_end <= *sec_end) {
                const auto delta = va - sec.virtual_address;
                const auto file_off = checked_add(sec.raw_offset, delta);
                if (!file_off) {
                    return diagnostics::Result<std::span<const std::uint8_t>>::err(
                        diagnostics::ErrorCode::IntegerOverflow, "File offset overflow", "PeBinaryFile::read_virtual");
                }
                const auto file_end = checked_add(*file_off, size);
                if (!file_end || *file_end > buffer_.size()) {
                    return diagnostics::Result<std::span<const std::uint8_t>>::err(
                        diagnostics::ErrorCode::OutOfBounds, "Section raw data exceeds file size", "PeBinaryFile::read_virtual");
                }
                return std::span<const std::uint8_t>(buffer_.data() + *file_off, size);
            }
        }
        return diagnostics::Result<std::span<const std::uint8_t>>::err(
            diagnostics::ErrorCode::OutOfBounds, "Virtual address range is not mapped in raw file", "PeBinaryFile::read_virtual");
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

[[nodiscard]] Architecture map_pe_arch(LIEF::PE::Header::MACHINE_TYPES m) noexcept {
    switch (m) {
        case LIEF::PE::Header::MACHINE_TYPES::I386: return Architecture::X86;
        case LIEF::PE::Header::MACHINE_TYPES::AMD64: return Architecture::X86_64;
        case LIEF::PE::Header::MACHINE_TYPES::ARM64: return Architecture::ARM64;
        default: return Architecture::Unknown;
    }
}

} // namespace

bool PeParser::supports(BinaryFormat format) const noexcept {
    return format == BinaryFormat::PE32 || format == BinaryFormat::PE32Plus;
}

diagnostics::Result<std::unique_ptr<IBinaryFile>>
PeParser::parse(std::vector<std::uint8_t> buffer) const {
    using diagnostics::ErrorCode;

    auto sig_res = BinaryLoader::detect_signature(buffer);
    if (!sig_res) {
        return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
            sig_res.error().code, sig_res.error().message, "PeParser::parse");
    }

    std::unique_ptr<LIEF::PE::Binary> pe;
    try {
        pe = LIEF::PE::Parser::parse(buffer);
    } catch (const std::exception& ex) {
        return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
            ErrorCode::ParseError, std::string("LIEF PE parse exception: ") + ex.what(), "PeParser::parse");
    }

    if (!pe) {
        return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
            ErrorCode::ParseError, "Failed to parse PE binary with LIEF", "PeParser::parse");
    }

    BinaryInfo info;
    info.format = (pe->type() == LIEF::PE::PE_TYPE::PE32_PLUS) ? BinaryFormat::PE32Plus : BinaryFormat::PE32;
    info.architecture = map_pe_arch(pe->header().machine());
    info.endianness = Endianness::Little;
    info.target_os = TargetOS::Windows;
    info.binary_type = pe->header().has_characteristic(LIEF::PE::Header::CHARACTERISTICS::DLL)
        ? BinaryType::SharedLibrary
        : BinaryType::Executable;

    const auto& opt = pe->optional_header();
    info.image_base = opt.imagebase();
    info.entry_point = info.image_base + opt.addressof_entrypoint();
    info.file_size = buffer.size();
    info.is_pie = opt.has(LIEF::PE::OptionalHeader::DLL_CHARACTERISTICS::DYNAMIC_BASE);
    info.has_nx = opt.has(LIEF::PE::OptionalHeader::DLL_CHARACTERISTICS::NX_COMPAT);

    if (info.format == BinaryFormat::PE32) {
        info.warnings.emplace_back("PE32 (32-bit) detected; v0.1 disassembly prioritizes PE32+ (x86-64).");
    }

    std::vector<SectionInfo> sections;
    sections.reserve(pe->sections().size());
    for (const auto& s : pe->sections()) {
        SectionInfo si;
        si.name = s.name();
        si.virtual_address = info.image_base + s.virtual_address();
        si.virtual_size = s.virtual_size();
        si.raw_offset = s.pointerto_raw_data();
        si.raw_size = s.sizeof_raw_data();
        si.characteristics = s.characteristics();
        si.readable = s.has_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_READ);
        si.writable = s.has_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_WRITE);
        si.executable = s.has_characteristic(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE);
        sections.push_back(std::move(si));
    }

    std::vector<ImportInfo> imports;
    for (const auto& imp : pe->imports()) {
        for (const auto& entry : imp.entries()) {
            ImportInfo ii;
            ii.library = imp.name();
            ii.symbol = entry.name();
            ii.address = info.image_base + entry.iat_address();
            ii.by_ordinal = entry.is_ordinal();
            if (entry.is_ordinal()) {
                ii.ordinal = entry.ordinal();
            }
            imports.push_back(std::move(ii));
        }
    }

    std::vector<ExportInfo> exports;
    std::vector<SymbolInfo> symbols;
    if (pe->has_exports()) {
        if (const auto* exp_dir = pe->get_export()) {
            for (const auto& entry : exp_dir->entries()) {
                ExportInfo ei;
                ei.name = entry.name();
                ei.address = info.image_base + entry.address();
                ei.ordinal = entry.ordinal();
                ei.is_forwarded = entry.is_forwarded();
                if (ei.is_forwarded) {
                    ei.forward_name = entry.forward_information().function;
                }
                exports.push_back(ei);

                SymbolInfo sym;
                sym.name = ei.name;
                sym.address = ei.address;
                sym.is_exported = true;
                sym.is_function = !ei.is_forwarded;
                symbols.push_back(std::move(sym));
            }
        }
    }

    std::vector<RelocationInfo> relocations;
    for (const auto& reloc : pe->relocations()) {
        for (const auto& entry : reloc.entries()) {
            RelocationInfo ri;
            ri.address = info.image_base + entry.address();
            ri.type = static_cast<std::uint32_t>(entry.type());
            ri.type_name = LIEF::PE::to_string(entry.type());
            relocations.push_back(std::move(ri));
        }
    }

    // Parse .pdata RUNTIME_FUNCTION entries (12 bytes each: BeginRVA, EndRVA, UnwindInfoRVA)
    for (const auto& sec : sections) {
        if (sec.name == ".pdata" && sec.raw_size >= 12 && sec.raw_offset < buffer.size()) {
            const std::size_t avail = (std::min)(static_cast<std::size_t>(sec.raw_size),
                                                 buffer.size() - static_cast<std::size_t>(sec.raw_offset));
            const std::size_t count = avail / 12;
            const std::uint8_t* pdata = buffer.data() + sec.raw_offset;
            for (std::size_t i = 0; i < count; ++i) {
                const std::size_t off = i * 12;
                const std::uint32_t begin_rva =
                    static_cast<std::uint32_t>(pdata[off]) |
                    (static_cast<std::uint32_t>(pdata[off + 1]) << 8) |
                    (static_cast<std::uint32_t>(pdata[off + 2]) << 16) |
                    (static_cast<std::uint32_t>(pdata[off + 3]) << 24);
                const std::uint32_t end_rva =
                    static_cast<std::uint32_t>(pdata[off + 4]) |
                    (static_cast<std::uint32_t>(pdata[off + 5]) << 8) |
                    (static_cast<std::uint32_t>(pdata[off + 6]) << 16) |
                    (static_cast<std::uint32_t>(pdata[off + 7]) << 24);

                if (begin_rva == 0 || end_rva <= begin_rva) {
                    continue;
                }
                const auto start_va = checked_add(info.image_base, begin_rva);
                const auto end_va = checked_add(info.image_base, end_rva);
                if (start_va && end_va) {
                    info.function_hints.push_back(FunctionHint{*start_va, *end_va, ".pdata"});
                }
            }
        }
    }

    return std::unique_ptr<IBinaryFile>(new PeBinaryFile(
        std::move(buffer),
        std::move(info),
        std::move(sections),
        {}, // PE uses sections rather than separate ELF-style program segments
        std::move(symbols),
        std::move(imports),
        std::move(exports),
        std::move(relocations)));
}

} // namespace bytemorph::formats::pe
