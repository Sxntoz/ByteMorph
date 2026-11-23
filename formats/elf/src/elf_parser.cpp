#include "bytemorph/formats/elf/elf_parser.hpp"

#include <LIEF/ELF.hpp>

namespace bytemorph::formats::elf {

namespace {

using namespace bytemorph::core;
using namespace bytemorph::core::binary;

class ElfBinaryFile final : public IBinaryFile {
public:
    ElfBinaryFile(std::vector<std::uint8_t> buffer,
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
            if (sec.virtual_address == 0 || sec.raw_size == 0) continue;
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
                diagnostics::ErrorCode::IntegerOverflow, "Virtual address + size overflow", "ElfBinaryFile::read_virtual");
        }
        for (const auto& sec : sections_) {
            if (sec.virtual_address == 0 || sec.raw_size == 0) continue;
            const auto sec_end = checked_add(sec.virtual_address, sec.raw_size);
            if (!sec_end) continue;
            if (va >= sec.virtual_address && *req_end <= *sec_end) {
                const auto file_off = checked_add(sec.raw_offset, va - sec.virtual_address);
                if (!file_off) {
                    return diagnostics::Result<std::span<const std::uint8_t>>::err(
                        diagnostics::ErrorCode::IntegerOverflow, "File offset overflow", "ElfBinaryFile::read_virtual");
                }
                const auto file_end = checked_add(*file_off, size);
                if (!file_end || *file_end > buffer_.size()) {
                    return diagnostics::Result<std::span<const std::uint8_t>>::err(
                        diagnostics::ErrorCode::OutOfBounds, "Section raw data exceeds file size", "ElfBinaryFile::read_virtual");
                }
                return std::span<const std::uint8_t>(buffer_.data() + *file_off, size);
            }
        }
        return diagnostics::Result<std::span<const std::uint8_t>>::err(
            diagnostics::ErrorCode::OutOfBounds, "Virtual address range is not mapped in raw file", "ElfBinaryFile::read_virtual");
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

[[nodiscard]] Architecture map_elf_arch(LIEF::ELF::ARCH arch) noexcept {
    switch (arch) {
        case LIEF::ELF::ARCH::I386: return Architecture::X86;
        case LIEF::ELF::ARCH::X86_64: return Architecture::X86_64;
        case LIEF::ELF::ARCH::AARCH64: return Architecture::ARM64;
        default: return Architecture::Unknown;
    }
}

[[nodiscard]] BinaryType map_elf_type(LIEF::ELF::Header::FILE_TYPE ft, bool is_pie) noexcept {
    switch (ft) {
        case LIEF::ELF::Header::FILE_TYPE::EXEC: return BinaryType::Executable;
        case LIEF::ELF::Header::FILE_TYPE::DYN:
            return is_pie ? BinaryType::Executable : BinaryType::SharedLibrary;
        case LIEF::ELF::Header::FILE_TYPE::REL: return BinaryType::Object;
        case LIEF::ELF::Header::FILE_TYPE::CORE: return BinaryType::Core;
        default: return BinaryType::Unknown;
    }
}

} // namespace

bool ElfParser::supports(BinaryFormat format) const noexcept {
    return format == BinaryFormat::ELF32 || format == BinaryFormat::ELF64;
}

diagnostics::Result<std::unique_ptr<IBinaryFile>>
ElfParser::parse(std::vector<std::uint8_t> buffer) const {
    using diagnostics::ErrorCode;

    auto sig_res = BinaryLoader::detect_signature(buffer);
    if (!sig_res) {
        return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
            sig_res.error().code, sig_res.error().message, "ElfParser::parse");
    }

    std::unique_ptr<LIEF::ELF::Binary> elf;
    try {
        elf = LIEF::ELF::Parser::parse(buffer);
    } catch (const std::exception& ex) {
        return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
            ErrorCode::ParseError, std::string("LIEF ELF parse exception: ") + ex.what(), "ElfParser::parse");
    }

    if (!elf) {
        return diagnostics::Result<std::unique_ptr<IBinaryFile>>::err(
            ErrorCode::ParseError, "Failed to parse ELF binary with LIEF", "ElfParser::parse");
    }

    BinaryInfo info;
    info.format = (elf->type() == LIEF::ELF::Header::CLASS::ELF64) ? BinaryFormat::ELF64 : BinaryFormat::ELF32;
    info.architecture = map_elf_arch(elf->header().machine_type());
    info.endianness = (elf->header().identity_data() == LIEF::ELF::Header::ELF_DATA::MSB)
        ? Endianness::Big
        : Endianness::Little;
    info.target_os = TargetOS::Linux;
    info.is_pie = elf->is_pie();
    info.has_nx = elf->has_nx();
    info.binary_type = map_elf_type(elf->header().file_type(), info.is_pie);
    info.image_base = elf->imagebase();
    info.entry_point = elf->entrypoint();
    info.file_size = buffer.size();

    if (info.format == BinaryFormat::ELF32) {
        info.warnings.emplace_back("ELF32 detected; v0.1 disassembly prioritizes ELF64 (x86-64).");
    }

    std::vector<SectionInfo> sections;
    sections.reserve(elf->sections().size());
    for (const auto& s : elf->sections()) {
        SectionInfo si;
        si.name = s.name();
        si.virtual_address = s.virtual_address();
        si.virtual_size = s.size();
        si.raw_offset = s.file_offset();
        si.raw_size = (s.type() == LIEF::ELF::Section::TYPE::NOBITS) ? 0 : s.size();
        si.characteristics = s.flags();
        si.readable = s.has(LIEF::ELF::Section::FLAGS::ALLOC);
        si.writable = s.has(LIEF::ELF::Section::FLAGS::WRITE);
        si.executable = s.has(LIEF::ELF::Section::FLAGS::EXECINSTR);
        sections.push_back(std::move(si));
    }

    std::vector<SegmentInfo> segments;
    segments.reserve(elf->segments().size());
    for (const auto& seg : elf->segments()) {
        SegmentInfo sgi;
        sgi.name = LIEF::ELF::to_string(seg.type());
        sgi.virtual_address = seg.virtual_address();
        sgi.virtual_size = seg.virtual_size();
        sgi.file_offset = seg.file_offset();
        sgi.file_size = seg.physical_size();
        sgi.flags = static_cast<std::uint32_t>(seg.flags());
        sgi.readable = seg.has(LIEF::ELF::Segment::FLAGS::R);
        sgi.writable = seg.has(LIEF::ELF::Segment::FLAGS::W);
        sgi.executable = seg.has(LIEF::ELF::Segment::FLAGS::X);
        segments.push_back(std::move(sgi));
    }

    std::vector<SymbolInfo> symbols;
    std::vector<ImportInfo> imports;
    std::vector<ExportInfo> exports;
    for (const auto& sym : elf->symbols()) {
        SymbolInfo si;
        si.name = sym.name();
        si.address = sym.value();
        si.size = sym.size();
        si.is_function = (sym.type() == LIEF::ELF::Symbol::TYPE::FUNC);
        si.is_exported = sym.is_exported();
        si.is_imported = sym.is_imported();
        symbols.push_back(si);

        if (si.is_imported && !si.name.empty()) {
            ImportInfo ii;
            ii.symbol = si.name;
            ii.address = si.address;
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
    for (const auto& rel : elf->relocations()) {
        RelocationInfo ri;
        ri.address = rel.address();
        ri.type = static_cast<std::uint32_t>(rel.type());
        ri.type_name = LIEF::ELF::to_string(rel.type());
        if (rel.has_symbol() && rel.symbol() != nullptr) {
            ri.symbol_name = rel.symbol()->name();
        }
        relocations.push_back(std::move(ri));
    }

    // Parse .eh_frame_hdr (DWARF version 1 binary search table) for function start hints
    if (info.endianness == Endianness::Little) {
        for (const auto& sec : sections) {
            if (sec.name == ".eh_frame_hdr" && sec.raw_size >= 12 && sec.raw_offset < buffer.size()) {
                const std::size_t avail = (std::min)(static_cast<std::size_t>(sec.raw_size),
                                                     buffer.size() - static_cast<std::size_t>(sec.raw_offset));
                const std::uint8_t* hdr = buffer.data() + sec.raw_offset;
                if (avail >= 12 && hdr[0] == 1) {
                    const std::uint8_t eh_ptr_enc = hdr[1];
                    const std::uint8_t fde_cnt_enc = hdr[2];
                    const std::uint8_t table_enc = hdr[3];
                    // Common x86-64/ARM64 ELF encoding: eh_ptr=0x1B (pcrel|sdata4), fde_cnt=0x03 (udata4), table=0x3B (datarel|sdata4)
                    if ((eh_ptr_enc == 0x1B || eh_ptr_enc == 0x03) &&
                        (fde_cnt_enc == 0x03 || fde_cnt_enc == 0x0B) &&
                        table_enc == 0x3B) {
                        const std::uint32_t fde_count =
                            static_cast<std::uint32_t>(hdr[8]) |
                            (static_cast<std::uint32_t>(hdr[9]) << 8) |
                            (static_cast<std::uint32_t>(hdr[10]) << 16) |
                            (static_cast<std::uint32_t>(hdr[11]) << 24);
                        const std::size_t max_entries = (avail - 12) / 8;
                        const std::size_t count = (std::min)(static_cast<std::size_t>(fde_count), max_entries);
                        for (std::size_t i = 0; i < count; ++i) {
                            const std::size_t off = 12 + i * 8;
                            const std::int32_t rel_fn = static_cast<std::int32_t>(
                                static_cast<std::uint32_t>(hdr[off]) |
                                (static_cast<std::uint32_t>(hdr[off + 1]) << 8) |
                                (static_cast<std::uint32_t>(hdr[off + 2]) << 16) |
                                (static_cast<std::uint32_t>(hdr[off + 3]) << 24));
                            const std::int64_t fn_va = static_cast<std::int64_t>(sec.virtual_address) + rel_fn;
                            if (fn_va > 0) {
                                info.function_hints.push_back(FunctionHint{
                                    static_cast<std::uint64_t>(fn_va), 0, ".eh_frame_hdr"
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    return std::unique_ptr<IBinaryFile>(new ElfBinaryFile(
        std::move(buffer),
        std::move(info),
        std::move(sections),
        std::move(segments),
        std::move(symbols),
        std::move(imports),
        std::move(exports),
        std::move(relocations)));
}

} // namespace bytemorph::formats::elf
