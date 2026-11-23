#include "bytemorph/prot/pe_rewriter.hpp"

#include "bytemorph/core/binary/loader.hpp"
#include "bytemorph/formats/elf/elf_parser.hpp"
#include "bytemorph/formats/macho/macho_parser.hpp"
#include "bytemorph/formats/pe/pe_parser.hpp"

namespace bytemorph::prot {

using namespace bytemorph::core::binary;

core::diagnostics::Result<ProtectionReport>
ProtectionEngine::protect(const std::filesystem::path& input,
                          const std::filesystem::path& output,
                          const ProtectOptions& options) {
    BinaryLoader loader;
    loader.register_parser(std::make_unique<formats::pe::PeParser>());
    loader.register_parser(std::make_unique<formats::elf::ElfParser>());
    loader.register_parser(std::make_unique<formats::macho::MachOParser>());

    auto bin_res = loader.load_file(input);
    if (!bin_res) {
        return core::diagnostics::Result<ProtectionReport>::err(
            bin_res.error().code, bin_res.error().message, "ProtectionEngine::protect");
    }

    const auto fmt = bin_res.value()->info().format;
    const auto arch = bin_res.value()->info().architecture;

    PeRewriter pe_rw;
    if (pe_rw.supports(fmt, arch)) {
        return pe_rw.protect_file(input, output, options);
    }

    ElfRewriter elf_rw;
    if (elf_rw.supports(fmt, arch)) {
        return elf_rw.protect_file(input, output, options);
    }

    MachORewriter macho_rw;
    if (macho_rw.supports(fmt, arch)) {
        return macho_rw.protect_file(input, output, options);
    }

    return core::diagnostics::Result<ProtectionReport>::err(
        core::diagnostics::ErrorCode::UnsupportedFormat,
        std::string("Unsupported format/architecture for protection: ") +
            std::string(to_string(fmt)) + " / " + std::string(to_string(arch)) +
            " (v0.4 supports PE32+ x86-64)",
        "ProtectionEngine::protect");
}

core::diagnostics::Result<VerifyReport>
ProtectionEngine::verify(const std::filesystem::path& path) {
    BinaryLoader loader;
    loader.register_parser(std::make_unique<formats::pe::PeParser>());
    loader.register_parser(std::make_unique<formats::elf::ElfParser>());
    loader.register_parser(std::make_unique<formats::macho::MachOParser>());

    auto bin_res = loader.load_file(path);
    if (!bin_res) {
        return core::diagnostics::Result<VerifyReport>::err(
            bin_res.error().code, bin_res.error().message, "ProtectionEngine::verify");
    }

    const auto fmt = bin_res.value()->info().format;
    const auto arch = bin_res.value()->info().architecture;

    PeRewriter pe_rw;
    if (pe_rw.supports(fmt, arch)) {
        return pe_rw.verify_file(path);
    }

    ElfRewriter elf_rw;
    if (elf_rw.supports(fmt, arch)) {
        return elf_rw.verify_file(path);
    }

    MachORewriter macho_rw;
    if (macho_rw.supports(fmt, arch)) {
        return macho_rw.verify_file(path);
    }

    return core::diagnostics::Result<VerifyReport>::err(
        core::diagnostics::ErrorCode::UnsupportedFormat,
        "Protection verification in v0.5 supports PE32+, ELF64, and Mach-O 64-bit",
        "ProtectionEngine::verify");
}

} // namespace bytemorph::prot
