#include "bytemorph/prot/pe_rewriter.hpp"

#include "bytemorph/arch/aarch64/aarch64_disasm.hpp"
#include "bytemorph/arch/aarch64/aarch64_lifter.hpp"
#include "bytemorph/arch/x86_64/x86_64_disasm.hpp"
#include "bytemorph/arch/x86_64/x86_64_lifter.hpp"
#include "bytemorph/core/analysis/analyzer.hpp"
#include "bytemorph/core/binary/loader.hpp"
#include "bytemorph/formats/elf/elf_parser.hpp"
#include "bytemorph/formats/macho/macho_parser.hpp"
#include "bytemorph/formats/pe/pe_parser.hpp"
#include "bytemorph/virt/ir_to_vm.hpp"

#include <unordered_set>

namespace bytemorph::prot {

using namespace bytemorph::core;
using namespace bytemorph::core::binary;
using namespace bytemorph::core::analysis;
using namespace bytemorph::core::ir;
using namespace bytemorph::virt;

namespace {

bool is_crt_or_entrypoint_stub(const std::string& name, bool is_entry_point) noexcept {
    if (is_entry_point) return true;
    static const std::unordered_set<std::string> kSkipNames = {
        "_start", "start", "_init", "_fini", "main", "_main",
        "__libc_csu_init", "__libc_csu_fini", "__do_global_dtors_aux",
        "frame_dummy", "register_tm_clones", "deregister_tm_clones",
        "_dl_relocate_static_pie", "__scrt_common_main_seh", "mainCRTStartup"
    };
    return kSkipNames.contains(name);
}

} // namespace

core::diagnostics::Result<CompatibilityReport>
ProtectionEngine::check_compatibility(const std::filesystem::path& path,
                                      bool allow_external_calls) {
    using diagnostics::ErrorCode;

    BinaryLoader loader;
    loader.register_parser(std::make_unique<formats::pe::PeParser>());
    loader.register_parser(std::make_unique<formats::elf::ElfParser>());
    loader.register_parser(std::make_unique<formats::macho::MachOParser>());

    auto bin_res = loader.load_file(path);
    if (!bin_res) {
        return diagnostics::Result<CompatibilityReport>::err(
            bin_res.error().code, bin_res.error().message, "ProtectionEngine::check_compatibility");
    }

    const auto& bin = *bin_res.value();
    const auto fmt = bin.info().format;
    const auto arch = bin.info().architecture;

    CompatibilityReport rep;
    rep.format = fmt;
    rep.architecture = arch;

    PeRewriter pe_rw;
    ElfRewriter elf_rw;
    MachORewriter macho_rw;
    rep.binary_supported = pe_rw.supports(fmt, arch) || elf_rw.supports(fmt, arch) || macho_rw.supports(fmt, arch);

    if (fmt == BinaryFormat::PE32Plus) {
        rep.os_requirements.push_back("Windows x64 (PE32+ loader, ASLR/DEP/CFG preserved)");
    } else if (fmt == BinaryFormat::ELF64) {
        rep.os_requirements.push_back(arch == Architecture::ARM64
            ? "Linux ARM64 / AArch64 (ELF64 PT_LOAD W^X, AAPCS64, PIE/ASLR)"
            : "Linux x86-64 (ELF64 PT_LOAD W^X, System V AMD64 ABI, PIE/ASLR/CET)");
    } else if (fmt == BinaryFormat::MachO64) {
        rep.os_requirements.push_back("macOS 64-bit (__BMRT/__BMVM W^X segments, /usr/bin/codesign ad-hoc signing)");
    }

    rep.known_limitations = {
        "Functions with inline syscalls or privileged/SIMD instructions are rejected",
        "Indirect calls and jump tables require explicit authorized targets",
        "Hardware exceptions / SEH / C++ unwinding across VM boundaries are not virtualized"
    };

    if (!rep.binary_supported) {
        return rep;
    }

    const bool is_arm64 = (arch == Architecture::ARM64);
    const std::size_t min_patch = is_arm64 ? 4 : 5;

    arch::x86_64::X86_64Disassembler x64_dis;
    arch::aarch64::AArch64Disassembler a64_dis;
    IDisassemblerEngine& disasm = is_arm64 ? static_cast<IDisassemblerEngine&>(a64_dis)
                                           : static_cast<IDisassemblerEngine&>(x64_dis);

    BinaryAnalyzer analyzer;
    auto an_res = analyzer.analyze(bin, disasm);
    if (!an_res) {
        return diagnostics::Result<CompatibilityReport>::err(
            an_res.error().code, an_res.error().message, "ProtectionEngine::check_compatibility");
    }

    arch::x86_64::X86_64Lifter x64_lifter;
    arch::aarch64::AArch64Lifter a64_lifter;

    for (const auto& fn : an_res.value().functions) {
        FunctionCompatibilityEntry entry;
        entry.name = fn.name;
        entry.entry_va = fn.entry_va;
        entry.size_bytes = fn.size_bytes;

        if (is_crt_or_entrypoint_stub(fn.name, fn.from_entry_point)) {
            entry.eligible = false;
            entry.rejection_reason = "Entry point or CRT/startup routine excluded from automatic virtualization";
            rep.rejected_functions.push_back(std::move(entry));
            continue;
        }
        if (fn.size_bytes < min_patch) {
            entry.eligible = false;
            entry.rejection_reason = "Function smaller than minimum trampoline patch size (" + std::to_string(min_patch) + " bytes)";
            rep.rejected_functions.push_back(std::move(entry));
            continue;
        }
        if (fn.confidence == AnalysisConfidence::Low) {
            entry.eligible = false;
            entry.rejection_reason = "Partially unknown CFG or invalid instructions in function body";
            rep.rejected_functions.push_back(std::move(entry));
            continue;
        }

        IrFunction ir_fn = is_arm64 ? a64_lifter.lift_function(fn) : x64_lifter.lift_function(fn);
        for (const auto& bb : ir_fn.blocks) {
            entry.ir_ops += static_cast<std::uint32_t>(bb.instructions.size());
            for (const auto& insn : bb.instructions) {
                if (insn.opcode == IrOpcode::Unknown || insn.opcode == IrOpcode::Syscall) {
                    entry.unsupported_instructions.push_back(
                        insn.comment.empty() ? std::string(ir::to_string(insn.opcode)) : insn.comment);
                }
            }
        }

        if (!entry.unsupported_instructions.empty()) {
            entry.eligible = false;
            entry.rejection_reason = "Contains unsupported instruction(s): " + entry.unsupported_instructions.front();
            rep.rejected_functions.push_back(std::move(entry));
            continue;
        }

        TranslateOptions t_opts;
        t_opts.allow_external_calls = allow_external_calls;
        auto bvm_res = IrToVmTranslator::translate(ir_fn, t_opts);
        if (!bvm_res) {
            entry.eligible = false;
            entry.rejection_reason = bvm_res.error().message;
            rep.rejected_functions.push_back(std::move(entry));
            continue;
        }

        entry.eligible = true;
        entry.vm_ops = static_cast<std::uint32_t>(bvm_res.value().instructions.size());
        rep.eligible_functions.push_back(std::move(entry));
    }

    return rep;
}

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

    ProtectOptions effective_opts = options;
    if (effective_opts.auto_select_functions &&
        !effective_opts.protect_all_eligible &&
        effective_opts.target_function_rvas.empty() &&
        effective_opts.target_function_names.empty() &&
        effective_opts.target_function_name.empty() &&
        !effective_opts.target_function_rva.has_value()) {
        auto comp_res = check_compatibility(input, effective_opts.allow_external_calls);
        if (!comp_res) {
            return core::diagnostics::Result<ProtectionReport>::err(
                comp_res.error().code, comp_res.error().message, "ProtectionEngine::protect");
        }
        if (comp_res.value().eligible_functions.empty()) {
            return core::diagnostics::Result<ProtectionReport>::err(
                core::diagnostics::ErrorCode::UnsupportedFormat,
                "No eligible functions found for automatic virtualization (--functions auto)",
                "ProtectionEngine::protect");
        }
        // Prefer named/exported non-sub_ function if available
        const auto* chosen = &comp_res.value().eligible_functions.front();
        for (const auto& ef : comp_res.value().eligible_functions) {
            if (!ef.name.empty() && ef.name.rfind("sub_", 0) != 0) {
                chosen = &ef;
                break;
            }
        }
        effective_opts.target_function_rva = chosen->entry_va - bin_res.value()->info().image_base;
        effective_opts.target_function_name = chosen->name;
    }

    PeRewriter pe_rw;
    if (pe_rw.supports(fmt, arch)) {
        return pe_rw.protect_file(input, output, effective_opts);
    }

    ElfRewriter elf_rw;
    if (elf_rw.supports(fmt, arch)) {
        return elf_rw.protect_file(input, output, effective_opts);
    }

    MachORewriter macho_rw;
    if (macho_rw.supports(fmt, arch)) {
        return macho_rw.protect_file(input, output, effective_opts);
    }

    return core::diagnostics::Result<ProtectionReport>::err(
        core::diagnostics::ErrorCode::UnsupportedFormat,
        std::string("Unsupported format/architecture for protection: ") +
            std::string(to_string(fmt)) + " / " + std::string(to_string(arch)) +
            " (v0.7 supports PE32+ x86-64/ARM64, ELF64 x86-64/ARM64, and Mach-O 64-bit/Universal x86-64/ARM64)",
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
