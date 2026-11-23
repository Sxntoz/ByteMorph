#include "bytemorph/prot/pe_rewriter.hpp"

#include "bytemorph/arch/aarch64/aarch64_disasm.hpp"
#include "bytemorph/arch/aarch64/aarch64_lifter.hpp"
#include "bytemorph/arch/x86_64/x86_64_disasm.hpp"
#include "bytemorph/arch/x86_64/x86_64_lifter.hpp"
#include "bytemorph/core/analysis/analyzer.hpp"
#include "bytemorph/core/binary/loader.hpp"
#include "bytemorph/formats/macho/macho_parser.hpp"
#include "bytemorph/obf/obfuscation_engine.hpp"
#include "bytemorph/prot/native_vm_emitter.hpp"
#include "bytemorph/virt/bvm_format.hpp"
#include "bytemorph/virt/ir_to_vm.hpp"

#include <LIEF/MachO.hpp>

#include <cstdlib>
#include <cstring>
#include <filesystem>

namespace bytemorph::prot {

using namespace bytemorph::core;
using namespace bytemorph::core::binary;
using namespace bytemorph::core::analysis;
using namespace bytemorph::core::ir;
using namespace bytemorph::obf;
using namespace bytemorph::virt;
using namespace bytemorph::prot::detail;

bool MachORewriter::supports(BinaryFormat fmt, Architecture arch) const noexcept {
    return fmt == BinaryFormat::MachO64 && (arch == Architecture::X86_64 || arch == Architecture::ARM64);
}

diagnostics::Result<ProtectionReport>
MachORewriter::protect_file(const std::filesystem::path& input,
                            const std::filesystem::path& output,
                            const ProtectOptions& options) const {
    using diagnostics::ErrorCode;

    BinaryLoader loader;
    loader.register_parser(std::make_unique<formats::macho::MachOParser>());
    auto bin_res = loader.load_file(input);
    if (!bin_res) {
        return diagnostics::Result<ProtectionReport>::err(
            bin_res.error().code, bin_res.error().message, "MachORewriter::protect_file");
    }

    const auto& bin = *bin_res.value();
    if (bin.info().is_fat_binary) {
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::UnsupportedFormat,
            "Fat/Universal Mach-O rewriting requires a single-architecture Mach-O 64-bit slice (use lipo -thin first)",
            "MachORewriter::protect_file");
    }
    if (!supports(bin.info().format, bin.info().architecture)) {
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::UnsupportedFormat, "MachORewriter supports Mach-O 64-bit (x86-64 / ARM64)", "MachORewriter::protect_file");
    }

    std::unique_ptr<LIEF::MachO::FatBinary> fat;
    try {
        fat = LIEF::MachO::Parser::parse(input.string());
    } catch (const std::exception& ex) {
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::ParseError, std::string("LIEF Mach-O parse failed: ") + ex.what(), "MachORewriter::protect_file");
    }
    if (!fat || fat->empty()) {
        return diagnostics::Result<ProtectionReport>::err(ErrorCode::ParseError, "Invalid Mach-O binary", "MachORewriter::protect_file");
    }

    LIEF::MachO::Binary* macho = fat->at(0);
    if (!macho) {
        return diagnostics::Result<ProtectionReport>::err(ErrorCode::ParseError, "Missing Mach-O slice", "MachORewriter::protect_file");
    }

    if (macho->has_code_signature()) {
        if (!options.allow_strip_signature) {
            return diagnostics::Result<ProtectionReport>::err(
                ErrorCode::ParseError,
                "Input Mach-O has an existing code signature; refusing to silently invalidate it (pass --allow-signed-strip)",
                "MachORewriter::protect_file");
        }
        macho->remove_signature();
    }

    std::uint64_t target_va = 0;
    std::string target_name;
    if (options.target_function_rva.has_value()) {
        target_va = bin.info().image_base + *options.target_function_rva;
        target_name = options.target_function_name.empty() ? "target_fn" : options.target_function_name;
    } else if (!options.target_function_name.empty()) {
        for (const auto& sym : bin.symbols()) {
            if ((sym.name == options.target_function_name || sym.name == ("_" + options.target_function_name)) &&
                sym.address != 0 && !sym.is_imported) {
                target_va = sym.address;
                target_name = sym.name;
                break;
            }
        }
        if (target_va == 0) {
            return diagnostics::Result<ProtectionReport>::err(
                ErrorCode::FileNotFound, "Target Mach-O symbol not found: " + options.target_function_name, "MachORewriter::protect_file");
        }
    } else {
        for (const auto& sym : bin.symbols()) {
            if (sym.is_function && sym.is_exported && sym.address != 0) {
                target_va = sym.address;
                target_name = sym.name;
                break;
            }
        }
        if (target_va == 0) {
            return diagnostics::Result<ProtectionReport>::err(
                ErrorCode::UnsupportedFormat, "No exported Mach-O function found; specify --func or --func-rva", "MachORewriter::protect_file");
        }
    }

    const bool is_arm64 = (bin.info().architecture == Architecture::ARM64);
    std::unique_ptr<IDisassemblerEngine> disasm = is_arm64
        ? std::unique_ptr<IDisassemblerEngine>(std::make_unique<arch::aarch64::AArch64Disassembler>())
        : std::unique_ptr<IDisassemblerEngine>(std::make_unique<arch::x86_64::X86_64Disassembler>());

    BinaryAnalyzer analyzer;
    auto an_res = analyzer.analyze(bin, *disasm);
    if (!an_res) {
        return diagnostics::Result<ProtectionReport>::err(an_res.error().code, an_res.error().message, "MachORewriter::protect_file");
    }

    const FunctionInfo* target_fn = nullptr;
    for (const auto& fn : an_res.value().functions) {
        if (fn.entry_va == target_va) {
            target_fn = &fn;
            break;
        }
    }

    FunctionInfo adhoc_fn;
    if (!target_fn) {
        auto slice = bin.read_virtual(target_va, 256);
        if (!slice) {
            return diagnostics::Result<ProtectionReport>::err(slice.error().code, slice.error().message, "MachORewriter::protect_file");
        }
        auto dis = disasm->disassemble(slice.value(), target_va, 64);
        if (!dis || dis.value().empty()) {
            return diagnostics::Result<ProtectionReport>::err(ErrorCode::DisassemblyError, "Failed to disassemble Mach-O function", "MachORewriter::protect_file");
        }
        adhoc_fn.name = target_name;
        adhoc_fn.entry_va = target_va;
        BasicBlock bb;
        bb.start_va = target_va;
        for (const auto& i : dis.value()) {
            bb.instructions.push_back(i);
            bb.end_va = i.address + i.bytes.size();
            adhoc_fn.size_bytes += i.bytes.size();
            if (i.flow == ControlFlowKind::Return) break;
        }
        adhoc_fn.blocks.push_back(std::move(bb));
        target_fn = &adhoc_fn;
    }

    const std::size_t min_patch = is_arm64 ? 4 : 5;
    if (target_fn->size_bytes < min_patch) {
        return diagnostics::Result<ProtectionReport>::err(ErrorCode::OutOfBounds, "Target Mach-O function too small for trampoline", "MachORewriter::protect_file");
    }

    IrFunction ir_fn = is_arm64
        ? arch::aarch64::AArch64Lifter().lift_function(*target_fn)
        : arch::x86_64::X86_64Lifter().lift_function(*target_fn);

    std::uint32_t orig_ops = 0;
    for (const auto& bb : ir_fn.blocks) orig_ops += static_cast<std::uint32_t>(bb.instructions.size());

    ObfuscationConfig obf_cfg;
    obf_cfg.seed = options.seed;
    obf_cfg.enable_substitution = true;
    obf_cfg.enable_mba = (options.profile != ProtectionProfile::Fast);
    obf_cfg.enable_cfg = (options.profile == ProtectionProfile::Maximum);

    auto obf_res = ObfuscationPipeline::obfuscate_function(ir_fn, obf_cfg);
    if (!obf_res) {
        return diagnostics::Result<ProtectionReport>::err(obf_res.error().code, obf_res.error().message, "MachORewriter::protect_file");
    }

    auto bvm_res = IrToVmTranslator::translate(ir_fn, options.seed);
    if (!bvm_res) {
        return diagnostics::Result<ProtectionReport>::err(
            bvm_res.error().code, "Mach-O function not eligible for virtualization: " + bvm_res.error().message, "MachORewriter::protect_file");
    }

    auto rt_res = is_arm64
        ? emit_pic_arm64_vm_runtime(bvm_res.value())
        : emit_pic_x64_vm_runtime(bvm_res.value(), AbiKind::SysV_AMD64);
    if (!rt_res) {
        return diagnostics::Result<ProtectionReport>::err(rt_res.error().code, rt_res.error().message, "MachORewriter::protect_file");
    }
    const auto& runtime_bytes = rt_res.value();

    // Add __BMRT segment (R-X, W^X compliant)
    LIEF::MachO::SegmentCommand bmrt_seg("__BMRT");
    bmrt_seg.init_protection(1 | 4); // VM_PROT_READ | VM_PROT_EXECUTE
    bmrt_seg.max_protection(1 | 4);
    LIEF::MachO::Section bmrt_sec("__bmrt", runtime_bytes);
    bmrt_sec.segment_name("__BMRT");
    bmrt_sec.type(LIEF::MachO::Section::TYPE::REGULAR);
    bmrt_sec.flags(static_cast<std::uint32_t>(LIEF::MachO::Section::FLAGS::PURE_INSTRUCTIONS) |
                   static_cast<std::uint32_t>(LIEF::MachO::Section::FLAGS::SOME_INSTRUCTIONS));
    bmrt_seg.add_section(bmrt_sec);

    auto* added_bmrt_cmd = macho->add(bmrt_seg);
    if (!added_bmrt_cmd) {
        return diagnostics::Result<ProtectionReport>::err(ErrorCode::InternalError, "Failed to add __BMRT Mach-O segment", "MachORewriter::protect_file");
    }
    const auto* added_bmrt_seg = dynamic_cast<const LIEF::MachO::SegmentCommand*>(added_bmrt_cmd);
    if (!added_bmrt_seg) {
        return diagnostics::Result<ProtectionReport>::err(ErrorCode::InternalError, "Added __BMRT command is not a SegmentCommand", "MachORewriter::protect_file");
    }
    const std::uint64_t stub_va = added_bmrt_seg->virtual_address();

    // Patch __TEXT,__text
    LIEF::MachO::Section* text_sec = macho->get_section("__TEXT", "__text");
    if (!text_sec) {
        return diagnostics::Result<ProtectionReport>::err(ErrorCode::ParseError, "Mach-O missing __TEXT,__text", "MachORewriter::protect_file");
    }
    if (target_va < text_sec->virtual_address() ||
        target_va + min_patch > text_sec->virtual_address() + text_sec->content().size()) {
        return diagnostics::Result<ProtectionReport>::err(ErrorCode::OutOfBounds, "Target VA outside __text", "MachORewriter::protect_file");
    }

    auto text_content = std::vector<std::uint8_t>(text_sec->content().begin(), text_sec->content().end());
    const std::size_t patch_off = static_cast<std::size_t>(target_va - text_sec->virtual_address());

    if (is_arm64) {
        const std::int64_t delta = static_cast<std::int64_t>(stub_va) - static_cast<std::int64_t>(target_va);
        const std::int64_t imm26 = delta >> 2;
        if (imm26 < -(1LL << 25) || imm26 >= (1LL << 25)) {
            return diagnostics::Result<ProtectionReport>::err(ErrorCode::OutOfBounds, "ARM64 branch target out of 128MB range", "MachORewriter::protect_file");
        }
        const std::uint32_t insn = 0x14000000u | (static_cast<std::uint32_t>(imm26) & 0x03FFFFFFu);
        std::memcpy(text_content.data() + patch_off, &insn, 4);
    } else {
        const std::int64_t rel32 = static_cast<std::int64_t>(stub_va) - static_cast<std::int64_t>(target_va + 5);
        text_content[patch_off] = 0xE9;
        const std::uint32_t rel32_u = static_cast<std::uint32_t>(static_cast<std::int32_t>(rel32));
        std::memcpy(text_content.data() + patch_off + 1, &rel32_u, 4);
    }
    text_sec->content(text_content);

    // Seal metadata in __BMVM (R--)
    auto bvm_encoded = BvmCodec::encode(bvm_res.value());
    if (!bvm_encoded) {
        return diagnostics::Result<ProtectionReport>::err(bvm_encoded.error().code, bvm_encoded.error().message, "MachORewriter::protect_file");
    }
    std::vector<std::uint8_t> plaintext = bvm_encoded.value();
    std::uint32_t str_cnt = 0;
    if (options.protect_strings) {
        if (const auto* cstring = macho->get_section("__TEXT", "__cstring")) {
            auto strs = collect_printable_strings(cstring->content(), str_cnt);
            plaintext.insert(plaintext.end(), strs.begin(), strs.end());
        }
    }

    ProtectionMetadata meta;
    meta.profile = options.profile;
    meta.seed = options.seed;
    meta.text_blake2b = CryptoAead::blake2b_256(text_content);
    meta.runtime_blake2b = CryptoAead::blake2b_256(runtime_bytes);
    meta.protected_strings_count = str_cnt;
    meta.functions.push_back(ProtectedFunctionRecord{
        target_name,
        target_va - bin.info().image_base,
        stub_va - bin.info().image_base,
        static_cast<std::uint32_t>(min_patch),
        orig_ops,
        static_cast<std::uint32_t>(obf_res.value().obfuscated_instructions),
        static_cast<std::uint32_t>(bvm_res.value().instructions.size())
    });

    const auto key = CryptoAead::derive_key_from_seed(options.seed, "ByteMorph-v0.5-MachO");
    const auto nonce = CryptoAead::generate_nonce(options.seed, 1);
    std::vector<std::uint8_t> aad;
    aad.insert(aad.end(), meta.text_blake2b.begin(), meta.text_blake2b.end());
    aad.insert(aad.end(), meta.runtime_blake2b.begin(), meta.runtime_blake2b.end());

    auto sealed = CryptoAead::seal(plaintext, aad, key, nonce);
    if (!sealed) {
        return diagnostics::Result<ProtectionReport>::err(sealed.error().code, sealed.error().message, "MachORewriter::protect_file");
    }
    meta.sealed_payload = std::move(sealed.value());

    const auto bmvm_bytes = serialize_metadata(meta);
    LIEF::MachO::SegmentCommand bmvm_seg("__BMVM");
    bmvm_seg.init_protection(1); // VM_PROT_READ only
    bmvm_seg.max_protection(1);
    LIEF::MachO::Section bmvm_sec("__bmvm", bmvm_bytes);
    bmvm_sec.segment_name("__BMVM");
    bmvm_sec.type(LIEF::MachO::Section::TYPE::REGULAR);
    bmvm_seg.add_section(bmvm_sec);

    if (!macho->add(bmvm_seg)) {
        return diagnostics::Result<ProtectionReport>::err(ErrorCode::InternalError, "Failed to add __BMVM Mach-O segment", "MachORewriter::protect_file");
    }

    const auto tmp_path = std::filesystem::path(output.string() + ".tmp");
    try {
        macho->write(tmp_path.string());
        std::filesystem::rename(tmp_path, output);
        std::error_code perm_ec;
        std::filesystem::permissions(
            output,
            std::filesystem::perms::owner_exec | std::filesystem::perms::group_exec | std::filesystem::perms::others_exec,
            std::filesystem::perm_options::add,
            perm_ec);
    } catch (const std::exception& ex) {
        std::error_code ec;
        std::filesystem::remove(tmp_path, ec);
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::IoError, std::string("LIEF Mach-O write failed: ") + ex.what(), "MachORewriter::protect_file");
    }

#if defined(__APPLE__)
    // Respect macOS code-signing policy using official Apple codesign tool (ad-hoc)
    const std::string cs_cmd = "/usr/bin/codesign -s - -f \"" + output.string() + "\" >/dev/null 2>&1";
    (void)std::system(cs_cmd.c_str());
#endif

    auto ver = verify_file(output);
    if (!ver || !ver.value().valid) {
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::ParseError, "Post-protection Mach-O verification failed", "MachORewriter::protect_file");
    }

    std::error_code ec;
    ProtectionReport rep;
    rep.format = BinaryFormat::MachO64;
    rep.architecture = bin.info().architecture;
    rep.profile = options.profile;
    rep.seed = options.seed;
    rep.input_size = bin.info().file_size;
    rep.output_size = std::filesystem::file_size(output, ec);
    rep.protected_functions = meta.functions;
    rep.protected_strings_count = meta.protected_strings_count;
    rep.aslr_preserved = bin.info().is_pie;
    rep.dep_preserved = bin.info().has_nx;
    return rep;
}

diagnostics::Result<VerifyReport>
MachORewriter::verify_file(const std::filesystem::path& path) const {
    using diagnostics::ErrorCode;
    std::unique_ptr<LIEF::MachO::FatBinary> fat;
    try {
        fat = LIEF::MachO::Parser::parse(path.string());
    } catch (const std::exception& ex) {
        return diagnostics::Result<VerifyReport>::err(
            ErrorCode::ParseError, std::string("Mach-O parse error: ") + ex.what(), "MachORewriter::verify_file");
    }
    if (!fat || fat->empty()) {
        return diagnostics::Result<VerifyReport>::err(ErrorCode::ParseError, "Invalid Mach-O file", "MachORewriter::verify_file");
    }
    const LIEF::MachO::Binary* macho = fat->at(0);
    const auto* bmvm = macho ? macho->get_section("__BMVM", "__bmvm") : nullptr;
    const auto* bmrt = macho ? macho->get_section("__BMRT", "__bmrt") : nullptr;
    const auto* text = macho ? macho->get_section("__TEXT", "__text") : nullptr;
    if (!bmvm || !bmrt || !text) {
        return diagnostics::Result<VerifyReport>::err(
            ErrorCode::ParseError, "Missing ByteMorph Mach-O protection sections (__BMVM/__BMRT/__TEXT)", "MachORewriter::verify_file");
    }

    auto meta_res = deserialize_metadata(bmvm->content());
    if (!meta_res) {
        return diagnostics::Result<VerifyReport>::err(meta_res.error().code, meta_res.error().message, "MachORewriter::verify_file");
    }

    VerifyReport rep;
    rep.metadata = std::move(meta_res.value());
    const auto cur_text = CryptoAead::blake2b_256(text->content());
    const auto cur_rt = CryptoAead::blake2b_256(bmrt->content());
    rep.text_integrity_ok = (cur_text == rep.metadata.text_blake2b);
    rep.runtime_integrity_ok = (cur_rt == rep.metadata.runtime_blake2b);

    const auto key = CryptoAead::derive_key_from_seed(rep.metadata.seed, "ByteMorph-v0.5-MachO");
    std::vector<std::uint8_t> aad;
    aad.insert(aad.end(), cur_text.begin(), cur_text.end());
    aad.insert(aad.end(), cur_rt.begin(), cur_rt.end());

    rep.aead_authenticated = CryptoAead::open(rep.metadata.sealed_payload, aad, key).has_value();
    rep.valid = rep.text_integrity_ok && rep.runtime_integrity_ok && rep.aead_authenticated;
    rep.summary = rep.valid ? "Mach-O integrity and AEAD authentication verified" : "Tampering detected";
    return rep;
}

} // namespace bytemorph::prot
