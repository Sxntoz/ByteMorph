#include "bytemorph/prot/pe_rewriter.hpp"

#include "bytemorph/arch/x86_64/x86_64_disasm.hpp"
#include "bytemorph/arch/x86_64/x86_64_lifter.hpp"
#include "bytemorph/core/analysis/analyzer.hpp"
#include "bytemorph/core/binary/loader.hpp"
#include "bytemorph/formats/pe/pe_parser.hpp"
#include "bytemorph/obf/obfuscation_engine.hpp"
#include "bytemorph/prot/native_vm_emitter.hpp"
#include "bytemorph/virt/bvm_format.hpp"
#include "bytemorph/virt/ir_to_vm.hpp"

#include <LIEF/PE.hpp>

#include <cstring>
#include <filesystem>
#include <fstream>

namespace bytemorph::prot {

using namespace bytemorph::core;
using namespace bytemorph::core::binary;
using namespace bytemorph::core::analysis;
using namespace bytemorph::core::ir;
using namespace bytemorph::obf;
using namespace bytemorph::virt;
using namespace bytemorph::prot::detail;

bool PeRewriter::supports(BinaryFormat fmt, Architecture arch) const noexcept {
    return fmt == BinaryFormat::PE32Plus && arch == Architecture::X86_64;
}

diagnostics::Result<ProtectionReport>
PeRewriter::protect_file(const std::filesystem::path& input,
                         const std::filesystem::path& output,
                         const ProtectOptions& options) const {
    using diagnostics::ErrorCode;

    formats::pe::PeParser parser;
    BinaryLoader loader;
    loader.register_parser(std::make_unique<formats::pe::PeParser>());
    auto bin_res = loader.load_file(input);
    if (!bin_res) {
        return diagnostics::Result<ProtectionReport>::err(
            bin_res.error().code, bin_res.error().message, "PeRewriter::protect_file");
    }

    const auto& bin = *bin_res.value();
    if (!supports(bin.info().format, bin.info().architecture)) {
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::UnsupportedFormat,
            "PeRewriter only supports PE32+ x86-64 binaries in v0.4",
            "PeRewriter::protect_file");
    }

    std::unique_ptr<LIEF::PE::Binary> pe;
    try {
        pe = LIEF::PE::Parser::parse(input.string());
    } catch (const std::exception& ex) {
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::ParseError, std::string("LIEF PE parse failed: ") + ex.what(), "PeRewriter::protect_file");
    }
    if (!pe) {
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::ParseError, "Failed to parse PE32+ binary", "PeRewriter::protect_file");
    }

    if (pe->has_signatures() && !options.allow_strip_signature) {
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::ParseError,
            "Input PE is Authenticode-signed; refusing to silently invalidate signature (pass --allow-signed-strip to override)",
            "PeRewriter::protect_file");
    }

#if !defined(BYTEMORPH_HAS_ASMJIT)
    return diagnostics::Result<ProtectionReport>::err(
        ErrorCode::NotImplemented,
        "AsmJit is disabled in this build; native x86-64 VM runtime emission requires AsmJit",
        "PeRewriter::protect_file");
#else
    // Locate target function
    std::uint64_t target_va = 0;
    std::string target_name;
    if (options.target_function_rva.has_value()) {
        target_va = bin.info().image_base + *options.target_function_rva;
        target_name = options.target_function_name.empty() ? "target_fn" : options.target_function_name;
    } else if (!options.target_function_name.empty()) {
        for (const auto& exp : bin.exports()) {
            if (exp.name == options.target_function_name && !exp.is_forwarded) {
                target_va = exp.address;
                target_name = exp.name;
                break;
            }
        }
        if (target_va == 0) {
            return diagnostics::Result<ProtectionReport>::err(
                ErrorCode::FileNotFound,
                "Target exported function not found: " + options.target_function_name,
                "PeRewriter::protect_file");
        }
    } else {
        // Default: pick first non-forwarded export
        for (const auto& exp : bin.exports()) {
            if (!exp.is_forwarded && exp.address != 0) {
                target_va = exp.address;
                target_name = exp.name;
                break;
            }
        }
        if (target_va == 0) {
            return diagnostics::Result<ProtectionReport>::err(
                ErrorCode::UnsupportedFormat,
                "No exported target function found; specify --func-rva <hex> or --func <export_name>",
                "PeRewriter::protect_file");
        }
    }

    // Analyze target function using existing engine
    arch::x86_64::X86_64Disassembler disasm;
    BinaryAnalyzer analyzer;
    auto an_res = analyzer.analyze(bin, disasm);
    if (!an_res) {
        return diagnostics::Result<ProtectionReport>::err(an_res.error().code, an_res.error().message, "PeRewriter::protect_file");
    }

    const FunctionInfo* target_fn = nullptr;
    for (const auto& fn : an_res.value().functions) {
        if (fn.entry_va == target_va) {
            target_fn = &fn;
            break;
        }
    }

    // If not in auto-discovered seeds (e.g. --func-rva passed directly), disassemble bounded window up to ret
    FunctionInfo adhoc_fn;
    if (!target_fn) {
        auto slice = bin.read_virtual(target_va, 256);
        if (!slice) {
            return diagnostics::Result<ProtectionReport>::err(slice.error().code, slice.error().message, "PeRewriter::protect_file");
        }
        auto dis = disasm.disassemble(slice.value(), target_va, 64);
        if (!dis || dis.value().empty()) {
            return diagnostics::Result<ProtectionReport>::err(ErrorCode::DisassemblyError, "Failed to disassemble target function", "PeRewriter::protect_file");
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

    if (target_fn->size_bytes < 5) {
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::OutOfBounds,
            "Target function is smaller than 5 bytes (cannot place rel32 trampoline)",
            "PeRewriter::protect_file");
    }

    // Lift -> Obfuscate -> Translate to BVM
    arch::x86_64::X86_64Lifter lifter;
    IrFunction ir_fn = lifter.lift_function(*target_fn);
    std::uint32_t orig_ops = 0;
    for (const auto& bb : ir_fn.blocks) orig_ops += static_cast<std::uint32_t>(bb.instructions.size());

    ObfuscationConfig obf_cfg;
    obf_cfg.seed = options.seed;
    obf_cfg.enable_substitution = true;
    obf_cfg.enable_mba = (options.profile != ProtectionProfile::Fast);
    obf_cfg.enable_cfg = (options.profile == ProtectionProfile::Maximum);

    auto obf_res = ObfuscationPipeline::obfuscate_function(ir_fn, obf_cfg);
    if (!obf_res) {
        return diagnostics::Result<ProtectionReport>::err(obf_res.error().code, obf_res.error().message, "PeRewriter::protect_file");
    }

    const std::uint32_t sec_align = pe->optional_header().section_alignment();
    std::uint32_t max_rva_end = 0;
    for (const auto& s : pe->sections()) {
        const std::uint32_t end = static_cast<std::uint32_t>(s.virtual_address() + (std::max)(s.virtual_size(), s.sizeof_raw_data()));
        if (end > max_rva_end) max_rva_end = end;
    }
    const std::uint32_t bmrt_rva = static_cast<std::uint32_t>(align_up(max_rva_end, sec_align));
    const std::uint64_t stub_va = bin.info().image_base + bmrt_rva;

    virt::TranslateOptions t_opts;
    t_opts.build_seed = options.seed;
    t_opts.allow_external_calls = options.allow_external_calls;
    t_opts.stub_base_va = stub_va;

    auto bvm_res = IrToVmTranslator::translate(ir_fn, t_opts);
    if (!bvm_res) {
        return diagnostics::Result<ProtectionReport>::err(
            bvm_res.error().code,
            "Function is not eligible for v0.4/v0.5 selective virtualization: " + bvm_res.error().message,
            "PeRewriter::protect_file");
    }

    auto runtime_bytes_res = emit_pic_x64_vm_runtime(bvm_res.value(), AbiKind::Win64);
    if (!runtime_bytes_res) {
        return diagnostics::Result<ProtectionReport>::err(
            runtime_bytes_res.error().code, runtime_bytes_res.error().message, "PeRewriter::protect_file");
    }
    const auto& runtime_bytes = runtime_bytes_res.value();

    LIEF::PE::Section* text_sec = pe->get_section(".text");
    if (!text_sec) {
        return diagnostics::Result<ProtectionReport>::err(ErrorCode::ParseError, "PE missing .text section", "PeRewriter::protect_file");
    }

    const std::uint64_t target_rva = target_va - bin.info().image_base;
    if (target_rva < text_sec->virtual_address() ||
        target_rva + 5 > text_sec->virtual_address() + text_sec->content().size()) {
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::OutOfBounds, "Target RVA is outside .text raw content", "PeRewriter::protect_file");
    }

    // Patch 5-byte relative JMP (E9 rel32) in .text -> bmrt_rva
    auto text_content = std::vector<std::uint8_t>(text_sec->content().begin(), text_sec->content().end());
    const std::size_t patch_off = static_cast<std::size_t>(target_rva - text_sec->virtual_address());
    const std::int64_t rel32 = static_cast<std::int64_t>(bmrt_rva) - static_cast<std::int64_t>(target_rva + 5);
    text_content[patch_off] = 0xE9;
    const std::uint32_t rel32_u = static_cast<std::uint32_t>(static_cast<std::int32_t>(rel32));
    std::memcpy(text_content.data() + patch_off + 1, &rel32_u, 4);
    text_sec->content(text_content);

    // Add .bmrt (R-X, W^X compliant)
    LIEF::PE::Section bmrt_sec(".bmrt");
    bmrt_sec.content(runtime_bytes);
    bmrt_sec.virtual_size(static_cast<std::uint32_t>(runtime_bytes.size()));
    bmrt_sec.characteristics(
        static_cast<std::uint32_t>(LIEF::PE::Section::CHARACTERISTICS::CNT_CODE) |
        static_cast<std::uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ) |
        static_cast<std::uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE));
    LIEF::PE::Section* added_bmrt = pe->add_section(bmrt_sec);
    if (!added_bmrt) {
        return diagnostics::Result<ProtectionReport>::err(ErrorCode::InternalError, "Failed to add .bmrt section", "PeRewriter::protect_file");
    }

    // Seal .bvm + optional strings with XChaCha20-Poly1305 AEAD
    auto bvm_encoded = BvmCodec::encode(bvm_res.value());
    if (!bvm_encoded) {
        return diagnostics::Result<ProtectionReport>::err(bvm_encoded.error().code, bvm_encoded.error().message, "PeRewriter::protect_file");
    }
    std::vector<std::uint8_t> plaintext = bvm_encoded.value();
    std::uint32_t str_cnt = 0;
    if (options.protect_strings) {
        if (const auto* rdata = pe->get_section(".rdata")) {
            auto strs = collect_printable_strings(rdata->content(), str_cnt);
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
        target_rva,
        added_bmrt->virtual_address(),
        5,
        orig_ops,
        static_cast<std::uint32_t>(obf_res.value().obfuscated_instructions),
        static_cast<std::uint32_t>(bvm_res.value().instructions.size())
    });

    const auto key = CryptoAead::derive_key_from_seed(options.seed, "ByteMorph-v0.4-PE");
    const auto nonce = CryptoAead::generate_nonce(options.seed, 1);
    std::vector<std::uint8_t> aad;
    aad.insert(aad.end(), meta.text_blake2b.begin(), meta.text_blake2b.end());
    aad.insert(aad.end(), meta.runtime_blake2b.begin(), meta.runtime_blake2b.end());

    auto sealed = CryptoAead::seal(plaintext, aad, key, nonce);
    if (!sealed) {
        return diagnostics::Result<ProtectionReport>::err(sealed.error().code, sealed.error().message, "PeRewriter::protect_file");
    }
    meta.sealed_payload = std::move(sealed.value());

    const auto bmvm_bytes = serialize_metadata(meta);
    LIEF::PE::Section bmvm_sec(".bmvm");
    bmvm_sec.content(bmvm_bytes);
    bmvm_sec.virtual_size(static_cast<std::uint32_t>(bmvm_bytes.size()));
    bmvm_sec.characteristics(
        static_cast<std::uint32_t>(LIEF::PE::Section::CHARACTERISTICS::CNT_INITIALIZED_DATA) |
        static_cast<std::uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_READ));
    if (!pe->add_section(bmvm_sec)) {
        return diagnostics::Result<ProtectionReport>::err(ErrorCode::InternalError, "Failed to add .bmvm section", "PeRewriter::protect_file");
    }

    // Atomic write via temporary file
    const auto tmp_path = std::filesystem::path(output.string() + ".tmp");
    try {
        LIEF::PE::Builder builder(*pe);
        builder.build();
        builder.write(tmp_path.string());
        std::filesystem::rename(tmp_path, output);
    } catch (const std::exception& ex) {
        std::error_code ec;
        std::filesystem::remove(tmp_path, ec);
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::IoError, std::string("LIEF PE write failed: ") + ex.what(), "PeRewriter::protect_file");
    }

    // Post-write structural validation
    auto verify_res = verify_file(output);
    if (!verify_res || !verify_res.value().valid) {
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::ParseError,
            "Post-protection structural/integrity verification failed",
            "PeRewriter::protect_file");
    }

    std::error_code ec;
    ProtectionReport rep;
    rep.format = BinaryFormat::PE32Plus;
    rep.architecture = Architecture::X86_64;
    rep.profile = options.profile;
    rep.seed = options.seed;
    rep.input_size = bin.info().file_size;
    rep.output_size = std::filesystem::file_size(output, ec);
    rep.protected_functions = meta.functions;
    rep.protected_strings_count = meta.protected_strings_count;
    rep.aslr_preserved = bin.info().is_pie;
    rep.dep_preserved = bin.info().has_nx;
    return rep;
#endif
}

diagnostics::Result<VerifyReport>
PeRewriter::verify_file(const std::filesystem::path& path) const {
    using diagnostics::ErrorCode;
    std::unique_ptr<LIEF::PE::Binary> pe;
    try {
        pe = LIEF::PE::Parser::parse(path.string());
    } catch (const std::exception& ex) {
        return diagnostics::Result<VerifyReport>::err(
            ErrorCode::ParseError, std::string("PE parse error: ") + ex.what(), "PeRewriter::verify_file");
    }
    if (!pe) {
        return diagnostics::Result<VerifyReport>::err(ErrorCode::ParseError, "Invalid PE file", "PeRewriter::verify_file");
    }

    const auto* bmvm = pe->get_section(".bmvm");
    const auto* bmrt = pe->get_section(".bmrt");
    const auto* text = pe->get_section(".text");
    if (!bmvm || !bmrt || !text) {
        return diagnostics::Result<VerifyReport>::err(
            ErrorCode::ParseError, "Missing ByteMorph protection sections (.bmvm/.bmrt/.text)", "PeRewriter::verify_file");
    }

    auto meta_res = deserialize_metadata(bmvm->content());
    if (!meta_res) {
        return diagnostics::Result<VerifyReport>::err(meta_res.error().code, meta_res.error().message, "PeRewriter::verify_file");
    }

    VerifyReport rep;
    rep.metadata = std::move(meta_res.value());
    rep.text_integrity_ok = (CryptoAead::blake2b_256(text->content()) == rep.metadata.text_blake2b);
    rep.runtime_integrity_ok = (CryptoAead::blake2b_256(bmrt->content()) == rep.metadata.runtime_blake2b);

    const auto key = CryptoAead::derive_key_from_seed(rep.metadata.seed, "ByteMorph-v0.4-PE");
    std::vector<std::uint8_t> aad;
    const auto cur_text = CryptoAead::blake2b_256(text->content());
    const auto cur_rt = CryptoAead::blake2b_256(bmrt->content());
    aad.insert(aad.end(), cur_text.begin(), cur_text.end());
    aad.insert(aad.end(), cur_rt.begin(), cur_rt.end());

    auto open_res = CryptoAead::open(rep.metadata.sealed_payload, aad, key);
    rep.aead_authenticated = open_res.has_value();
    rep.valid = rep.text_integrity_ok && rep.runtime_integrity_ok && rep.aead_authenticated;
    rep.summary = rep.valid ? "Integrity and AEAD authentication verified" : "Tampering detected";
    return rep;
}

} // namespace bytemorph::prot
