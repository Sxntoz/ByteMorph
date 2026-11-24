#include "bytemorph/prot/pe_rewriter.hpp"

#include "bytemorph/arch/aarch64/aarch64_disasm.hpp"
#include "bytemorph/arch/aarch64/aarch64_lifter.hpp"
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

#include <chrono>
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
    return fmt == BinaryFormat::PE32Plus && (arch == Architecture::X86_64 || arch == Architecture::ARM64);
}

diagnostics::Result<ProtectionReport>
PeRewriter::protect_file(const std::filesystem::path& input,
                         const std::filesystem::path& output,
                         const ProtectOptions& options) const {
    using diagnostics::ErrorCode;
    const auto t_start = std::chrono::steady_clock::now();

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
            "PeRewriter only supports PE32+ x86-64 and ARM64 binaries",
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
        "AsmJit is disabled in this build; native VM runtime emission requires AsmJit",
        "PeRewriter::protect_file");
#else
    const bool is_arm64 = (bin.info().architecture == Architecture::ARM64);
    const std::size_t min_patch = is_arm64 ? 4 : 5;

    arch::x86_64::X86_64Disassembler x64_disasm;
    arch::aarch64::AArch64Disassembler a64_disasm;
    IDisassemblerEngine& disasm = is_arm64 ? static_cast<IDisassemblerEngine&>(a64_disasm)
                                           : static_cast<IDisassemblerEngine&>(x64_disasm);
    BinaryAnalyzer analyzer;
    auto an_res = analyzer.analyze(bin, disasm);
    if (!an_res) {
        return diagnostics::Result<ProtectionReport>::err(an_res.error().code, an_res.error().message, "PeRewriter::protect_file");
    }

    const std::uint32_t sec_align = pe->optional_header().section_alignment();
    std::uint32_t max_rva_end = 0;
    for (const auto& s : pe->sections()) {
        const std::uint32_t end = static_cast<std::uint32_t>(s.virtual_address() + (std::max)(s.virtual_size(), s.sizeof_raw_data()));
        if (end > max_rva_end) max_rva_end = end;
    }
    const std::uint32_t bmrt_rva = static_cast<std::uint32_t>(align_up(max_rva_end, sec_align));
    const std::uint64_t stub_base_va = bin.info().image_base + bmrt_rva;

    auto plan_res = prepare_target_functions(bin, an_res.value(), disasm, options, stub_base_va, is_arm64);
    if (!plan_res) {
        return diagnostics::Result<ProtectionReport>::err(
            plan_res.error().code, plan_res.error().message, "PeRewriter::protect_file");
    }
    auto& plan = plan_res.value();

    std::vector<BvmProgram> progs;
    progs.reserve(plan.prepared.size());
    for (const auto& pf : plan.prepared) {
        progs.push_back(pf.program);
    }

    SharedRuntimeLayout rt_layout;
    detail::SharedRuntimeOptions rt_opts;
    rt_opts.encrypt_bytecode = options.encrypt_bytecode || (options.profile == ProtectionProfile::Maximum);
    rt_opts.seed = options.seed;

    auto runtime_bytes_res = is_arm64
        ? emit_shared_pic_arm64_vm_runtime(progs, rt_layout, rt_opts)
        : emit_shared_pic_x64_vm_runtime(progs, AbiKind::Win64, rt_layout, rt_opts);
    if (!runtime_bytes_res) {
        return diagnostics::Result<ProtectionReport>::err(
            runtime_bytes_res.error().code, runtime_bytes_res.error().message, "PeRewriter::protect_file");
    }
    const auto& runtime_bytes = runtime_bytes_res.value();

    LIEF::PE::Section* text_sec = pe->get_section(".text");
    if (!text_sec) {
        return diagnostics::Result<ProtectionReport>::err(ErrorCode::ParseError, "PE missing .text section", "PeRewriter::protect_file");
    }

    // Validate ALL function patch locations BEFORE mutating sections (transactional!)
    struct MutableSec {
        LIEF::PE::Section* sec{nullptr};
        std::vector<std::uint8_t> content;
    };
    std::vector<MutableSec> mutable_secs;
    auto get_or_load_sec = [&](std::uint64_t rva, std::size_t len) -> MutableSec* {
        for (auto& ms : mutable_secs) {
            const std::uint64_t s_va = ms.sec->virtual_address();
            if (rva >= s_va && rva + len <= s_va + ms.content.size()) return &ms;
        }
        for (auto& sec : pe->sections()) {
            const std::uint64_t s_va = sec.virtual_address();
            auto c = sec.content();
            if (rva >= s_va && rva + len <= s_va + c.size()) {
                mutable_secs.push_back({&sec, std::vector<std::uint8_t>(c.begin(), c.end())});
                return &mutable_secs.back();
            }
        }
        return nullptr;
    };

    for (std::size_t i = 0; i < plan.prepared.size(); ++i) {
        const auto& pf = plan.prepared[i];
        const std::uint64_t target_rva = pf.entry_va - bin.info().image_base;
        MutableSec* target_ms = get_or_load_sec(target_rva, min_patch);
        if (!target_ms) {
            return diagnostics::Result<ProtectionReport>::err(
                ErrorCode::OutOfBounds, "Target RVA is outside executable section raw content: " + pf.name, "PeRewriter::protect_file");
        }
        const std::size_t patch_off = static_cast<std::size_t>(target_rva - target_ms->sec->virtual_address());
        const std::uint64_t fn_stub_rva = bmrt_rva + rt_layout.entry_offsets[i];
        if (is_arm64) {
            const std::int64_t delta = static_cast<std::int64_t>(fn_stub_rva) - static_cast<std::int64_t>(target_rva);
            const std::int64_t imm26 = delta >> 2;
            if (imm26 < -(1LL << 25) || imm26 >= (1LL << 25)) {
                return diagnostics::Result<ProtectionReport>::err(ErrorCode::OutOfBounds, "ARM64 branch target out of 128MB range", "PeRewriter::protect_file");
            }
            const std::uint32_t insn = 0x14000000u | (static_cast<std::uint32_t>(imm26) & 0x03FFFFFFu);
            std::memcpy(target_ms->content.data() + patch_off, &insn, 4);
        } else {
            const std::int64_t rel32 = static_cast<std::int64_t>(fn_stub_rva) - static_cast<std::int64_t>(target_rva + 5);
            target_ms->content[patch_off] = 0xE9;
            const std::uint32_t rel32_u = static_cast<std::uint32_t>(static_cast<std::int32_t>(rel32));
            std::memcpy(target_ms->content.data() + patch_off + 1, &rel32_u, 4);
        }
    }
    for (auto& ms : mutable_secs) {
        ms.sec->content(ms.content);
    }

    // Add shared .bmrt (R-X, W^X compliant)
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

    // Seal all .bvm programs + optional strings with XChaCha20-Poly1305 AEAD
    std::vector<std::uint8_t> plaintext;
    for (const auto& prog : progs) {
        auto bvm_encoded = BvmCodec::encode(prog);
        if (!bvm_encoded) {
            return diagnostics::Result<ProtectionReport>::err(bvm_encoded.error().code, bvm_encoded.error().message, "PeRewriter::protect_file");
        }
        plaintext.insert(plaintext.end(), bvm_encoded.value().begin(), bvm_encoded.value().end());
    }
    std::uint32_t str_cnt = 0;
    if (options.protect_strings) {
        if (const auto* rdata = pe->get_section(".rdata")) {
            auto strs = collect_printable_strings(rdata->content(), str_cnt);
            plaintext.insert(plaintext.end(), strs.begin(), strs.end());
        }
    }

    ProtectionMetadata meta;
    meta.profile = options.profile;
    meta.bytecode_mode = options.bytecode_mode;
    meta.seed = options.seed;
    meta.bytecode_encrypted = rt_opts.encrypt_bytecode;
    meta.text_blake2b = CryptoAead::blake2b_256(text_sec->content());
    meta.runtime_blake2b = CryptoAead::blake2b_256(runtime_bytes);
    meta.protected_strings_count = str_cnt;
    if (rt_opts.encrypt_bytecode || options.bytecode_mode == BytecodeMode::Lazy) {
        auto rt_key = CryptoAead::derive_key_from_seed(rt_opts.seed, rt_opts.key_domain);
        if (rt_opts.encrypt_bytecode) {
            for (std::size_t i = 0; i < progs.size(); ++i) {
                const std::uint32_t plain_sz = static_cast<std::uint32_t>(4 + progs[i].instructions.size() * 12);
                const auto nonce = CryptoAead::generate_nonce(rt_opts.seed ^ (0x9E3779B97F4A7C15ULL * (i + 1)), i + 100);
                std::array<std::uint8_t, 16> aad{};
                const std::uint32_t words[4] = {0x43424D42u, 2u, static_cast<std::uint32_t>(i), plain_sz};
                std::memcpy(aad.data(), words, sizeof(words));
                EncryptedBytecodeRecord ef;
                ef.fn_index = static_cast<std::uint32_t>(i);
                ef.nonce = nonce;
                ef.plaintext_size = plain_sz;
                ef.aad_hash = CryptoAead::blake2b_256(aad);
                meta.encrypted_functions.push_back(ef);
            }
        }
        if (options.bytecode_mode == BytecodeMode::Lazy) {
            for (std::size_t i = 0; i < progs.size(); ++i) {
                auto sealed_fn = LazyBytecodeEngine::seal_function(
                    progs[i], rt_key, options.seed, static_cast<std::uint32_t>(i));
                if (!sealed_fn) {
                    CryptoAead::secure_wipe(rt_key.bytes);
                    return diagnostics::Result<ProtectionReport>::err(
                        sealed_fn.error().code, sealed_fn.error().message, "PeRewriter::protect_file");
                }
                for (auto& blk : sealed_fn.value().blocks) {
                    meta.lazy_blocks.push_back(std::move(blk));
                }
            }
        }
        CryptoAead::secure_wipe(rt_key.bytes);
    }
    for (std::size_t i = 0; i < plan.prepared.size(); ++i) {
        const auto& pf = plan.prepared[i];
        meta.functions.push_back(ProtectedFunctionRecord{
            pf.name,
            pf.entry_va - bin.info().image_base,
            added_bmrt->virtual_address() + rt_layout.entry_offsets[i],
            static_cast<std::uint32_t>(min_patch),
            pf.orig_ir_ops,
            pf.obf_ir_ops,
            static_cast<std::uint32_t>(pf.program.instructions.size())
        });
    }

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

    const auto t_end = std::chrono::steady_clock::now();
    const double elapsed_ms = std::chrono::duration<double, std::milli>(t_end - t_start).count();

    std::error_code ec;
    ProtectionReport rep;
    rep.format = BinaryFormat::PE32Plus;
    rep.architecture = bin.info().architecture;
    rep.profile = options.profile;
    rep.bytecode_mode = options.bytecode_mode;
    rep.seed = options.seed;
    rep.input_size = bin.info().file_size;
    rep.output_size = std::filesystem::file_size(output, ec);
    rep.protected_functions = meta.functions;
    rep.protected_strings_count = meta.protected_strings_count;
    rep.encrypted_blocks_count = static_cast<std::uint32_t>(meta.lazy_blocks.size());
    rep.aslr_preserved = bin.info().is_pie;
    rep.dep_preserved = bin.info().has_nx;
    rep.total_functions_analyzed = plan.total_analyzed;
    rep.eligible_functions_count = plan.eligible_count;
    rep.rejected_functions = std::move(plan.rejected);
    rep.transform_time_ms = elapsed_ms;
    rep.shared_runtime_used = true;
    rep.runtime_bytes_size = runtime_bytes.size();
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
    if (rep.aead_authenticated && rep.metadata.bytecode_mode == BytecodeMode::Lazy) {
        auto rt_key = CryptoAead::derive_key_from_seed(rep.metadata.seed, "ByteMorph-v0.10-Runtime");
        for (const auto& lb : rep.metadata.lazy_blocks) {
            auto blk_ok = LazyBytecodeEngine::verify_block_aead(lb, rt_key);
            if (!blk_ok) {
                rep.aead_authenticated = false;
                break;
            }
            ++rep.blocks_verified_count;
        }
        CryptoAead::secure_wipe(rt_key.bytes);
    }
    rep.valid = rep.text_integrity_ok && rep.runtime_integrity_ok && rep.aead_authenticated;
    rep.summary = rep.valid ? "Integrity and AEAD authentication verified" : "Tampering detected";
    return rep;
}

} // namespace bytemorph::prot
