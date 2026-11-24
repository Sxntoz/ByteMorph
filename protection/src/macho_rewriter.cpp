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

#include <chrono>
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
    const auto t_start = std::chrono::steady_clock::now();

    BinaryLoader loader;
    loader.register_parser(std::make_unique<formats::macho::MachOParser>());
    auto bin_res = loader.load_file(input);
    if (!bin_res) {
        return diagnostics::Result<ProtectionReport>::err(
            bin_res.error().code, bin_res.error().message, "MachORewriter::protect_file");
    }

    const auto& first_bin = *bin_res.value();
    if (!supports(first_bin.info().format, first_bin.info().architecture)) {
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

    ProtectionReport rep;
    rep.format = BinaryFormat::MachO64;
    rep.architecture = first_bin.info().architecture;
    rep.profile = options.profile;
    rep.seed = options.seed;
    rep.input_size = first_bin.info().file_size;
    rep.aslr_preserved = first_bin.info().is_pie;
    rep.dep_preserved = first_bin.info().has_nx;
    rep.shared_runtime_used = true;

    const std::size_t num_slices = fat->size();
    for (std::size_t s_idx = 0; s_idx < num_slices; ++s_idx) {
        LIEF::MachO::Binary* macho = fat->at(s_idx);
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

        std::unique_ptr<IBinaryFile> temp_slice_bin;
        const IBinaryFile* slice_bin = nullptr;
        if (num_slices == 1) {
            slice_bin = bin_res.value().get();
        } else {
            const auto slice_tmp = std::filesystem::path(
                output.string() + ".slice" + std::to_string(s_idx) + ".tmp");
            try {
                macho->write(slice_tmp.string());
            } catch (const std::exception& ex) {
                std::error_code rm_ec;
                std::filesystem::remove(slice_tmp, rm_ec);
                return diagnostics::Result<ProtectionReport>::err(
                    ErrorCode::IoError, std::string("Failed to extract Mach-O Universal slice: ") + ex.what(), "MachORewriter::protect_file");
            }
            auto s_bin_res = loader.load_file(slice_tmp);
            std::error_code rm_ec;
            std::filesystem::remove(slice_tmp, rm_ec);
            if (!s_bin_res) {
                return diagnostics::Result<ProtectionReport>::err(
                    s_bin_res.error().code, s_bin_res.error().message, "MachORewriter::protect_file");
            }
            temp_slice_bin = std::move(s_bin_res.value());
            slice_bin = temp_slice_bin.get();
        }

        if (!supports(slice_bin->info().format, slice_bin->info().architecture)) {
            return diagnostics::Result<ProtectionReport>::err(
                ErrorCode::UnsupportedFormat, "Unsupported Mach-O slice architecture", "MachORewriter::protect_file");
        }

        const bool is_arm64 = (slice_bin->info().architecture == Architecture::ARM64);
        const std::size_t min_patch = is_arm64 ? 4 : 5;
        std::unique_ptr<IDisassemblerEngine> disasm = is_arm64
            ? std::unique_ptr<IDisassemblerEngine>(std::make_unique<arch::aarch64::AArch64Disassembler>())
            : std::unique_ptr<IDisassemblerEngine>(std::make_unique<arch::x86_64::X86_64Disassembler>());

        BinaryAnalyzer analyzer;
        auto an_res = analyzer.analyze(*slice_bin, *disasm);
        if (!an_res) {
            return diagnostics::Result<ProtectionReport>::err(an_res.error().code, an_res.error().message, "MachORewriter::protect_file");
        }

        auto plan_res = prepare_target_functions(*slice_bin, an_res.value(), *disasm, options, 0, is_arm64);
        if (!plan_res) {
            return diagnostics::Result<ProtectionReport>::err(plan_res.error().code, plan_res.error().message, "MachORewriter::protect_file");
        }
        auto plan = std::move(plan_res.value());

        std::vector<BvmProgram> progs;
        progs.reserve(plan.prepared.size());
        for (const auto& pf : plan.prepared) {
            progs.push_back(pf.program);
        }

        SharedRuntimeLayout rt_layout;
        detail::SharedRuntimeOptions rt_opts;
        rt_opts.encrypt_bytecode = options.encrypt_bytecode || (options.profile == ProtectionProfile::Maximum);
        rt_opts.seed = options.seed;

        auto rt_res = is_arm64
            ? emit_shared_pic_arm64_vm_runtime(progs, rt_layout, rt_opts)
            : emit_shared_pic_x64_vm_runtime(progs, AbiKind::SysV_AMD64, rt_layout, rt_opts);
        if (!rt_res) {
            return diagnostics::Result<ProtectionReport>::err(rt_res.error().code, rt_res.error().message, "MachORewriter::protect_file");
        }

        std::vector<std::uint8_t> runtime_bytes = rt_res.value();
        std::size_t effective_rt_size = runtime_bytes.size();
        runtime_bytes.resize(static_cast<std::size_t>(align_up(runtime_bytes.size(), 0x1000)), 0);

        // Validate ALL patch locations BEFORE mutating __TEXT,__text or adding segments
        LIEF::MachO::Section* text_sec = macho->get_section("__TEXT", "__text");
        if (!text_sec) {
            return diagnostics::Result<ProtectionReport>::err(ErrorCode::ParseError, "Mach-O missing __TEXT,__text", "MachORewriter::protect_file");
        }
        std::vector<std::size_t> patch_offsets;
        patch_offsets.reserve(plan.prepared.size());
        for (const auto& pf : plan.prepared) {
            if (pf.entry_va < text_sec->virtual_address() ||
                pf.entry_va + min_patch > text_sec->virtual_address() + text_sec->content().size()) {
                return diagnostics::Result<ProtectionReport>::err(
                    ErrorCode::OutOfBounds, "Target VA outside __text: " + pf.name, "MachORewriter::protect_file");
            }
            patch_offsets.push_back(static_cast<std::size_t>(pf.entry_va - text_sec->virtual_address()));
        }

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

        if (options.allow_external_calls) {
            auto plan2_res = prepare_target_functions(*slice_bin, an_res.value(), *disasm, options, stub_va, is_arm64);
            if (!plan2_res) {
                return diagnostics::Result<ProtectionReport>::err(plan2_res.error().code, plan2_res.error().message, "MachORewriter::protect_file");
            }
            plan = std::move(plan2_res.value());
            progs.clear();
            for (const auto& pf : plan.prepared) {
                progs.push_back(pf.program);
            }
            auto rt2 = is_arm64
                ? emit_shared_pic_arm64_vm_runtime(progs, rt_layout, rt_opts)
                : emit_shared_pic_x64_vm_runtime(progs, AbiKind::SysV_AMD64, rt_layout, rt_opts);
            if (!rt2) {
                return diagnostics::Result<ProtectionReport>::err(rt2.error().code, rt2.error().message, "MachORewriter::protect_file");
            }
            effective_rt_size = rt2.value().size();
            const std::size_t target_sz = std::max<std::size_t>(
                runtime_bytes.size(),
                static_cast<std::size_t>(align_up(rt2.value().size(), 0x1000)));
            runtime_bytes = std::move(rt2.value());
            runtime_bytes.resize(target_sz, 0);
            if (auto* added_bmrt_sec = macho->get_section("__BMRT", "__bmrt")) {
                added_bmrt_sec->content(runtime_bytes);
            }
        }

        // Patch __TEXT,__text transactionally
        auto text_content = std::vector<std::uint8_t>(text_sec->content().begin(), text_sec->content().end());
        for (std::size_t i = 0; i < plan.prepared.size(); ++i) {
            const auto& pf = plan.prepared[i];
            const std::size_t patch_off = patch_offsets[i];
            const std::uint64_t fn_stub_va = stub_va + rt_layout.entry_offsets[i];
            if (is_arm64) {
                const std::int64_t delta = static_cast<std::int64_t>(fn_stub_va) - static_cast<std::int64_t>(pf.entry_va);
                const std::int64_t imm26 = delta >> 2;
                if (imm26 < -(1LL << 25) || imm26 >= (1LL << 25)) {
                    return diagnostics::Result<ProtectionReport>::err(ErrorCode::OutOfBounds, "ARM64 branch target out of 128MB range", "MachORewriter::protect_file");
                }
                const std::uint32_t insn = 0x14000000u | (static_cast<std::uint32_t>(imm26) & 0x03FFFFFFu);
                std::memcpy(text_content.data() + patch_off, &insn, 4);
            } else {
                const std::int64_t rel32 = static_cast<std::int64_t>(fn_stub_va) - static_cast<std::int64_t>(pf.entry_va + 5);
                text_content[patch_off] = 0xE9;
                const std::uint32_t rel32_u = static_cast<std::uint32_t>(static_cast<std::int32_t>(rel32));
                std::memcpy(text_content.data() + patch_off + 1, &rel32_u, 4);
            }
        }
        text_sec->content(text_content);

        // Seal metadata in __BMVM (R--)
        std::vector<std::uint8_t> plaintext;
        for (const auto& pf : plan.prepared) {
            auto bvm_encoded = BvmCodec::encode(pf.program);
            if (!bvm_encoded) {
                return diagnostics::Result<ProtectionReport>::err(bvm_encoded.error().code, bvm_encoded.error().message, "MachORewriter::protect_file");
            }
            plaintext.insert(plaintext.end(), bvm_encoded.value().begin(), bvm_encoded.value().end());
        }
        std::uint32_t str_cnt = 0;
        if (options.protect_strings) {
            if (const auto* cstring = macho->get_section("__TEXT", "__cstring")) {
                auto strs = collect_printable_strings(cstring->content(), str_cnt);
                plaintext.insert(plaintext.end(), strs.begin(), strs.end());
            }
        }

        ProtectionMetadata meta;
        meta.profile = options.profile;
        meta.bytecode_mode = options.bytecode_mode;
        meta.seed = options.seed;
        meta.bytecode_encrypted = rt_opts.encrypt_bytecode;
        meta.text_blake2b = CryptoAead::blake2b_256(text_content);
        meta.runtime_blake2b = CryptoAead::blake2b_256(runtime_bytes);
        if (options.bytecode_mode == BytecodeMode::Lazy) {
            auto rt_key = CryptoAead::derive_key_from_seed(rt_opts.seed, rt_opts.key_domain);
            for (std::size_t i = 0; i < progs.size(); ++i) {
                auto sealed_fn = LazyBytecodeEngine::seal_function(
                    progs[i], rt_key, options.seed, static_cast<std::uint32_t>(i));
                if (!sealed_fn) {
                    CryptoAead::secure_wipe(rt_key.bytes);
                    return diagnostics::Result<ProtectionReport>::err(
                        sealed_fn.error().code, sealed_fn.error().message, "MachORewriter::protect_file");
                }
                for (auto& blk : sealed_fn.value().blocks) {
                    meta.lazy_blocks.push_back(std::move(blk));
                }
            }
            CryptoAead::secure_wipe(rt_key.bytes);
        }
        meta.protected_strings_count = str_cnt;
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
        for (std::size_t i = 0; i < plan.prepared.size(); ++i) {
            const auto& pf = plan.prepared[i];
            const std::uint64_t fn_stub_va = stub_va + rt_layout.entry_offsets[i];
            meta.functions.push_back(ProtectedFunctionRecord{
                pf.name,
                pf.entry_va - slice_bin->info().image_base,
                fn_stub_va - slice_bin->info().image_base,
                static_cast<std::uint32_t>(min_patch),
                pf.orig_ir_ops,
                pf.obf_ir_ops,
                static_cast<std::uint32_t>(pf.program.instructions.size())
            });
        }

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

        rep.total_functions_analyzed += plan.total_analyzed;
        rep.eligible_functions_count += plan.eligible_count;
        rep.rejected_functions.insert(rep.rejected_functions.end(),
                                      plan.rejected.begin(),
                                      plan.rejected.end());
        rep.protected_functions.insert(rep.protected_functions.end(),
                                       meta.functions.begin(),
                                       meta.functions.end());
        rep.protected_strings_count += meta.protected_strings_count;
        rep.runtime_bytes_size += effective_rt_size;
    }

    const auto tmp_path = std::filesystem::path(output.string() + ".tmp");
    try {
        fat->write(tmp_path.string());
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

    const auto t_end = std::chrono::steady_clock::now();
    std::error_code ec;
    rep.output_size = std::filesystem::file_size(output, ec);
    rep.transform_time_ms = std::chrono::duration<double, std::milli>(t_end - t_start).count();
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

    VerifyReport rep;
    rep.text_integrity_ok = true;
    rep.runtime_integrity_ok = true;
    rep.aead_authenticated = true;

    for (std::size_t s = 0; s < fat->size(); ++s) {
        const LIEF::MachO::Binary* macho = fat->at(s);
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

        const auto cur_text = CryptoAead::blake2b_256(text->content());
        const auto cur_rt = CryptoAead::blake2b_256(bmrt->content());
        const bool slice_text_ok = (cur_text == meta_res.value().text_blake2b);
        const bool slice_rt_ok = (cur_rt == meta_res.value().runtime_blake2b);

        const auto key = CryptoAead::derive_key_from_seed(meta_res.value().seed, "ByteMorph-v0.5-MachO");
        std::vector<std::uint8_t> aad;
        aad.insert(aad.end(), cur_text.begin(), cur_text.end());
        aad.insert(aad.end(), cur_rt.begin(), cur_rt.end());
        const bool slice_aead_ok = CryptoAead::open(meta_res.value().sealed_payload, aad, key).has_value();
        bool slice_blocks_ok = true;
        if (slice_aead_ok && meta_res.value().bytecode_mode == BytecodeMode::Lazy) {
            auto rt_key = CryptoAead::derive_key_from_seed(meta_res.value().seed, "ByteMorph-v0.10-Runtime");
            for (const auto& lb : meta_res.value().lazy_blocks) {
                if (!LazyBytecodeEngine::verify_block_aead(lb, rt_key)) {
                    slice_blocks_ok = false;
                    break;
                }
                ++rep.blocks_verified_count;
            }
            CryptoAead::secure_wipe(rt_key.bytes);
        }

        rep.text_integrity_ok = rep.text_integrity_ok && slice_text_ok;
        rep.runtime_integrity_ok = rep.runtime_integrity_ok && slice_rt_ok;
        rep.aead_authenticated = rep.aead_authenticated && slice_aead_ok && slice_blocks_ok;

        if (s == 0) {
            rep.metadata = std::move(meta_res.value());
        } else {
            rep.metadata.functions.insert(rep.metadata.functions.end(),
                                          meta_res.value().functions.begin(),
                                          meta_res.value().functions.end());
        }
    }

    rep.valid = rep.text_integrity_ok && rep.runtime_integrity_ok && rep.aead_authenticated;
    rep.summary = rep.valid
        ? (fat->size() > 1 ? "Universal Mach-O integrity and AEAD authentication verified across all slices"
                            : "Mach-O integrity and AEAD authentication verified")
        : "Tampering detected";
    return rep;
}

} // namespace bytemorph::prot
