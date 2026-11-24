#include "bytemorph/prot/pe_rewriter.hpp"

#include "bytemorph/arch/aarch64/aarch64_disasm.hpp"
#include "bytemorph/arch/aarch64/aarch64_lifter.hpp"
#include "bytemorph/arch/x86_64/x86_64_disasm.hpp"
#include "bytemorph/arch/x86_64/x86_64_lifter.hpp"
#include "bytemorph/core/analysis/analyzer.hpp"
#include "bytemorph/core/binary/loader.hpp"
#include "bytemorph/formats/elf/elf_parser.hpp"
#include "bytemorph/obf/obfuscation_engine.hpp"
#include "bytemorph/prot/native_vm_emitter.hpp"
#include "bytemorph/virt/bvm_format.hpp"
#include "bytemorph/virt/ir_to_vm.hpp"

#include <LIEF/ELF.hpp>

#include <chrono>
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

bool ElfRewriter::supports(BinaryFormat fmt, Architecture arch) const noexcept {
    return fmt == BinaryFormat::ELF64 && (arch == Architecture::X86_64 || arch == Architecture::ARM64);
}

diagnostics::Result<ProtectionReport>
ElfRewriter::protect_file(const std::filesystem::path& input,
                          const std::filesystem::path& output,
                          const ProtectOptions& options) const {
    using diagnostics::ErrorCode;
    const auto t_start = std::chrono::steady_clock::now();

    BinaryLoader loader;
    loader.register_parser(std::make_unique<formats::elf::ElfParser>());
    auto bin_res = loader.load_file(input);
    if (!bin_res) {
        return diagnostics::Result<ProtectionReport>::err(
            bin_res.error().code, bin_res.error().message, "ElfRewriter::protect_file");
    }

    const auto& bin = *bin_res.value();
    if (bin.info().format != BinaryFormat::ELF64) {
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::UnsupportedFormat, "ElfRewriter supports ELF64 only", "ElfRewriter::protect_file");
    }
    if (bin.info().architecture != Architecture::X86_64 && bin.info().architecture != Architecture::ARM64) {
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::UnsupportedArchitecture, "Unsupported ELF64 architecture", "ElfRewriter::protect_file");
    }
    const bool is_arm64 = (bin.info().architecture == Architecture::ARM64);
    const std::size_t min_patch = is_arm64 ? 4 : 5;

    std::unique_ptr<LIEF::ELF::Binary> elf;
    try {
        elf = LIEF::ELF::Parser::parse(input.string());
    } catch (const std::exception& ex) {
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::ParseError, std::string("LIEF ELF parse failed: ") + ex.what(), "ElfRewriter::protect_file");
    }
    if (!elf) {
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::ParseError, "Failed to parse ELF64 binary", "ElfRewriter::protect_file");
    }

    arch::x86_64::X86_64Disassembler x64_disasm;
    arch::aarch64::AArch64Disassembler a64_disasm;
    IDisassemblerEngine& disasm = is_arm64 ? static_cast<IDisassemblerEngine&>(a64_disasm)
                                           : static_cast<IDisassemblerEngine&>(x64_disasm);
    BinaryAnalyzer analyzer;
    auto an_res = analyzer.analyze(bin, disasm);
    if (!an_res) {
        return diagnostics::Result<ProtectionReport>::err(an_res.error().code, an_res.error().message, "ElfRewriter::protect_file");
    }

    auto plan_res = prepare_target_functions(bin, an_res.value(), disasm, options, 0, is_arm64);
    if (!plan_res) {
        return diagnostics::Result<ProtectionReport>::err(plan_res.error().code, plan_res.error().message, "ElfRewriter::protect_file");
    }
    auto plan = std::move(plan_res.value());

    std::vector<BvmProgram> progs;
    progs.reserve(plan.prepared.size());
    for (const auto& pf : plan.prepared) {
        progs.push_back(pf.program);
    }

    SharedRuntimeLayout rt_layout;
    auto rt_res = is_arm64 ? emit_shared_pic_arm64_vm_runtime(progs, rt_layout)
                           : emit_shared_pic_x64_vm_runtime(progs, AbiKind::SysV_AMD64, rt_layout);
    if (!rt_res) {
        return diagnostics::Result<ProtectionReport>::err(rt_res.error().code, rt_res.error().message, "ElfRewriter::protect_file");
    }

    std::vector<std::uint8_t> runtime_bytes = rt_res.value();
    const std::size_t raw_rt_size = runtime_bytes.size();
    runtime_bytes.resize(static_cast<std::size_t>(align_up(runtime_bytes.size(), 0x1000)), 0);

    LIEF::ELF::Section* text_sec_pre = elf->get_section(".text");
    if (!text_sec_pre) {
        return diagnostics::Result<ProtectionReport>::err(ErrorCode::ParseError, "ELF missing .text section", "ElfRewriter::protect_file");
    }
    std::vector<std::size_t> patch_offsets;
    patch_offsets.reserve(plan.prepared.size());
    for (const auto& pf : plan.prepared) {
        if (pf.entry_va < text_sec_pre->virtual_address() ||
            pf.entry_va + min_patch > text_sec_pre->virtual_address() + text_sec_pre->content().size()) {
            return diagnostics::Result<ProtectionReport>::err(
                ErrorCode::OutOfBounds, "Target VA outside .text: " + pf.name, "ElfRewriter::protect_file");
        }
        patch_offsets.push_back(static_cast<std::size_t>(pf.entry_va - text_sec_pre->virtual_address()));
    }

    LIEF::ELF::Section bmrt_sec(".bmrt", LIEF::ELF::Section::TYPE::PROGBITS);
    bmrt_sec.add(LIEF::ELF::Section::FLAGS::ALLOC);
    bmrt_sec.add(LIEF::ELF::Section::FLAGS::EXECINSTR);
    bmrt_sec.alignment(16);
    bmrt_sec.content(runtime_bytes);

    LIEF::ELF::Section* added_bmrt = elf->add(bmrt_sec, true);
    if (!added_bmrt) {
        return diagnostics::Result<ProtectionReport>::err(ErrorCode::InternalError, "Failed to add .bmrt ELF section", "ElfRewriter::protect_file");
    }
    if (added_bmrt->size() > runtime_bytes.size()) {
        runtime_bytes.resize(static_cast<std::size_t>(added_bmrt->size()), 0);
        added_bmrt->content(runtime_bytes);
    }

    // Re-translate with exact stub_base_va if external calls are enabled,
    // then re-add .bmrt on a fresh LIEF::ELF::Binary so PT_LOAD segment content matches .bmrt section.
    std::size_t effective_rt_size = raw_rt_size;
    if (options.allow_external_calls) {
        const std::uint64_t bmrt_va = added_bmrt->virtual_address();
        const std::size_t prev_rt_size = static_cast<std::size_t>(added_bmrt->size());
        auto plan2_res = prepare_target_functions(
            bin, an_res.value(), disasm, options, bmrt_va, is_arm64);
        if (!plan2_res) {
            return diagnostics::Result<ProtectionReport>::err(plan2_res.error().code, plan2_res.error().message, "ElfRewriter::protect_file");
        }
        plan = std::move(plan2_res.value());
        progs.clear();
        for (const auto& pf : plan.prepared) {
            progs.push_back(pf.program);
        }
        auto rt2 = is_arm64 ? emit_shared_pic_arm64_vm_runtime(progs, rt_layout)
                            : emit_shared_pic_x64_vm_runtime(progs, AbiKind::SysV_AMD64, rt_layout);
        if (!rt2) {
            return diagnostics::Result<ProtectionReport>::err(rt2.error().code, rt2.error().message, "ElfRewriter::protect_file");
        }
        effective_rt_size = rt2.value().size();
        const std::size_t target_rt_size = std::max<std::size_t>(
            static_cast<std::size_t>(align_up(rt2.value().size(), 0x1000)),
            prev_rt_size);
        runtime_bytes = std::move(rt2.value());
        runtime_bytes.resize(target_rt_size, 0);

        elf = LIEF::ELF::Parser::parse(input.string());
        if (!elf) {
            return diagnostics::Result<ProtectionReport>::err(ErrorCode::ParseError, "Failed to re-parse ELF64 binary", "ElfRewriter::protect_file");
        }
        LIEF::ELF::Section bmrt_sec2(".bmrt", LIEF::ELF::Section::TYPE::PROGBITS);
        bmrt_sec2.add(LIEF::ELF::Section::FLAGS::ALLOC);
        bmrt_sec2.add(LIEF::ELF::Section::FLAGS::EXECINSTR);
        bmrt_sec2.alignment(16);
        bmrt_sec2.content(runtime_bytes);
        added_bmrt = elf->add(bmrt_sec2, true);
        if (!added_bmrt) {
            return diagnostics::Result<ProtectionReport>::err(ErrorCode::InternalError, "Failed to re-add .bmrt ELF section", "ElfRewriter::protect_file");
        }
        if (added_bmrt->size() > runtime_bytes.size()) {
            runtime_bytes.resize(static_cast<std::size_t>(added_bmrt->size()), 0);
        }
    } else {
        runtime_bytes.assign(added_bmrt->content().begin(), added_bmrt->content().end());
    }

    LIEF::ELF::Section* text_sec = elf->get_section(".text");
    if (!text_sec) {
        return diagnostics::Result<ProtectionReport>::err(ErrorCode::OutOfBounds, "Missing .text after segment add", "ElfRewriter::protect_file");
    }
    auto text_content = std::vector<std::uint8_t>(text_sec->content().begin(), text_sec->content().end());
    for (std::size_t i = 0; i < plan.prepared.size(); ++i) {
        const std::size_t patch_off = patch_offsets[i];
        if (patch_off + min_patch > text_content.size()) {
            return diagnostics::Result<ProtectionReport>::err(
                ErrorCode::OutOfBounds, "Target VA outside .text after segment add: " + plan.prepared[i].name, "ElfRewriter::protect_file");
        }
        const std::uint64_t patched_va = text_sec->virtual_address() + patch_off;
        const std::uint64_t fn_stub_va = added_bmrt->virtual_address() + rt_layout.entry_offsets[i];
        if (is_arm64) {
            const std::int64_t delta = static_cast<std::int64_t>(fn_stub_va) - static_cast<std::int64_t>(patched_va);
            const std::int64_t imm26 = delta >> 2;
            if (imm26 < -(1LL << 25) || imm26 >= (1LL << 25)) {
                return diagnostics::Result<ProtectionReport>::err(ErrorCode::OutOfBounds, "ARM64 branch target out of 128MB range", "ElfRewriter::protect_file");
            }
            const std::uint32_t insn = 0x14000000u | (static_cast<std::uint32_t>(imm26) & 0x03FFFFFFu);
            std::memcpy(text_content.data() + patch_off, &insn, 4);
        } else {
            const std::int64_t rel32 = static_cast<std::int64_t>(fn_stub_va) - static_cast<std::int64_t>(patched_va + 5);
            text_content[patch_off] = 0xE9;
            const std::uint32_t rel32_u = static_cast<std::uint32_t>(static_cast<std::int32_t>(rel32));
            std::memcpy(text_content.data() + patch_off + 1, &rel32_u, 4);
        }
    }
    text_sec->content(text_content);

    std::vector<std::uint8_t> plaintext;
    for (const auto& pf : plan.prepared) {
        auto bvm_encoded = BvmCodec::encode(pf.program);
        if (!bvm_encoded) {
            return diagnostics::Result<ProtectionReport>::err(bvm_encoded.error().code, bvm_encoded.error().message, "ElfRewriter::protect_file");
        }
        plaintext.insert(plaintext.end(), bvm_encoded.value().begin(), bvm_encoded.value().end());
    }
    std::uint32_t str_cnt = 0;
    if (options.protect_strings) {
        if (const auto* rodata = elf->get_section(".rodata")) {
            auto strs = collect_printable_strings(rodata->content(), str_cnt);
            plaintext.insert(plaintext.end(), strs.begin(), strs.end());
        }
    }

    ProtectionMetadata meta;
    meta.profile = options.profile;
    meta.seed = options.seed;
    meta.text_blake2b = CryptoAead::blake2b_256(text_content);
    meta.runtime_blake2b = CryptoAead::blake2b_256(runtime_bytes);
    meta.protected_strings_count = str_cnt;
    for (std::size_t i = 0; i < plan.prepared.size(); ++i) {
        const auto& pf = plan.prepared[i];
        const std::uint64_t fn_stub_va = added_bmrt->virtual_address() + rt_layout.entry_offsets[i];
        meta.functions.push_back(ProtectedFunctionRecord{
            pf.name,
            pf.entry_va - bin.info().image_base,
            fn_stub_va - bin.info().image_base,
            static_cast<std::uint32_t>(min_patch),
            pf.orig_ir_ops,
            pf.obf_ir_ops,
            static_cast<std::uint32_t>(pf.program.instructions.size())
        });
    }

    const auto key = CryptoAead::derive_key_from_seed(options.seed, "ByteMorph-v0.5-ELF");
    const auto nonce = CryptoAead::generate_nonce(options.seed, 1);
    std::vector<std::uint8_t> aad;
    aad.insert(aad.end(), meta.text_blake2b.begin(), meta.text_blake2b.end());
    aad.insert(aad.end(), meta.runtime_blake2b.begin(), meta.runtime_blake2b.end());

    auto sealed = CryptoAead::seal(plaintext, aad, key, nonce);
    if (!sealed) {
        return diagnostics::Result<ProtectionReport>::err(sealed.error().code, sealed.error().message, "ElfRewriter::protect_file");
    }
    meta.sealed_payload = std::move(sealed.value());

    const auto bmvm_bytes = serialize_metadata(meta);
    LIEF::ELF::Section bmvm_sec(".bmvm", LIEF::ELF::Section::TYPE::PROGBITS);
    bmvm_sec.add(LIEF::ELF::Section::FLAGS::ALLOC);
    bmvm_sec.alignment(16);
    bmvm_sec.content(bmvm_bytes);
    if (!elf->add(bmvm_sec, true)) {
        return diagnostics::Result<ProtectionReport>::err(ErrorCode::InternalError, "Failed to add .bmvm ELF section", "ElfRewriter::protect_file");
    }

    const auto tmp_path = std::filesystem::path(output.string() + ".tmp");
    try {
        elf->write(tmp_path.string());
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
            ErrorCode::IoError, std::string("LIEF ELF write failed: ") + ex.what(), "ElfRewriter::protect_file");
    }

    auto ver = verify_file(output);
    if (!ver) {
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::ParseError,
            "Post-protection ELF verify error: " + ver.error().message,
            "ElfRewriter::protect_file");
    }
    if (!ver.value().valid) {
        return diagnostics::Result<ProtectionReport>::err(
            ErrorCode::ParseError,
            "Post-protection ELF verification failed (text=" +
                std::string(ver.value().text_integrity_ok ? "ok" : "bad") +
                ", rt=" + std::string(ver.value().runtime_integrity_ok ? "ok" : "bad") +
                ", aead=" + std::string(ver.value().aead_authenticated ? "ok" : "bad") +
                ", rt_orig=" + std::to_string(runtime_bytes.size()) +
                ", " + ver.value().summary + ")",
            "ElfRewriter::protect_file");
    }

    const auto t_end = std::chrono::steady_clock::now();
    const double elapsed_ms = std::chrono::duration<double, std::milli>(t_end - t_start).count();

    std::error_code ec;
    ProtectionReport rep;
    rep.format = BinaryFormat::ELF64;
    rep.architecture = bin.info().architecture;
    rep.profile = options.profile;
    rep.seed = options.seed;
    rep.input_size = bin.info().file_size;
    rep.output_size = std::filesystem::file_size(output, ec);
    rep.protected_functions = meta.functions;
    rep.protected_strings_count = meta.protected_strings_count;
    rep.aslr_preserved = bin.info().is_pie;
    rep.dep_preserved = bin.info().has_nx;
    rep.total_functions_analyzed = plan.total_analyzed;
    rep.eligible_functions_count = plan.eligible_count;
    rep.rejected_functions = std::move(plan.rejected);
    rep.transform_time_ms = elapsed_ms;
    rep.shared_runtime_used = true;
    rep.runtime_bytes_size = effective_rt_size;
    return rep;
}

diagnostics::Result<VerifyReport>
ElfRewriter::verify_file(const std::filesystem::path& path) const {
    using diagnostics::ErrorCode;
    std::unique_ptr<LIEF::ELF::Binary> elf;
    try {
        elf = LIEF::ELF::Parser::parse(path.string());
    } catch (const std::exception& ex) {
        return diagnostics::Result<VerifyReport>::err(
            ErrorCode::ParseError, std::string("ELF parse error: ") + ex.what(), "ElfRewriter::verify_file");
    }
    if (!elf) {
        return diagnostics::Result<VerifyReport>::err(ErrorCode::ParseError, "Invalid ELF file", "ElfRewriter::verify_file");
    }

    const auto* bmvm = elf->get_section(".bmvm");
    const auto* bmrt = elf->get_section(".bmrt");
    const auto* text = elf->get_section(".text");
    if (!bmvm || !bmrt || !text) {
        return diagnostics::Result<VerifyReport>::err(
            ErrorCode::ParseError, "Missing ByteMorph ELF protection sections (.bmvm/.bmrt/.text)", "ElfRewriter::verify_file");
    }

    auto meta_res = deserialize_metadata(bmvm->content());
    if (!meta_res) {
        return diagnostics::Result<VerifyReport>::err(meta_res.error().code, meta_res.error().message, "ElfRewriter::verify_file");
    }

    VerifyReport rep;
    rep.metadata = std::move(meta_res.value());
    const auto cur_text = CryptoAead::blake2b_256(text->content());
    const auto cur_rt = CryptoAead::blake2b_256(bmrt->content());
    rep.text_integrity_ok = (cur_text == rep.metadata.text_blake2b);
    rep.runtime_integrity_ok = (cur_rt == rep.metadata.runtime_blake2b);

    const auto key = CryptoAead::derive_key_from_seed(rep.metadata.seed, "ByteMorph-v0.5-ELF");
    std::vector<std::uint8_t> aad;
    aad.insert(aad.end(), cur_text.begin(), cur_text.end());
    aad.insert(aad.end(), cur_rt.begin(), cur_rt.end());

    rep.aead_authenticated = CryptoAead::open(rep.metadata.sealed_payload, aad, key).has_value();
    rep.valid = rep.text_integrity_ok && rep.runtime_integrity_ok && rep.aead_authenticated;
    rep.summary = rep.valid ? "ELF64 integrity and AEAD authentication verified"
                            : ("Tampering detected (rt_disk=" + std::to_string(bmrt->content().size()) + ")");
    return rep;
}

} // namespace bytemorph::prot
