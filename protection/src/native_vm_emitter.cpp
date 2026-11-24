#include "bytemorph/prot/native_vm_emitter.hpp"

#include "bytemorph/arch/aarch64/aarch64_lifter.hpp"
#include "bytemorph/arch/x86_64/x86_64_lifter.hpp"
#include "bytemorph/obf/obfuscation_engine.hpp"
#include "bytemorph/virt/ir_to_vm.hpp"

#if defined(BYTEMORPH_HAS_ASMJIT)
#include <asmjit/a64.h>
#include <asmjit/x86.h>
#endif

#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace bytemorph::prot::detail {

using namespace bytemorph::core;
using namespace bytemorph::virt;

namespace {

void write_u16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
}

void write_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
}

void write_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
}

void write_str(std::vector<std::uint8_t>& out, const std::string& s) {
    write_u32(out, static_cast<std::uint32_t>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
}

std::uint16_t read_u16(std::span<const std::uint8_t> d, std::size_t off) noexcept {
    return static_cast<std::uint16_t>(d[off]) | (static_cast<std::uint16_t>(d[off + 1]) << 8);
}

std::uint32_t read_u32(std::span<const std::uint8_t> d, std::size_t off) noexcept {
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v |= static_cast<std::uint32_t>(d[off + i]) << (i * 8);
    return v;
}

std::uint64_t read_u64(std::span<const std::uint8_t> d, std::size_t off) noexcept {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(d[off + i]) << (i * 8);
    return v;
}

} // namespace

std::uint64_t align_up(std::uint64_t v, std::uint64_t align) noexcept {
    if (align == 0) return v;
    return (v + align - 1) & ~(align - 1);
}

std::vector<std::uint8_t> serialize_metadata(const ProtectionMetadata& m) {
    std::vector<std::uint8_t> out;
    write_u32(out, ProtectionMetadata::kMagic);
    write_u16(out, ProtectionMetadata::kVersion);
    out.push_back(static_cast<std::uint8_t>(m.profile));
    out.push_back(m.bytecode_encrypted ? 1 : 0);
    write_u64(out, m.seed);
    out.insert(out.end(), m.text_blake2b.begin(), m.text_blake2b.end());
    out.insert(out.end(), m.runtime_blake2b.begin(), m.runtime_blake2b.end());
    out.insert(out.end(), m.sealed_payload.nonce.bytes.begin(), m.sealed_payload.nonce.bytes.end());
    out.insert(out.end(), m.sealed_payload.mac.begin(), m.sealed_payload.mac.end());
    write_u32(out, m.protected_strings_count);
    write_u32(out, static_cast<std::uint32_t>(m.functions.size()));
    for (const auto& f : m.functions) {
        write_str(out, f.name);
        write_u64(out, f.original_rva);
        write_u64(out, f.stub_rva);
        write_u32(out, f.patch_size);
        write_u32(out, f.orig_ir_ops);
        write_u32(out, f.obf_ir_ops);
        write_u32(out, f.vm_ops);
    }
    write_u32(out, static_cast<std::uint32_t>(m.sealed_payload.ciphertext.size()));
    out.insert(out.end(), m.sealed_payload.ciphertext.begin(), m.sealed_payload.ciphertext.end());
    if (m.bytecode_encrypted) {
        write_u32(out, static_cast<std::uint32_t>(m.encrypted_functions.size()));
        for (const auto& ef : m.encrypted_functions) {
            write_u32(out, ef.fn_index);
            out.insert(out.end(), ef.nonce.bytes.begin(), ef.nonce.bytes.end());
            out.insert(out.end(), ef.mac.begin(), ef.mac.end());
            write_u32(out, ef.plaintext_size);
            out.insert(out.end(), ef.aad_hash.begin(), ef.aad_hash.end());
        }
    }
    return out;
}

diagnostics::Result<ProtectionMetadata> deserialize_metadata(std::span<const std::uint8_t> data) {
    using diagnostics::ErrorCode;
    constexpr std::size_t kMinHdr = 4 + 2 + 1 + 1 + 8 + 32 + 32 + 24 + 16 + 4 + 4;
    if (data.size() < kMinHdr) {
        return diagnostics::Result<ProtectionMetadata>::err(
            ErrorCode::TruncatedData, "Protected .bmvm metadata is truncated", "deserialize_metadata");
    }

    if (read_u32(data, 0) != ProtectionMetadata::kMagic) {
        return diagnostics::Result<ProtectionMetadata>::err(
            ErrorCode::InvalidMagic, "Invalid .bmvm protection magic (expected BMP4)", "deserialize_metadata");
    }
    const std::uint16_t meta_ver = read_u16(data, 4);
    if (meta_ver != 1 && meta_ver != ProtectionMetadata::kVersion) {
        return diagnostics::Result<ProtectionMetadata>::err(
            ErrorCode::UnsupportedFormat, "Unsupported BMP4 metadata version", "deserialize_metadata");
    }

    ProtectionMetadata m;
    const std::uint8_t prof = data[6];
    if (prof > 2) {
        return diagnostics::Result<ProtectionMetadata>::err(ErrorCode::ParseError, "Invalid protection profile", "deserialize_metadata");
    }
    m.profile = static_cast<ProtectionProfile>(prof);
    m.bytecode_encrypted = (meta_ver >= 2 && (data[7] & 1) != 0);
    m.seed = read_u64(data, 8);

    std::size_t pos = 16;
    std::memcpy(m.text_blake2b.data(), data.data() + pos, 32); pos += 32;
    std::memcpy(m.runtime_blake2b.data(), data.data() + pos, 32); pos += 32;
    std::memcpy(m.sealed_payload.nonce.bytes.data(), data.data() + pos, 24); pos += 24;
    std::memcpy(m.sealed_payload.mac.data(), data.data() + pos, 16); pos += 16;
    m.protected_strings_count = read_u32(data, pos); pos += 4;
    const std::uint32_t fn_cnt = read_u32(data, pos); pos += 4;
    if (fn_cnt > 1024) {
        return diagnostics::Result<ProtectionMetadata>::err(ErrorCode::OutOfBounds, "Excessive function count in BMP4", "deserialize_metadata");
    }

    for (std::uint32_t i = 0; i < fn_cnt; ++i) {
        if (pos + 4 > data.size()) {
            return diagnostics::Result<ProtectionMetadata>::err(ErrorCode::TruncatedData, "Truncated function record", "deserialize_metadata");
        }
        const std::uint32_t slen = read_u32(data, pos); pos += 4;
        if (slen > 4096 || pos + slen + 32 > data.size()) {
            return diagnostics::Result<ProtectionMetadata>::err(ErrorCode::TruncatedData, "Truncated function record body", "deserialize_metadata");
        }
        ProtectedFunctionRecord rec;
        rec.name.assign(reinterpret_cast<const char*>(data.data() + pos), slen); pos += slen;
        rec.original_rva = read_u64(data, pos); pos += 8;
        rec.stub_rva = read_u64(data, pos); pos += 8;
        rec.patch_size = read_u32(data, pos); pos += 4;
        rec.orig_ir_ops = read_u32(data, pos); pos += 4;
        rec.obf_ir_ops = read_u32(data, pos); pos += 4;
        rec.vm_ops = read_u32(data, pos); pos += 4;
        m.functions.push_back(std::move(rec));
    }

    if (pos + 4 > data.size()) {
        return diagnostics::Result<ProtectionMetadata>::err(ErrorCode::TruncatedData, "Missing ciphertext size", "deserialize_metadata");
    }
    const std::uint32_t ct_size = read_u32(data, pos); pos += 4;
    if (pos + ct_size > data.size()) {
        return diagnostics::Result<ProtectionMetadata>::err(ErrorCode::TruncatedData, "Truncated AEAD ciphertext", "deserialize_metadata");
    }
    m.sealed_payload.ciphertext.assign(data.begin() + static_cast<std::ptrdiff_t>(pos),
                                       data.begin() + static_cast<std::ptrdiff_t>(pos + ct_size));
    pos += ct_size;

    if (m.bytecode_encrypted) {
        if (pos + 4 > data.size()) {
            return diagnostics::Result<ProtectionMetadata>::err(ErrorCode::TruncatedData, "Missing encrypted function count", "deserialize_metadata");
        }
        const std::uint32_t ef_cnt = read_u32(data, pos); pos += 4;
        if (ef_cnt > 1024 || pos + static_cast<std::size_t>(ef_cnt) * 80 > data.size()) {
            return diagnostics::Result<ProtectionMetadata>::err(ErrorCode::TruncatedData, "Truncated encrypted function records", "deserialize_metadata");
        }
        m.encrypted_functions.reserve(ef_cnt);
        for (std::uint32_t i = 0; i < ef_cnt; ++i) {
            EncryptedBytecodeRecord ef;
            ef.fn_index = read_u32(data, pos); pos += 4;
            std::memcpy(ef.nonce.bytes.data(), data.data() + pos, 24); pos += 24;
            std::memcpy(ef.mac.data(), data.data() + pos, 16); pos += 16;
            ef.plaintext_size = read_u32(data, pos); pos += 4;
            std::memcpy(ef.aad_hash.data(), data.data() + pos, 32); pos += 32;
            m.encrypted_functions.push_back(ef);
        }
    }
    return m;
}

std::vector<std::uint8_t> collect_printable_strings(std::span<const std::uint8_t> data, std::uint32_t& out_count) {
    std::vector<std::uint8_t> packed;
    out_count = 0;
    std::string cur;
    for (std::uint8_t b : data) {
        if (b >= 0x20 && b <= 0x7E) {
            cur.push_back(static_cast<char>(b));
        } else {
            if (cur.size() >= 6 && out_count < 64) {
                write_str(packed, cur);
                ++out_count;
            }
            cur.clear();
        }
    }
    return packed;
}

std::unordered_set<std::uint64_t>
build_authorized_call_targets(const core::binary::IBinaryFile& bin,
                              const core::analysis::AnalysisResult& analysis) {
    std::unordered_set<std::uint64_t> targets;
    // 1. All discovered internal functions (calls between protected and non-protected functions)
    for (const auto& fn : analysis.functions) {
        if (fn.entry_va != 0) {
            targets.insert(fn.entry_va);
        }
    }
    // 2. Verified imports (Windows IAT slots / Linux PLT-GOT / macOS stubs)
    for (const auto& imp : bin.imports()) {
        if (imp.address != 0) {
            targets.insert(imp.address);
        }
    }
    // 3. Verified symbols and non-forwarded exports
    for (const auto& sym : bin.symbols()) {
        if (sym.address != 0 && (sym.is_function || sym.is_imported || sym.is_exported)) {
            targets.insert(sym.address);
        }
    }
    for (const auto& exp : bin.exports()) {
        if (!exp.is_forwarded && exp.address != 0) {
            targets.insert(exp.address);
        }
    }
    return targets;
}

namespace {

bool is_crt_stub_name(const std::string& name, bool is_ep) noexcept {
    if (is_ep) return true;
    static const std::unordered_set<std::string> kSkip = {
        "_start", "start", "_init", "_fini", "main", "_main",
        "__libc_csu_init", "__libc_csu_fini", "__do_global_dtors_aux",
        "frame_dummy", "register_tm_clones", "deregister_tm_clones",
        "_dl_relocate_static_pie", "__scrt_common_main_seh", "mainCRTStartup",
        "__security_init_cookie", "__security_check_cookie", "__GSHandlerCheck"
    };
    if (kSkip.contains(name)) return true;
    return name.rfind("__scrt_", 0) == 0 || name.rfind("_RTC_", 0) == 0;
}

bool is_in_import_or_plt_section(const core::binary::IBinaryFile& bin, std::uint64_t va) noexcept {
    for (const auto& sec : bin.sections()) {
        if (sec.virtual_size == 0) continue;
        if (va >= sec.virtual_address && va < sec.virtual_address + sec.virtual_size) {
            if (sec.name == ".plt" || sec.name == ".plt.got" || sec.name == ".plt.sec" ||
                sec.name == ".idata" || sec.name == "__stubs" || sec.name == "__stub_helper" ||
                sec.name == "__got") {
                return true;
            }
        }
    }
    return false;
}

std::optional<std::string> detect_thunk_or_stub(const core::binary::IBinaryFile& bin,
                                                const core::analysis::FunctionInfo& fn) {
    if (is_in_import_or_plt_section(bin, fn.entry_va)) {
        return "Located inside IAT/PLT/GOT or stub section";
    }
    if (fn.name.rfind("__imp_", 0) == 0 || fn.name.rfind("imp.", 0) == 0 ||
        fn.name.rfind("j_", 0) == 0 || fn.name.rfind("plt_", 0) == 0) {
        return "Import thunk or jump-stub symbol prefix";
    }
    if (fn.blocks.empty()) {
        return "Function contains no decoded basic blocks";
    }

    // Collect flat instruction stream from entry block (up to 4 instructions)
    const auto& insns = fn.blocks.front().instructions;
    if (insns.empty()) {
        return "Entry basic block is empty";
    }

    std::size_t idx = 0;
    if (insns[idx].mnemonic == "endbr64" || insns[idx].mnemonic == "endbr32" ||
        insns[idx].mnemonic == "bti" || insns[idx].mnemonic == "nop") {
        ++idx;
    }
    if (idx < insns.size()) {
        const auto& first_real = insns[idx];
        // Direct or indirect jump thunk at entry (e.g. FF 25 jmp [rip+disp], jmp imm, b target)
        if (fn.blocks.size() == 1 && insns.size() <= idx + 1 &&
            first_real.flow == core::analysis::ControlFlowKind::UnconditionalJump) {
            return "Unconditional jump stub / IAT-PLT trampoline (" + first_real.full_text + ")";
        }
        // ARM64 PLT/GOT stub pattern: adrp + ldr/add + br
        if (fn.blocks.size() == 1 && insns.size() <= idx + 3 &&
            first_real.mnemonic == "adrp" &&
            insns.back().flow == core::analysis::ControlFlowKind::UnconditionalJump) {
            return "ARM64 ADRP+BR import/PLT trampoline";
        }
        // Single-instruction return stub (e.g., stubbed out / empty void helper)
        if (fn.blocks.size() == 1 && insns.size() <= idx + 1 &&
            first_real.flow == core::analysis::ControlFlowKind::Return) {
            return "Trivial single-instruction return stub";
        }
    }
    return std::nullopt;
}

bool has_mixed_data_or_padding(const core::analysis::FunctionInfo& fn) noexcept {
    if (fn.blocks.empty()) return true;
    std::size_t total_insns = 0;
    std::size_t padding_or_trap = 0;
    for (const auto& bb : fn.blocks) {
        for (const auto& insn : bb.instructions) {
            ++total_insns;
            if (insn.mnemonic == "int3" || insn.mnemonic == "nop" ||
                insn.mnemonic == "brk" || insn.mnemonic == "ud2" ||
                insn.mnemonic == "hlt") {
                ++padding_or_trap;
            }
        }
    }
    if (total_insns == 0) return true;
    // If all instructions are traps/padding or invalid instructions exist, reject
    return padding_or_trap == total_insns;
}

bool overlaps_another_function(const core::analysis::AnalysisResult& analysis,
                               const core::analysis::FunctionInfo& fn) noexcept {
    if (fn.size_bytes == 0) return false;
    const std::uint64_t end_va = fn.entry_va + fn.size_bytes;
    for (const auto& other : analysis.functions) {
        if (other.entry_va == fn.entry_va || other.size_bytes == 0) continue;
        const std::uint64_t other_end = other.entry_va + other.size_bytes;
        if (fn.entry_va < other_end && other.entry_va < end_va) {
            return true;
        }
    }
    return false;
}

std::optional<std::uint64_t> resolve_symbol_va_by_name(const core::binary::IBinaryFile& bin,
                                                       const std::string& name) {
    for (const auto& exp : bin.exports()) {
        if (!exp.is_forwarded && exp.address != 0 &&
            (exp.name == name || exp.name == ("_" + name))) {
            return exp.address;
        }
    }
    for (const auto& sym : bin.symbols()) {
        if (sym.address != 0 && !sym.is_imported &&
            (sym.name == name || sym.name == ("_" + name))) {
            return sym.address;
        }
    }
    return std::nullopt;
}

} // namespace

FunctionCompatibilityEntry
evaluate_function_eligibility(const core::binary::IBinaryFile& bin,
                              const core::analysis::AnalysisResult& analysis,
                              const core::analysis::FunctionInfo& fn,
                              const std::unordered_set<std::uint64_t>& auth_calls,
                              bool allow_external_calls,
                              bool is_arm64,
                              virt::BvmProgram* out_program,
                              std::uint32_t* out_orig_ir_ops) {
    using namespace core::ir;
    using namespace virt;

    FunctionCompatibilityEntry entry;
    entry.name = fn.name;
    entry.entry_va = fn.entry_va;
    entry.size_bytes = fn.size_bytes;

    const std::size_t min_patch = is_arm64 ? 4 : 5;

    if (is_crt_stub_name(fn.name, fn.from_entry_point)) {
        entry.category = "crt_entrypoint";
        entry.rejection_reason = "Entry point or CRT/startup routine excluded from automatic virtualization";
        return entry;
    }
    if (auto thunk_reason = detect_thunk_or_stub(bin, fn)) {
        entry.category = "iat_plt_thunk";
        entry.rejection_reason = *thunk_reason;
        return entry;
    }
    if (fn.size_bytes < min_patch) {
        entry.category = "too_small";
        entry.rejection_reason = "Function smaller than minimum trampoline patch size (" + std::to_string(min_patch) + " bytes)";
        return entry;
    }
    if (has_mixed_data_or_padding(fn)) {
        entry.category = "mixed_data_or_padding";
        entry.rejection_reason = "Function body consists solely of padding/traps or invalid bytes";
        return entry;
    }
    if (overlaps_another_function(analysis, fn)) {
        entry.category = "overlap";
        entry.rejection_reason = "Function address range overlaps another discovered function";
        return entry;
    }
    if (fn.confidence == core::analysis::AnalysisConfidence::Low) {
        entry.category = "low_confidence";
        entry.rejection_reason = "Partially unknown CFG or invalid instructions in function body";
        return entry;
    }

    // Exception & unwind metadata check (v0.10)
    if (bin.info().format == core::binary::BinaryFormat::PE32Plus) {
        const std::uint64_t fn_rva = (fn.entry_va >= bin.info().image_base)
            ? (fn.entry_va - bin.info().image_base)
            : fn.entry_va;
        for (const auto& sec : bin.sections()) {
            if (sec.name == ".pdata") {
                auto pdata_bytes = bin.read_virtual(sec.virtual_address, std::min<std::uint64_t>(sec.virtual_size, 1 << 20));
                if (pdata_bytes && pdata_bytes.value().size() >= 12) {
                    const auto& buf = pdata_bytes.value();
                    for (std::size_t off = 0; off + 12 <= buf.size(); off += 12) {
                        const std::uint32_t begin_rva = read_u32(buf, off);
                        const std::uint32_t end_rva = read_u32(buf, off + 4);
                        const std::uint32_t unwind_rva = read_u32(buf, off + 8);
                        if (begin_rva == 0 && end_rva == 0) break;
                        if (fn_rva >= begin_rva && fn_rva < end_rva) {
                            entry.has_exception_unwind = true;
                            auto uw = bin.read_virtual(bin.info().image_base + unwind_rva, 4);
                            if (uw && !uw.value().empty()) {
                                const std::uint8_t flags = (uw.value()[0] >> 3) & 0x1F;
                                if ((flags & 0x03u) != 0u) {
                                    entry.exception_detail = "PE .pdata/.xdata active EHANDLER/UHANDLER";
                                    entry.category = "exception_unwind_incompatible";
                                    entry.rejection_reason =
                                        "Function has active PE .pdata/.xdata exception/termination handler (SEH/C++ EH cannot unwind across virtualized frame)";
                                    return entry;
                                }
                            }
                            entry.exception_detail = "PE .pdata standard prolog unwind (no EH handler)";
                            break;
                        }
                    }
                }
                break;
            }
        }
    }

    IrFunction ir_fn = is_arm64
        ? arch::aarch64::AArch64Lifter().lift_function(fn)
        : arch::x86_64::X86_64Lifter().lift_function(fn);

    auto is_valid_global_va = [&](std::uint64_t va) noexcept -> bool {
        for (const auto& sec : bin.sections()) {
            const std::uint64_t span = std::max<std::uint64_t>(sec.virtual_size, sec.raw_size);
            if (span > 0 && va >= sec.virtual_address && va < sec.virtual_address + span) {
                return true;
            }
        }
        return false;
    };

    bool has_return = false;
    for (const auto& bb : ir_fn.blocks) {
        entry.ir_ops += static_cast<std::uint32_t>(bb.instructions.size());
        for (const auto& insn : bb.instructions) {
            if (insn.opcode == IrOpcode::Ret) {
                has_return = true;
            }
            if (insn.opcode == IrOpcode::VMov || insn.opcode == IrOpcode::FAdd ||
                insn.opcode == IrOpcode::FSub || insn.opcode == IrOpcode::FMul ||
                insn.opcode == IrOpcode::FDiv || insn.opcode == IrOpcode::FCmp ||
                (insn.opcode == IrOpcode::Xor && !insn.dsts.empty() && insn.dsts[0].bit_width == 128)) {
                entry.uses_simd = true;
            }
            if (insn.opcode == IrOpcode::Call && !insn.srcs.empty() && insn.srcs[0].kind == IrOperand::Kind::Label) {
                const std::uint64_t call_va = static_cast<std::uint64_t>(insn.srcs[0].imm);
                for (const auto& imp : bin.imports()) {
                    if (imp.address == call_va &&
                        (imp.symbol.find("CxxThrow") != std::string::npos ||
                         imp.symbol.find("__cxa_throw") != std::string::npos ||
                         imp.symbol.find("_Unwind_Resume") != std::string::npos ||
                         imp.symbol.find("objc_exception_throw") != std::string::npos)) {
                        entry.has_exception_unwind = true;
                        entry.exception_detail = "Calls exception throw/unwind API: " + imp.symbol;
                        entry.category = "exception_unwind_incompatible";
                        entry.rejection_reason = "Function invokes exception throw/resume runtime (" + imp.symbol + ")";
                        return entry;
                    }
                }
            }
            if (insn.opcode == IrOpcode::Unknown || insn.opcode == IrOpcode::Syscall) {
                entry.unsupported_instructions.push_back(
                    insn.comment.empty() ? std::string(core::ir::to_string(insn.opcode)) : insn.comment);
            }
            if (insn.opcode == IrOpcode::LeaGlobal) {
                if (insn.srcs.empty() || insn.srcs[0].kind != IrOperand::Kind::Label ||
                    !is_valid_global_va(static_cast<std::uint64_t>(insn.srcs[0].imm))) {
                    entry.category = "rip_relative_or_unresolved_mem";
                    entry.rejection_reason = "RIP/PC-relative global reference points outside mapped binary sections";
                    return entry;
                }
            }
            // Reject unresolved memory operands (resolved __bm_rip_tmp from LeaGlobal is permitted)
            auto has_unresolved_mem = [](const std::vector<IrOperand>& ops) noexcept {
                for (const auto& o : ops) {
                    if (o.kind == IrOperand::Kind::Memory && o.name != "__bm_rip_tmp") return true;
                }
                return false;
            };
            if (has_unresolved_mem(insn.srcs) || has_unresolved_mem(insn.dsts)) {
                entry.category = "rip_relative_or_unresolved_mem";
                entry.rejection_reason = "Contains RIP-relative or unresolved global memory operand";
                return entry;
            }
            // Conservative indirect call/jump check
            if ((insn.opcode == IrOpcode::Call || insn.opcode == IrOpcode::Jump) &&
                !insn.srcs.empty() && insn.srcs[0].kind != IrOperand::Kind::Label) {
                entry.category = "indirect_control_flow";
                entry.rejection_reason = "Conservative rejection: unverified indirect call/jump (" +
                    std::string(core::ir::to_string(insn.opcode)) + ")";
                return entry;
            }
        }
    }

    if (!entry.unsupported_instructions.empty()) {
        entry.category = "unsupported_insn";
        entry.rejection_reason = "Contains unsupported instruction(s): " + entry.unsupported_instructions.front();
        return entry;
    }
    if (!has_return) {
        entry.category = "incomplete_boundaries";
        entry.rejection_reason = "Function has no return path (tail-call or incomplete boundary)";
        return entry;
    }

    TranslateOptions t_opts;
    t_opts.allow_external_calls = allow_external_calls;
    t_opts.authorized_call_targets = auth_calls;
    auto bvm_res = IrToVmTranslator::translate(ir_fn, t_opts);
    if (!bvm_res) {
        entry.category = "vm_translation_rejected";
        entry.rejection_reason = bvm_res.error().message;
        return entry;
    }

    entry.eligible = true;
    entry.category = "eligible";
    entry.vm_ops = static_cast<std::uint32_t>(bvm_res.value().instructions.size());
    entry.estimated_runtime_bytes = static_cast<std::uint32_t>(12 + entry.vm_ops * 12);
    entry.estimated_overhead_pct = (entry.ir_ops > 0)
        ? static_cast<std::uint32_t>((entry.vm_ops * 100u) / entry.ir_ops)
        : 100u;

    if (out_orig_ir_ops) *out_orig_ir_ops = entry.ir_ops;
    if (out_program) *out_program = std::move(bvm_res.value());
    return entry;
}

core::diagnostics::Result<MultiFunctionPlan>
prepare_target_functions(const core::binary::IBinaryFile& bin,
                         const core::analysis::AnalysisResult& analysis,
                         core::analysis::IDisassemblerEngine& disasm,
                         const ProtectOptions& options,
                         std::uint64_t stub_base_va,
                         bool is_arm64) {
    using core::diagnostics::ErrorCode;
    using namespace core::analysis;
    using namespace core::ir;
    using namespace obf;
    using namespace virt;

    const std::size_t min_patch = is_arm64 ? 4 : 5;
    MultiFunctionPlan plan;
    plan.total_analyzed = static_cast<std::uint32_t>(analysis.functions.size());

    const auto auth_calls = options.allow_external_calls
        ? build_authorized_call_targets(bin, analysis)
        : std::unordered_set<std::uint64_t>{};

    auto process_fn = [&](const FunctionInfo& fn) -> core::diagnostics::Result<PreparedFunction> {
        if (fn.size_bytes < min_patch) {
            return core::diagnostics::Result<PreparedFunction>::err(
                ErrorCode::OutOfBounds,
                "Function smaller than minimum trampoline size (" + std::to_string(min_patch) + " bytes)",
                "prepare_target_functions");
        }
        if (fn.confidence == AnalysisConfidence::Low) {
            return core::diagnostics::Result<PreparedFunction>::err(
                ErrorCode::UnsupportedFormat,
                "Partially unknown CFG or invalid instructions in function body",
                "prepare_target_functions");
        }

        IrFunction ir_fn = is_arm64
            ? arch::aarch64::AArch64Lifter().lift_function(fn)
            : arch::x86_64::X86_64Lifter().lift_function(fn);

        std::uint32_t orig_ops = 0;
        for (const auto& bb : ir_fn.blocks) orig_ops += static_cast<std::uint32_t>(bb.instructions.size());

        ObfuscationConfig obf_cfg;
        obf_cfg.seed = options.seed ^ fn.entry_va;
        obf_cfg.enable_substitution = true;
        obf_cfg.enable_mba = (options.profile != ProtectionProfile::Fast);
        obf_cfg.enable_cfg = (options.profile == ProtectionProfile::Maximum);

        auto obf_res = ObfuscationPipeline::obfuscate_function(ir_fn, obf_cfg);
        if (!obf_res) {
            return core::diagnostics::Result<PreparedFunction>::err(
                obf_res.error().code, obf_res.error().message, "prepare_target_functions");
        }

        TranslateOptions t_opts;
        t_opts.build_seed = options.seed ^ fn.entry_va;
        t_opts.allow_external_calls = options.allow_external_calls;
        t_opts.stub_base_va = stub_base_va;
        t_opts.authorized_call_targets = auth_calls;

        auto bvm_res = IrToVmTranslator::translate(ir_fn, t_opts);
        if (!bvm_res) {
            return core::diagnostics::Result<PreparedFunction>::err(
                bvm_res.error().code, bvm_res.error().message, "prepare_target_functions");
        }

        PreparedFunction pf;
        pf.name = fn.name;
        pf.entry_va = fn.entry_va;
        pf.size_bytes = fn.size_bytes;
        pf.orig_ir_ops = orig_ops;
        pf.obf_ir_ops = static_cast<std::uint32_t>(obf_res.value().obfuscated_instructions);
        pf.program = std::move(bvm_res.value());
        return pf;
    };

    const bool explicit_multi = !options.target_function_rvas.empty() || !options.target_function_names.empty();

    if (options.protect_all_eligible) {
        for (const auto& fn : analysis.functions) {
            auto elig = evaluate_function_eligibility(
                bin, analysis, fn, auth_calls, options.allow_external_calls, is_arm64);
            if (!elig.eligible) {
                plan.rejected.push_back(std::move(elig));
                continue;
            }
            auto pf = process_fn(fn);
            if (!pf) {
                elig.eligible = false;
                elig.rejection_reason = pf.error().message;
                plan.rejected.push_back(std::move(elig));
                continue;
            }
            ++plan.eligible_count;
            plan.prepared.push_back(std::move(pf.value()));
        }
    } else if (explicit_multi) {
        struct TargetSpec { std::string name; std::uint64_t va; };
        std::vector<TargetSpec> specs;
        for (const auto rva : options.target_function_rvas) {
            const std::uint64_t va = (rva >= bin.info().image_base && bin.info().image_base != 0)
                ? rva
                : (bin.info().image_base + rva);
            specs.push_back({"fn_0x" + std::to_string(va), va});
        }
        for (const auto& name : options.target_function_names) {
            auto va = resolve_symbol_va_by_name(bin, name);
            if (!va) {
                return core::diagnostics::Result<MultiFunctionPlan>::err(
                    ErrorCode::FileNotFound, "Target function symbol not found: " + name, "prepare_target_functions");
            }
            specs.push_back({name, *va});
        }
        for (const auto& sp : specs) {
            const FunctionInfo* found = nullptr;
            for (const auto& fn : analysis.functions) {
                if (fn.entry_va == sp.va) { found = &fn; break; }
            }
            FunctionInfo adhoc;
            if (!found) {
                auto slice = bin.read_virtual(sp.va, 256);
                if (!slice) {
                    return core::diagnostics::Result<MultiFunctionPlan>::err(
                        slice.error().code, slice.error().message, "prepare_target_functions");
                }
                auto dis = disasm.disassemble(slice.value(), sp.va, 64);
                if (!dis || dis.value().empty()) {
                    return core::diagnostics::Result<MultiFunctionPlan>::err(
                        ErrorCode::DisassemblyError, "Failed to disassemble target function", "prepare_target_functions");
                }
                adhoc.name = sp.name;
                adhoc.entry_va = sp.va;
                BasicBlock bb;
                bb.start_va = sp.va;
                for (const auto& i : dis.value()) {
                    bb.instructions.push_back(i);
                    bb.end_va = i.address + i.bytes.size();
                    adhoc.size_bytes += i.bytes.size();
                    if (i.flow == ControlFlowKind::Return) break;
                }
                adhoc.blocks.push_back(std::move(bb));
                found = &adhoc;
            }
            auto pf = process_fn(*found);
            if (!pf) {
                return core::diagnostics::Result<MultiFunctionPlan>::err(
                    pf.error().code,
                    "Function '" + found->name + "' is not eligible: " + pf.error().message,
                    "prepare_target_functions");
            }
            plan.prepared.push_back(std::move(pf.value()));
        }
    } else {
        // Single target mode (backwards-compatible with v0.4-v0.6)
        std::uint64_t target_va = 0;
        std::string target_name;
        if (options.target_function_rva.has_value()) {
            target_va = bin.info().image_base + *options.target_function_rva;
            target_name = options.target_function_name.empty() ? "target_fn" : options.target_function_name;
        } else if (!options.target_function_name.empty()) {
            auto va = resolve_symbol_va_by_name(bin, options.target_function_name);
            if (!va) {
                return core::diagnostics::Result<MultiFunctionPlan>::err(
                    ErrorCode::FileNotFound, "Target function not found: " + options.target_function_name, "prepare_target_functions");
            }
            target_va = *va;
            target_name = options.target_function_name;
        } else {
            for (const auto& exp : bin.exports()) {
                if (!exp.is_forwarded && exp.address != 0) {
                    target_va = exp.address;
                    target_name = exp.name;
                    break;
                }
            }
            if (target_va == 0) {
                for (const auto& sym : bin.symbols()) {
                    if (sym.is_function && sym.is_exported && sym.address != 0 && !sym.name.empty()) {
                        target_va = sym.address;
                        target_name = sym.name;
                        break;
                    }
                }
            }
            if (target_va == 0) {
                return core::diagnostics::Result<MultiFunctionPlan>::err(
                    ErrorCode::UnsupportedFormat, "No exported target function found; specify --func, --func-rva, or --functions all-eligible", "prepare_target_functions");
            }
        }

        const FunctionInfo* found = nullptr;
        for (const auto& fn : analysis.functions) {
            if (fn.entry_va == target_va) { found = &fn; break; }
        }
        FunctionInfo adhoc;
        if (!found) {
            auto slice = bin.read_virtual(target_va, 256);
            if (!slice) {
                return core::diagnostics::Result<MultiFunctionPlan>::err(
                    slice.error().code, slice.error().message, "prepare_target_functions");
            }
            auto dis = disasm.disassemble(slice.value(), target_va, 64);
            if (!dis || dis.value().empty()) {
                return core::diagnostics::Result<MultiFunctionPlan>::err(
                    ErrorCode::DisassemblyError, "Failed to disassemble target function", "prepare_target_functions");
            }
            adhoc.name = target_name;
            adhoc.entry_va = target_va;
            BasicBlock bb;
            bb.start_va = target_va;
            for (const auto& i : dis.value()) {
                bb.instructions.push_back(i);
                bb.end_va = i.address + i.bytes.size();
                adhoc.size_bytes += i.bytes.size();
                if (i.flow == ControlFlowKind::Return) break;
            }
            adhoc.blocks.push_back(std::move(bb));
            found = &adhoc;
        }
        auto pf = process_fn(*found);
        if (!pf) {
            return core::diagnostics::Result<MultiFunctionPlan>::err(
                pf.error().code, "Function is not eligible for virtualization: " + pf.error().message, "prepare_target_functions");
        }
        plan.prepared.push_back(std::move(pf.value()));
    }

    // Sort and detect overlapping functions
    std::sort(plan.prepared.begin(), plan.prepared.end(),
              [](const PreparedFunction& a, const PreparedFunction& b) { return a.entry_va < b.entry_va; });

    std::vector<PreparedFunction> non_overlapping;
    non_overlapping.reserve(plan.prepared.size());
    for (auto& pf : plan.prepared) {
        if (!non_overlapping.empty()) {
            const auto& prev = non_overlapping.back();
            const std::uint64_t prev_end = prev.entry_va + std::max<std::uint64_t>(prev.size_bytes, min_patch);
            if (pf.entry_va < prev_end) {
                if (!options.protect_all_eligible) {
                    return core::diagnostics::Result<MultiFunctionPlan>::err(
                        ErrorCode::OutOfBounds,
                        "Overlapping target functions detected at 0x" + std::to_string(pf.entry_va),
                        "prepare_target_functions");
                }
                FunctionCompatibilityEntry rej;
                rej.name = pf.name;
                rej.entry_va = pf.entry_va;
                rej.size_bytes = pf.size_bytes;
                rej.rejection_reason = "Overlaps previously selected function";
                plan.rejected.push_back(std::move(rej));
                continue;
            }
        }
        non_overlapping.push_back(std::move(pf));
    }
    plan.prepared = std::move(non_overlapping);
    plan.eligible_count = static_cast<std::uint32_t>(plan.prepared.size());

    if (plan.prepared.empty()) {
        return core::diagnostics::Result<MultiFunctionPlan>::err(
            ErrorCode::UnsupportedFormat, "No eligible functions selected for protection", "prepare_target_functions");
    }

    return plan;
}

#if defined(BYTEMORPH_HAS_ASMJIT)
namespace {

constexpr std::uint32_t kBmbcMagic = 0x43424D42u; // "BMBC"
constexpr std::uint32_t kBmbcVersion = 2u;

// Standalone PIC XChaCha20-Poly1305 AEAD open subroutine for x86-64.
// Inputs: r13 = blob_ptr, r11 = key_ptr (32B), r14 = out_plain_ptr, ecx = max_plain_bytes
// Output: rax = 0 on valid tag & decryption, rax = -1 on tampered/invalid blob
void emit_x64_aead_open_subroutine(asmjit::x86::Assembler& a,
                                   asmjit::Label l_sub,
                                   std::size_t max_plain_bytes) {
    using namespace asmjit;
    a.bind(l_sub);

    Label l_fail = a.new_label();
    Label l_done = a.new_label();
    Label l_chacha_rounds = a.new_label();
    Label l_poly_block = a.new_label();

    // Stack frame (328 bytes -> 16B aligned with retaddr):
    // [rsp + 0..63]    chacha working state[16]
    // [rsp + 64..127]  chacha orig state[16]
    // [rsp + 128..159] subkey[32]
    // [rsp + 160..191] poly_key[32]
    // [rsp + 192..207] tmp_blk[16]
    // [rsp + 208..231] h[3] (24B)
    // [rsp + 232..247] r[2] (16B)
    // [rsp + 248..255] r1_5 (8B)
    // [rsp + 256..271] s[2] (16B)
    // [rsp + 272..279] blob_ptr
    // [rsp + 280..287] out_ptr
    // [rsp + 288..295] ct_len
    // [rsp + 296..303] key_ptr
    a.sub(x86::rsp, 312);
    a.mov(x86::qword_ptr(x86::rsp, 272), x86::r13);
    a.mov(x86::qword_ptr(x86::rsp, 280), x86::r14);
    a.mov(x86::qword_ptr(x86::rsp, 296), x86::r11);

    // Validate header: magic, version, 0 < ct_len <= max_plain_bytes
    a.cmp(x86::dword_ptr(x86::r13, 0), static_cast<int>(kBmbcMagic));
    a.jne(l_fail);
    a.cmp(x86::dword_ptr(x86::r13, 4), static_cast<int>(kBmbcVersion));
    a.jne(l_fail);
    a.mov(x86::eax, x86::dword_ptr(x86::r13, 12));
    a.test(x86::eax, x86::eax);
    a.jz(l_fail);
    a.cmp(x86::eax, static_cast<int>(max_plain_bytes));
    a.ja(l_fail);
    a.mov(x86::qword_ptr(x86::rsp, 288), x86::rax);

    // 1. HChaCha20(subkey, key, nonce[0..15])
    a.mov(x86::dword_ptr(x86::rsp, 0),  0x61707865);
    a.mov(x86::dword_ptr(x86::rsp, 4),  0x3320646E);
    a.mov(x86::dword_ptr(x86::rsp, 8),  0x79622D32);
    a.mov(x86::dword_ptr(x86::rsp, 12), 0x6B206574);
    for (int i = 0; i < 8; ++i) {
        a.mov(x86::eax, x86::dword_ptr(x86::r11, i * 4));
        a.mov(x86::dword_ptr(x86::rsp, 16 + i * 4), x86::eax);
    }
    for (int i = 0; i < 4; ++i) {
        a.mov(x86::eax, x86::dword_ptr(x86::r13, 16 + i * 4));
        a.mov(x86::dword_ptr(x86::rsp, 48 + i * 4), x86::eax);
    }
    a.call(l_chacha_rounds);
    // subkey = state[0..3] || state[12..15]
    for (int i = 0; i < 4; ++i) {
        a.mov(x86::eax, x86::dword_ptr(x86::rsp, i * 4));
        a.mov(x86::dword_ptr(x86::rsp, 128 + i * 4), x86::eax);
        a.mov(x86::eax, x86::dword_ptr(x86::rsp, 48 + i * 4));
        a.mov(x86::dword_ptr(x86::rsp, 144 + i * 4), x86::eax);
    }

    // 2. ChaCha20 block(counter=0, subkey, {0,0,0,0, nonce[16..23]}) -> poly_key[32]
    auto setup_chacha_block = [&](std::uint32_t counter) {
        a.mov(x86::dword_ptr(x86::rsp, 0),  0x61707865);
        a.mov(x86::dword_ptr(x86::rsp, 4),  0x3320646E);
        a.mov(x86::dword_ptr(x86::rsp, 8),  0x79622D32);
        a.mov(x86::dword_ptr(x86::rsp, 12), 0x6B206574);
        for (int i = 0; i < 8; ++i) {
            a.mov(x86::eax, x86::dword_ptr(x86::rsp, 128 + i * 4));
            a.mov(x86::dword_ptr(x86::rsp, 16 + i * 4), x86::eax);
        }
        a.mov(x86::dword_ptr(x86::rsp, 48), static_cast<int>(counter));
        a.mov(x86::dword_ptr(x86::rsp, 52), 0);
        a.mov(x86::rdi, x86::qword_ptr(x86::rsp, 272)); // blob_ptr
        a.mov(x86::eax, x86::dword_ptr(x86::rdi, 32));
        a.mov(x86::dword_ptr(x86::rsp, 56), x86::eax);
        a.mov(x86::eax, x86::dword_ptr(x86::rdi, 36));
        a.mov(x86::dword_ptr(x86::rsp, 60), x86::eax);
        for (int i = 0; i < 8; ++i) {
            a.mov(x86::rax, x86::qword_ptr(x86::rsp, i * 8));
            a.mov(x86::qword_ptr(x86::rsp, 64 + i * 8), x86::rax);
        }
        a.call(l_chacha_rounds);
        for (int i = 0; i < 16; ++i) {
            a.mov(x86::eax, x86::dword_ptr(x86::rsp, 64 + i * 4));
            a.add(x86::dword_ptr(x86::rsp, i * 4), x86::eax);
        }
    };

    setup_chacha_block(0);
    for (int i = 0; i < 4; ++i) {
        a.mov(x86::rax, x86::qword_ptr(x86::rsp, i * 8));
        a.mov(x86::qword_ptr(x86::rsp, 160 + i * 8), x86::rax);
    }

    // 3. Poly1305 init: clamp r0, r1; compute r1_5; load s0, s1; h = 0
    a.mov(x86::rax, 0x0FFFFFFC0FFFFFFFULL);
    a.and_(x86::rax, x86::qword_ptr(x86::rsp, 160));
    a.mov(x86::qword_ptr(x86::rsp, 232), x86::rax);
    a.mov(x86::rax, 0x0FFFFFFC0FFFFFFCULL);
    a.and_(x86::rax, x86::qword_ptr(x86::rsp, 168));
    a.mov(x86::qword_ptr(x86::rsp, 240), x86::rax);
    a.mov(x86::rdx, x86::rax);
    a.shr(x86::rdx, 2);
    a.add(x86::rax, x86::rdx); // r1_5 = (r1 >> 2) * 5
    a.mov(x86::qword_ptr(x86::rsp, 248), x86::rax);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, 176));
    a.mov(x86::qword_ptr(x86::rsp, 256), x86::rax);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, 184));
    a.mov(x86::qword_ptr(x86::rsp, 264), x86::rax);
    a.xor_(x86::eax, x86::eax);
    a.mov(x86::qword_ptr(x86::rsp, 208), x86::rax);
    a.mov(x86::qword_ptr(x86::rsp, 216), x86::rax);
    a.mov(x86::qword_ptr(x86::rsp, 224), x86::rax);

    // Feed AAD (16B at [blob_ptr + 0])
    a.mov(x86::rsi, x86::qword_ptr(x86::rsp, 272));
    a.call(l_poly_block);

    // Feed ciphertext blocks ([blob_ptr + 56], ct_len bytes)
    a.mov(x86::rsi, x86::qword_ptr(x86::rsp, 272));
    a.add(x86::rsi, 56);
    a.mov(x86::rbp, x86::qword_ptr(x86::rsp, 288)); // remaining
    Label l_ct_poly_loop = a.new_label();
    Label l_ct_poly_tail = a.new_label();
    Label l_ct_poly_done = a.new_label();
    a.bind(l_ct_poly_loop);
    a.cmp(x86::rbp, 16);
    a.jb(l_ct_poly_tail);
    a.call(l_poly_block);
    a.add(x86::rsi, 16);
    a.sub(x86::rbp, 16);
    a.jmp(l_ct_poly_loop);

    a.bind(l_ct_poly_tail);
    a.test(x86::rbp, x86::rbp);
    a.jz(l_ct_poly_done);
    a.xor_(x86::eax, x86::eax);
    a.mov(x86::qword_ptr(x86::rsp, 192), x86::rax);
    a.mov(x86::qword_ptr(x86::rsp, 200), x86::rax);
    a.xor_(x86::ecx, x86::ecx);
    Label l_copy_tail = a.new_label();
    a.bind(l_copy_tail);
    a.mov(x86::al, x86::byte_ptr(x86::rsi, x86::rcx));
    a.mov(x86::byte_ptr(x86::rsp, x86::rcx, 0, 192), x86::al);
    a.inc(x86::rcx);
    a.cmp(x86::rcx, x86::rbp);
    a.jb(l_copy_tail);
    a.lea(x86::rsi, x86::ptr(x86::rsp, 192));
    a.call(l_poly_block);

    // Feed lengths block: le64(16) || le64(ct_len)
    a.bind(l_ct_poly_done);
    a.mov(x86::qword_ptr(x86::rsp, 192), 16);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, 288));
    a.mov(x86::qword_ptr(x86::rsp, 200), x86::rax);
    a.lea(x86::rsi, x86::ptr(x86::rsp, 192));
    a.call(l_poly_block);

    // Final Poly1305 reduction + add s + constant-time MAC check
    a.mov(x86::r8, x86::qword_ptr(x86::rsp, 208));
    a.mov(x86::r9, x86::qword_ptr(x86::rsp, 216));
    a.mov(x86::r10, x86::qword_ptr(x86::rsp, 224));
    a.mov(x86::rax, x86::r8);
    a.mov(x86::rdx, x86::r9);
    a.mov(x86::rcx, x86::r10);
    a.add(x86::rax, 5);
    a.adc(x86::rdx, 0);
    a.adc(x86::rcx, 0);
    a.sub(x86::rcx, 4);
    a.cmovnc(x86::r8, x86::rax);
    a.cmovnc(x86::r9, x86::rdx);
    a.add(x86::r8, x86::qword_ptr(x86::rsp, 256));
    a.adc(x86::r9, x86::qword_ptr(x86::rsp, 264));

    a.mov(x86::rdi, x86::qword_ptr(x86::rsp, 272)); // blob_ptr
    a.xor_(x86::r8, x86::qword_ptr(x86::rdi, 40));
    a.xor_(x86::r9, x86::qword_ptr(x86::rdi, 48));
    a.or_(x86::r8, x86::r9);
    a.jnz(l_fail);

    // 4. Tag valid! Decrypt ciphertext with ChaCha20(counter=1..)
    a.mov(x86::rsi, x86::qword_ptr(x86::rsp, 272));
    a.add(x86::rsi, 56);
    a.mov(x86::rdi, x86::qword_ptr(x86::rsp, 280)); // out_ptr
    a.mov(x86::rbp, x86::qword_ptr(x86::rsp, 288)); // remaining
    a.mov(x86::r15d, 1); // block counter = 1
    Label l_dec_loop = a.new_label();
    Label l_dec_done = a.new_label();
    a.bind(l_dec_loop);
    a.test(x86::rbp, x86::rbp);
    a.jz(l_dec_done);
    a.push(x86::rsi);
    a.push(x86::rdi);
    a.mov(x86::dword_ptr(x86::rsp, 16 + 0),  0x61707865);
    a.mov(x86::dword_ptr(x86::rsp, 16 + 4),  0x3320646E);
    a.mov(x86::dword_ptr(x86::rsp, 16 + 8),  0x79622D32);
    a.mov(x86::dword_ptr(x86::rsp, 16 + 12), 0x6B206574);
    for (int i = 0; i < 8; ++i) {
        a.mov(x86::eax, x86::dword_ptr(x86::rsp, 16 + 128 + i * 4));
        a.mov(x86::dword_ptr(x86::rsp, 16 + 16 + i * 4), x86::eax);
    }
    a.mov(x86::dword_ptr(x86::rsp, 16 + 48), x86::r15d);
    a.mov(x86::dword_ptr(x86::rsp, 16 + 52), 0);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, 16 + 272));
    a.mov(x86::ecx, x86::dword_ptr(x86::rax, 32));
    a.mov(x86::dword_ptr(x86::rsp, 16 + 56), x86::ecx);
    a.mov(x86::ecx, x86::dword_ptr(x86::rax, 36));
    a.mov(x86::dword_ptr(x86::rsp, 16 + 60), x86::ecx);
    for (int i = 0; i < 8; ++i) {
        a.mov(x86::rax, x86::qword_ptr(x86::rsp, 16 + i * 8));
        a.mov(x86::qword_ptr(x86::rsp, 16 + 64 + i * 8), x86::rax);
    }
    // Temporarily adjust rsp for l_chacha_rounds? No, l_chacha_rounds reads [rsp+8..71] if called!
    // Better: pop rsi/rdi after? No, use rbx/r12 instead of pushing!
    a.pop(x86::rdi);
    a.pop(x86::rsi);
    a.mov(x86::r12, x86::rsi);
    a.mov(x86::r13, x86::rdi);
    a.call(l_chacha_rounds);
    for (int i = 0; i < 16; ++i) {
        a.mov(x86::eax, x86::dword_ptr(x86::rsp, 64 + i * 4));
        a.add(x86::dword_ptr(x86::rsp, i * 4), x86::eax);
    }
    a.mov(x86::rsi, x86::r12);
    a.mov(x86::rdi, x86::r13);
    a.mov(x86::rcx, x86::rbp);
    a.cmp(x86::rcx, 64);
    Label l_cnt_ok = a.new_label();
    a.jbe(l_cnt_ok);
    a.mov(x86::rcx, 64);
    a.bind(l_cnt_ok);
    a.xor_(x86::edx, x86::edx);
    Label l_xor_byte = a.new_label();
    a.bind(l_xor_byte);
    a.mov(x86::al, x86::byte_ptr(x86::rsi, x86::rdx));
    a.xor_(x86::al, x86::byte_ptr(x86::rsp, x86::rdx));
    a.mov(x86::byte_ptr(x86::rdi, x86::rdx), x86::al);
    a.inc(x86::rdx);
    a.cmp(x86::rdx, x86::rcx);
    a.jb(l_xor_byte);
    a.add(x86::rsi, x86::rcx);
    a.add(x86::rdi, x86::rcx);
    a.sub(x86::rbp, x86::rcx);
    a.inc(x86::r15d);
    a.jmp(l_dec_loop);

    a.bind(l_dec_done);
    a.xor_(x86::eax, x86::eax);
    a.jmp(l_done);

    a.bind(l_fail);
    a.mov(x86::rax, -1);

    a.bind(l_done);
    // Wipe sensitive stack state [rsp + 0..271]
    a.xor_(x86::ecx, x86::ecx);
    for (int i = 0; i < 34; ++i) {
        a.mov(x86::qword_ptr(x86::rsp, i * 8), x86::rcx);
    }
    a.add(x86::rsp, 312);
    a.ret();

    // --- Internal helper: ChaCha20 20 rounds on [rsp + 8 .. rsp + 71] (caller retaddr at [rsp]) ---
    a.bind(l_chacha_rounds);
    auto emit_qr = [&](int ai, int bi, int ci, int di) {
        const int ao = 8 + ai * 4;
        const int bo = 8 + bi * 4;
        const int co = 8 + ci * 4;
        const int do_ = 8 + di * 4;
        a.mov(x86::eax, x86::dword_ptr(x86::rsp, ao));
        a.mov(x86::ebx, x86::dword_ptr(x86::rsp, bo));
        a.mov(x86::ecx, x86::dword_ptr(x86::rsp, co));
        a.mov(x86::edx, x86::dword_ptr(x86::rsp, do_));
        a.add(x86::eax, x86::ebx); a.xor_(x86::edx, x86::eax); a.rol(x86::edx, 16);
        a.add(x86::ecx, x86::edx); a.xor_(x86::ebx, x86::ecx); a.rol(x86::ebx, 12);
        a.add(x86::eax, x86::ebx); a.xor_(x86::edx, x86::eax); a.rol(x86::edx, 8);
        a.add(x86::ecx, x86::edx); a.xor_(x86::ebx, x86::ecx); a.rol(x86::ebx, 7);
        a.mov(x86::dword_ptr(x86::rsp, ao), x86::eax);
        a.mov(x86::dword_ptr(x86::rsp, bo), x86::ebx);
        a.mov(x86::dword_ptr(x86::rsp, co), x86::ecx);
        a.mov(x86::dword_ptr(x86::rsp, do_), x86::edx);
    };
    a.push(x86::r14);
    a.mov(x86::r14d, 10);
    // With extra push r14, state is at [rsp + 16 .. 79] -> adjust? No, use r11d without push!
    a.pop(x86::r14);
    a.mov(x86::r11d, 10);
    Label l_round_loop = a.new_label();
    a.bind(l_round_loop);
    emit_qr(0, 4, 8, 12); emit_qr(1, 5, 9, 13); emit_qr(2, 6, 10, 14); emit_qr(3, 7, 11, 15);
    emit_qr(0, 5, 10, 15); emit_qr(1, 6, 11, 12); emit_qr(2, 7, 8, 13); emit_qr(3, 4, 9, 14);
    a.dec(x86::r11d);
    a.jnz(l_round_loop);
    a.ret();

    // --- Internal helper: Poly1305 16B block at [rsi], state at [rsp + 8 + 208..] ---
    a.bind(l_poly_block);
    a.mov(x86::rax, x86::qword_ptr(x86::rsi, 0));
    a.add(x86::qword_ptr(x86::rsp, 8 + 208), x86::rax);
    a.mov(x86::rax, x86::qword_ptr(x86::rsi, 8));
    a.adc(x86::qword_ptr(x86::rsp, 8 + 216), x86::rax);
    a.adc(x86::qword_ptr(x86::rsp, 8 + 224), 1);

    a.mov(x86::rax, x86::qword_ptr(x86::rsp, 8 + 208));
    a.mul(x86::qword_ptr(x86::rsp, 8 + 232));
    a.mov(x86::r8, x86::rax); a.mov(x86::r9, x86::rdx);

    a.mov(x86::rax, x86::qword_ptr(x86::rsp, 8 + 208));
    a.mul(x86::qword_ptr(x86::rsp, 8 + 240));
    a.mov(x86::r10, x86::rax); a.mov(x86::r11, x86::rdx);

    a.mov(x86::rax, x86::qword_ptr(x86::rsp, 8 + 216));
    a.mul(x86::qword_ptr(x86::rsp, 8 + 232));
    a.add(x86::r10, x86::rax); a.adc(x86::r11, x86::rdx);

    a.mov(x86::rax, x86::qword_ptr(x86::rsp, 8 + 224));
    a.mul(x86::qword_ptr(x86::rsp, 8 + 248));
    a.add(x86::r10, x86::rax); a.adc(x86::r11, x86::rdx);

    a.mov(x86::rax, x86::qword_ptr(x86::rsp, 8 + 216));
    a.mul(x86::qword_ptr(x86::rsp, 8 + 240));
    a.mov(x86::r12, x86::rax); a.mov(x86::r13, x86::rdx);

    a.mov(x86::rax, x86::qword_ptr(x86::rsp, 8 + 224));
    a.mul(x86::qword_ptr(x86::rsp, 8 + 232));
    a.add(x86::r12, x86::rax); a.adc(x86::r13, x86::rdx);

    a.add(x86::r10, x86::r9);  a.adc(x86::r11, 0);
    a.add(x86::r12, x86::r11); a.adc(x86::r13, 0);

    a.mov(x86::rax, x86::r12);
    a.and_(x86::eax, 3);
    a.mov(x86::qword_ptr(x86::rsp, 8 + 224), x86::rax);

    a.shrd(x86::r12, x86::r13, 2);
    a.shr(x86::r13, 2);
    a.mov(x86::rax, x86::r12);
    a.mov(x86::rdx, x86::r13);
    a.shld(x86::rdx, x86::rax, 2);
    a.shl(x86::rax, 2);
    a.add(x86::r12, x86::rax);
    a.adc(x86::r13, x86::rdx);

    a.add(x86::r8, x86::r12);
    a.adc(x86::r10, x86::r13);
    a.adc(x86::qword_ptr(x86::rsp, 8 + 224), 0);
    a.mov(x86::qword_ptr(x86::rsp, 8 + 208), x86::r8);
    a.mov(x86::qword_ptr(x86::rsp, 8 + 216), x86::r10);
    a.ret();
}

} // namespace
#endif

diagnostics::Result<std::vector<std::uint8_t>>
emit_pic_x64_vm_runtime(const BvmProgram& prog, AbiKind abi) {
    SharedRuntimeLayout layout;
    return emit_shared_pic_x64_vm_runtime(std::vector<BvmProgram>{prog}, abi, layout);
}

diagnostics::Result<std::vector<std::uint8_t>>
emit_shared_pic_x64_vm_runtime(const std::vector<BvmProgram>& progs,
                               AbiKind abi,
                               SharedRuntimeLayout& out_layout) {
    return emit_shared_pic_x64_vm_runtime(progs, abi, out_layout, SharedRuntimeOptions{});
}

diagnostics::Result<std::vector<std::uint8_t>>
emit_shared_pic_x64_vm_runtime(const std::vector<BvmProgram>& progs,
                               AbiKind abi,
                               SharedRuntimeLayout& out_layout,
                               const SharedRuntimeOptions& rt_opts) {
#if !defined(BYTEMORPH_HAS_ASMJIT)
    (void)progs;
    (void)abi;
    (void)out_layout;
    (void)rt_opts;
    return diagnostics::Result<std::vector<std::uint8_t>>::err(
        diagnostics::ErrorCode::NotImplemented, "AsmJit is disabled", "emit_shared_pic_x64_vm_runtime");
#else
    if (progs.empty()) {
        return diagnostics::Result<std::vector<std::uint8_t>>::err(
            diagnostics::ErrorCode::EmptyInput, "No BvmPrograms provided", "emit_shared_pic_x64_vm_runtime");
    }

    asmjit::Environment env(asmjit::Arch::kX64);
    asmjit::CodeHolder code;
    code.init(env);
    asmjit::x86::Assembler a(&code);
    using namespace asmjit;

    Label l_entry = a.new_label();
    Label l_core = a.new_label();
    Label l_aead_open = a.new_label();
    Label l_crypto_key = a.new_label();
    Label l_aead_fail = a.new_label();
    std::vector<Label> l_stubs;
    std::vector<Label> l_bytecodes;
    l_stubs.reserve(progs.size());
    l_bytecodes.reserve(progs.size());
    std::size_t max_plain_bytes = 0;
    bool has_simd = false;
    for (std::size_t i = 0; i < progs.size(); ++i) {
        l_stubs.push_back(a.new_label());
        l_bytecodes.push_back(a.new_label());
        const std::size_t pbytes = 4 + progs[i].instructions.size() * 12;
        if (pbytes > max_plain_bytes) max_plain_bytes = pbytes;
        for (const auto& insn : progs[i].instructions) {
            if (insn.opcode >= VmOpcode::VMovReg && insn.opcode <= VmOpcode::VXor) {
                has_simd = true;
            }
        }
    }
    const std::size_t vreg_buf_bytes = has_simd ? 512 : 0;
    const std::size_t plain_buf_bytes = rt_opts.encrypt_bytecode
        ? static_cast<std::size_t>(align_up(std::max<std::size_t>(max_plain_bytes, 64), 16))
        : 0;
    Label l_vm_loop = a.new_label();
    Label l_vm_done = a.new_label();
    Label l_take_branch = a.new_label();

    Label l_op_nop = a.new_label();
    Label l_op_movreg = a.new_label();
    Label l_op_movimm = a.new_label();
    Label l_op_load = a.new_label();
    Label l_op_store = a.new_label();
    Label l_op_add = a.new_label();
    Label l_op_sub = a.new_label();
    Label l_op_mul = a.new_label();
    Label l_op_div = a.new_label();
    Label l_op_and = a.new_label();
    Label l_op_or = a.new_label();
    Label l_op_xor = a.new_label();
    Label l_op_shl = a.new_label();
    Label l_op_shr = a.new_label();
    Label l_op_cmp = a.new_label();
    Label l_op_leapic = a.new_label();
    Label l_op_selectcc = a.new_label();
    Label l_op_setcc = a.new_label();
    Label l_op_jmp = a.new_label();
    Label l_op_jeq = a.new_label();
    Label l_op_jne = a.new_label();
    Label l_op_jlt = a.new_label();
    Label l_op_jle = a.new_label();
    Label l_op_jgt = a.new_label();
    Label l_op_jge = a.new_label();
    Label l_op_ret = a.new_label();
    Label l_op_callext = a.new_label();
    Label l_op_vmov = a.new_label();
    Label l_op_vadd32 = a.new_label(); Label l_op_vadd64 = a.new_label();
    Label l_op_vsub32 = a.new_label(); Label l_op_vsub64 = a.new_label();
    Label l_op_vmul32 = a.new_label(); Label l_op_vmul64 = a.new_label();
    Label l_op_vdiv32 = a.new_label(); Label l_op_vdiv64 = a.new_label();
    Label l_op_vcmp32 = a.new_label(); Label l_op_vcmp64 = a.new_label();
    Label l_op_vload = a.new_label();  Label l_op_vstore = a.new_label();
    Label l_op_vxor = a.new_label();

    a.bind(l_entry);
    for (std::size_t i = 0; i < progs.size(); ++i) {
        a.bind(l_stubs[i]);
        a.lea(x86::r10, x86::ptr(l_bytecodes[i]));
        a.jmp(l_core);
    }

    a.bind(l_core);
    a.push(x86::rbx);
    a.push(x86::rbp);
    a.push(x86::rdi);
    a.push(x86::rsi);
    a.push(x86::r12);
    a.push(x86::r13);
    a.push(x86::r14);
    a.push(x86::r15);
    const std::size_t saved_xmm_bytes = has_simd ? 160 : 0;
    if (has_simd) {
        a.sub(x86::rsp, 160);
        for (int i = 0; i < 10; ++i) {
            a.movups(x86::xmmword_ptr(x86::rsp, i * 16), x86::xmm(6 + i));
        }
    }

    // Preserve bytecode/blob pointer passed from per-function stub in r10
    if (rt_opts.encrypt_bytecode) {
        a.mov(x86::r13, x86::r10);
    } else {
        a.mov(x86::r12d, x86::dword_ptr(x86::r10));
        a.lea(x86::r13, x86::ptr(x86::r10, 4));
    }

    const std::size_t total_frame_bytes = 1288 + vreg_buf_bytes + plain_buf_bytes;
    const std::size_t plain_buf_off = 1288 + vreg_buf_bytes;
    const std::size_t caller_arg_base = 1288 + vreg_buf_bytes + plain_buf_bytes + saved_xmm_bytes + 64;
    // Probe stack guard pages in 4KB steps before touching deep stack on Windows
    if (total_frame_bytes >= 4096) {
        for (std::size_t step = 4096; step <= total_frame_bytes; step += 4096) {
            a.sub(x86::rsp, 4096);
            a.test(x86::qword_ptr(x86::rsp), x86::rax);
        }
        const std::size_t rem = total_frame_bytes % 4096;
        if (rem > 0) a.sub(x86::rsp, static_cast<std::uint32_t>(rem));
    } else {
        a.sub(x86::rsp, static_cast<std::uint32_t>(total_frame_bytes));
    }

    a.xor_(x86::eax, x86::eax);
    a.mov(x86::rdi, x86::rsp);
    a.mov(x86::r10d, 161);
    Label l_zero_loop = a.new_label();
    a.bind(l_zero_loop);
    a.mov(x86::qword_ptr(x86::rdi), x86::rax);
    a.add(x86::rdi, 8);
    a.dec(x86::r10d);
    a.jnz(l_zero_loop);

    // Initialize virtual stack pointer R4 (rsp) and frame pointer R5 (rbp) to [rsp + 896]
    a.lea(x86::rax, x86::ptr(x86::rsp, 896));
    a.mov(x86::qword_ptr(x86::rsp, 4 * 8), x86::rax);
    a.mov(x86::qword_ptr(x86::rsp, 5 * 8), x86::rax);

    // Copy 64B of caller stack arguments / shadow space from [caller_rsp + 8]
    for (int i = 1; i <= 8; ++i) {
        a.mov(x86::r10, x86::qword_ptr(x86::rsp, static_cast<std::int32_t>(caller_arg_base + i * 8)));
        a.mov(x86::qword_ptr(x86::rsp, 896 + i * 8), x86::r10);
    }

    // Restore rdi from saved stack slot for SysV arg0
    if (abi == AbiKind::Win64) {
        a.mov(x86::qword_ptr(x86::rsp, 1 * 8), x86::rcx);
        a.mov(x86::qword_ptr(x86::rsp, 2 * 8), x86::rdx);
        a.mov(x86::qword_ptr(x86::rsp, 8 * 8), x86::r8);
        a.mov(x86::qword_ptr(x86::rsp, 9 * 8), x86::r9);
        if (has_simd) {
            for (int i = 0; i < 4; ++i) {
                a.movups(x86::xmmword_ptr(x86::rsp, 1288 + i * 16), x86::xmm(i));
            }
        }
    } else {
        // System V AMD64: rdi->R7, rsi->R6, rdx->R2, rcx->R1, r8->R8, r9->R9
        a.mov(x86::rax, x86::qword_ptr(x86::rsp, static_cast<std::int32_t>(total_frame_bytes + saved_xmm_bytes + 5 * 8)));
        a.mov(x86::qword_ptr(x86::rsp, 7 * 8), x86::rax);
        a.mov(x86::qword_ptr(x86::rsp, 6 * 8), x86::rsi);
        a.mov(x86::qword_ptr(x86::rsp, 2 * 8), x86::rdx);
        a.mov(x86::qword_ptr(x86::rsp, 1 * 8), x86::rcx);
        a.mov(x86::qword_ptr(x86::rsp, 8 * 8), x86::r8);
        a.mov(x86::qword_ptr(x86::rsp, 9 * 8), x86::r9);
        if (has_simd) {
            for (int i = 0; i < 8; ++i) {
                a.movups(x86::xmmword_ptr(x86::rsp, 1288 + i * 16), x86::xmm(i));
            }
        }
    }

    if (rt_opts.encrypt_bytecode) {
        a.lea(x86::r11, x86::ptr(l_crypto_key));
        a.lea(x86::r14, x86::ptr(x86::rsp, static_cast<std::int32_t>(plain_buf_off)));
        a.call(l_aead_open);
        a.test(x86::rax, x86::rax);
        a.jnz(l_aead_fail);
        a.mov(x86::r12d, x86::dword_ptr(x86::rsp, static_cast<std::int32_t>(plain_buf_off)));
        a.lea(x86::r13, x86::ptr(x86::rsp, static_cast<std::int32_t>(plain_buf_off + 4)));
    }

    a.xor_(x86::r14d, x86::r14d);
    a.xor_(x86::r15d, x86::r15d);

    a.bind(l_vm_loop);
    a.cmp(x86::r14d, x86::r12d);
    a.jae(l_vm_done);

    a.imul(x86::rbx, x86::r14, 12);
    a.add(x86::rbx, x86::r13);

    a.movzx(x86::eax, x86::byte_ptr(x86::rbx, 0));
    a.movzx(x86::ecx, x86::byte_ptr(x86::rbx, 1));
    a.movzx(x86::r8d, x86::byte_ptr(x86::rbx, 2));
    a.movzx(x86::r9d, x86::byte_ptr(x86::rbx, 3));
    a.mov(x86::r11, x86::qword_ptr(x86::rbx, 4));

    a.cmp(x86::eax, static_cast<int>(VmOpcode::Nop));     a.je(l_op_nop);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::MovReg));  a.je(l_op_movreg);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::MovImm));  a.je(l_op_movimm);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Load));    a.je(l_op_load);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Store));   a.je(l_op_store);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Add));     a.je(l_op_add);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Sub));     a.je(l_op_sub);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Mul));     a.je(l_op_mul);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Div));     a.je(l_op_div);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::And));     a.je(l_op_and);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Or));      a.je(l_op_or);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Xor));     a.je(l_op_xor);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Shl));     a.je(l_op_shl);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Shr));     a.je(l_op_shr);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Cmp));      a.je(l_op_cmp);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::LeaPic));   a.je(l_op_leapic);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::SelectCc)); a.je(l_op_selectcc);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::SetCc));    a.je(l_op_setcc);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jmp));      a.je(l_op_jmp);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jeq));     a.je(l_op_jeq);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jne));     a.je(l_op_jne);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jlt));     a.je(l_op_jlt);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jle));     a.je(l_op_jle);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jgt));     a.je(l_op_jgt);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jge));     a.je(l_op_jge);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Ret));     a.je(l_op_ret);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Halt));    a.je(l_op_ret);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::CallExt)); a.je(l_op_callext);
    if (has_simd) {
        a.cmp(x86::eax, static_cast<int>(VmOpcode::VMovReg)); a.je(l_op_vmov);
        a.cmp(x86::eax, static_cast<int>(VmOpcode::VAddF32)); a.je(l_op_vadd32);
        a.cmp(x86::eax, static_cast<int>(VmOpcode::VAddF64)); a.je(l_op_vadd64);
        a.cmp(x86::eax, static_cast<int>(VmOpcode::VSubF32)); a.je(l_op_vsub32);
        a.cmp(x86::eax, static_cast<int>(VmOpcode::VSubF64)); a.je(l_op_vsub64);
        a.cmp(x86::eax, static_cast<int>(VmOpcode::VMulF32)); a.je(l_op_vmul32);
        a.cmp(x86::eax, static_cast<int>(VmOpcode::VMulF64)); a.je(l_op_vmul64);
        a.cmp(x86::eax, static_cast<int>(VmOpcode::VDivF32)); a.je(l_op_vdiv32);
        a.cmp(x86::eax, static_cast<int>(VmOpcode::VDivF64)); a.je(l_op_vdiv64);
        a.cmp(x86::eax, static_cast<int>(VmOpcode::VCmpF32)); a.je(l_op_vcmp32);
        a.cmp(x86::eax, static_cast<int>(VmOpcode::VCmpF64)); a.je(l_op_vcmp64);
        a.cmp(x86::eax, static_cast<int>(VmOpcode::VLoad));   a.je(l_op_vload);
        a.cmp(x86::eax, static_cast<int>(VmOpcode::VStore));  a.je(l_op_vstore);
        a.cmp(x86::eax, static_cast<int>(VmOpcode::VXor));    a.je(l_op_vxor);
    }
    a.jmp(l_vm_done);

    auto emit_update_flags = [&]() {
        a.test(x86::rax, x86::rax);
        a.setz(x86::r15b);
        a.sets(x86::dl);
        a.shl(x86::dl, 1);
        a.or_(x86::r15b, x86::dl);
    };

    a.bind(l_op_nop); a.inc(x86::r14d); a.jmp(l_vm_loop);

    a.bind(l_op_movreg);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    a.inc(x86::r14d); a.jmp(l_vm_loop);

    a.bind(l_op_movimm);
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::r11);
    a.inc(x86::r14d); a.jmp(l_vm_loop);

    // Load: dst=rcx, src1=r8 (base), src2=r9 (width: 8/16/32/64/0), imm=r11 (disp)
    Label l_load_16 = a.new_label();
    Label l_load_32 = a.new_label();
    Label l_load_64 = a.new_label();
    Label l_load_done = a.new_label();
    a.bind(l_op_load);
    a.mov(x86::r10, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.add(x86::r10, x86::r11);
    a.cmp(x86::r10, 0x1000);
    a.jb(l_vm_done);
    a.cmp(x86::r9d, 8);  a.jne(l_load_16);
    a.movzx(x86::eax, x86::byte_ptr(x86::r10));
    a.jmp(l_load_done);
    a.bind(l_load_16);
    a.cmp(x86::r9d, 16); a.jne(l_load_32);
    a.movzx(x86::eax, x86::word_ptr(x86::r10));
    a.jmp(l_load_done);
    a.bind(l_load_32);
    a.cmp(x86::r9d, 32); a.jne(l_load_64);
    a.mov(x86::eax, x86::dword_ptr(x86::r10));
    a.jmp(l_load_done);
    a.bind(l_load_64);
    a.mov(x86::rax, x86::qword_ptr(x86::r10));
    a.bind(l_load_done);
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    a.inc(x86::r14d); a.jmp(l_vm_loop);

    // Store: dst=rcx (base), src1=r8 (val), src2=r9 (width: 8/16/32/64/0), imm=r11 (disp)
    Label l_store_16 = a.new_label();
    Label l_store_32 = a.new_label();
    Label l_store_64 = a.new_label();
    Label l_store_done = a.new_label();
    a.bind(l_op_store);
    a.mov(x86::r10, x86::qword_ptr(x86::rsp, x86::rcx, 3));
    a.add(x86::r10, x86::r11);
    a.cmp(x86::r10, 0x1000);
    a.jb(l_vm_done);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.cmp(x86::r9d, 8);  a.jne(l_store_16);
    a.mov(x86::byte_ptr(x86::r10), x86::al);
    a.jmp(l_store_done);
    a.bind(l_store_16);
    a.cmp(x86::r9d, 16); a.jne(l_store_32);
    a.mov(x86::word_ptr(x86::r10), x86::ax);
    a.jmp(l_store_done);
    a.bind(l_store_32);
    a.cmp(x86::r9d, 32); a.jne(l_store_64);
    a.mov(x86::dword_ptr(x86::r10), x86::eax);
    a.jmp(l_store_done);
    a.bind(l_store_64);
    a.mov(x86::qword_ptr(x86::r10), x86::rax);
    a.bind(l_store_done);
    a.inc(x86::r14d); a.jmp(l_vm_loop);

    a.bind(l_op_add);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.add(x86::rax, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    emit_update_flags(); a.inc(x86::r14d); a.jmp(l_vm_loop);

    a.bind(l_op_sub);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.sub(x86::rax, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    emit_update_flags(); a.inc(x86::r14d); a.jmp(l_vm_loop);

    a.bind(l_op_mul);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.imul(x86::rax, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    emit_update_flags(); a.inc(x86::r14d); a.jmp(l_vm_loop);

    a.bind(l_op_div);
    a.mov(x86::r10, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.test(x86::r10, x86::r10); a.jz(l_vm_done);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.xor_(x86::edx, x86::edx);
    a.div(x86::r10);
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    emit_update_flags(); a.inc(x86::r14d); a.jmp(l_vm_loop);

    a.bind(l_op_and);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.and_(x86::rax, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    emit_update_flags(); a.inc(x86::r14d); a.jmp(l_vm_loop);

    a.bind(l_op_or);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.or_(x86::rax, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    emit_update_flags(); a.inc(x86::r14d); a.jmp(l_vm_loop);

    a.bind(l_op_xor);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.xor_(x86::rax, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    emit_update_flags(); a.inc(x86::r14d); a.jmp(l_vm_loop);

    a.bind(l_op_shl);
    a.mov(x86::r10, x86::rcx);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.mov(x86::rcx, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.shl(x86::rax, x86::cl);
    a.mov(x86::qword_ptr(x86::rsp, x86::r10, 3), x86::rax);
    emit_update_flags(); a.inc(x86::r14d); a.jmp(l_vm_loop);

    a.bind(l_op_shr);
    a.mov(x86::r10, x86::rcx);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.mov(x86::rcx, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.shr(x86::rax, x86::cl);
    a.mov(x86::qword_ptr(x86::rsp, x86::r10, 3), x86::rax);
    emit_update_flags(); a.inc(x86::r14d); a.jmp(l_vm_loop);

    a.bind(l_op_cmp);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.cmp(x86::rax, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.setz(x86::r15b);
    a.sets(x86::dl);
    a.setb(x86::al);
    a.seto(x86::r10b);
    a.and_(x86::r15d, 1);
    a.shl(x86::dl, 1);
    a.or_(x86::r15b, x86::dl);
    a.shl(x86::al, 2);
    a.or_(x86::r15b, x86::al);
    a.shl(x86::r10b, 3);
    a.or_(x86::r15b, x86::r10b);
    a.inc(x86::r14d); a.jmp(l_vm_loop);

    a.bind(l_op_leapic);
    a.lea(x86::rax, x86::ptr(l_entry));
    a.add(x86::rax, x86::r11);
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    a.inc(x86::r14d); a.jmp(l_vm_loop);

    {
        Label l_eval_cc = a.new_label();
        Label l_cc_apply = a.new_label();
        Label l_cc_next = a.new_label();
        Label l_cc_0 = a.new_label(); Label l_cc_1 = a.new_label();
        Label l_cc_2 = a.new_label(); Label l_cc_3 = a.new_label();
        Label l_cc_4 = a.new_label(); Label l_cc_5 = a.new_label();
        Label l_cc_6 = a.new_label(); Label l_cc_7 = a.new_label();
        Label l_cc_8 = a.new_label(); Label l_cc_9 = a.new_label();
        Label l_cc_10 = a.new_label(); Label l_cc_11 = a.new_label();
        Label l_cc_12 = a.new_label(); Label l_cc_13 = a.new_label();

        a.bind(l_op_setcc);
        a.xor_(x86::r10d, x86::r10d);
        a.jmp(l_eval_cc);

        a.bind(l_op_selectcc);
        a.mov(x86::r10d, 1);

        a.bind(l_eval_cc);
        a.xor_(x86::eax, x86::eax);
        a.cmp(x86::r9d, 0);  a.je(l_cc_0);
        a.cmp(x86::r9d, 1);  a.je(l_cc_1);
        a.cmp(x86::r9d, 2);  a.je(l_cc_2);
        a.cmp(x86::r9d, 3);  a.je(l_cc_3);
        a.cmp(x86::r9d, 4);  a.je(l_cc_4);
        a.cmp(x86::r9d, 5);  a.je(l_cc_5);
        a.cmp(x86::r9d, 6);  a.je(l_cc_6);
        a.cmp(x86::r9d, 7);  a.je(l_cc_7);
        a.cmp(x86::r9d, 8);  a.je(l_cc_8);
        a.cmp(x86::r9d, 9);  a.je(l_cc_9);
        a.cmp(x86::r9d, 10); a.je(l_cc_10);
        a.cmp(x86::r9d, 11); a.je(l_cc_11);
        a.cmp(x86::r9d, 12); a.je(l_cc_12);
        a.cmp(x86::r9d, 13); a.je(l_cc_13);
        a.jmp(l_cc_apply);

        a.bind(l_cc_0);  a.test(x86::r15d, 1); a.setnz(x86::al); a.jmp(l_cc_apply);
        a.bind(l_cc_1);  a.test(x86::r15d, 1); a.setz(x86::al);  a.jmp(l_cc_apply);
        a.bind(l_cc_2);  a.mov(x86::edx, x86::r15d); a.shr(x86::edx, 2); a.xor_(x86::edx, x86::r15d); a.test(x86::edx, 2); a.setnz(x86::al); a.jmp(l_cc_apply);
        a.bind(l_cc_3);  a.test(x86::r15d, 1); a.setnz(x86::al); a.jnz(l_cc_apply); a.mov(x86::edx, x86::r15d); a.shr(x86::edx, 2); a.xor_(x86::edx, x86::r15d); a.test(x86::edx, 2); a.setnz(x86::al); a.jmp(l_cc_apply);
        a.bind(l_cc_4);  a.test(x86::r15d, 1); a.jnz(l_cc_apply); a.mov(x86::edx, x86::r15d); a.shr(x86::edx, 2); a.xor_(x86::edx, x86::r15d); a.test(x86::edx, 2); a.setz(x86::al); a.jmp(l_cc_apply);
        a.bind(l_cc_5);  a.mov(x86::edx, x86::r15d); a.shr(x86::edx, 2); a.xor_(x86::edx, x86::r15d); a.test(x86::edx, 2); a.setz(x86::al); a.jmp(l_cc_apply);
        a.bind(l_cc_6);  a.test(x86::r15d, 4); a.setnz(x86::al); a.jmp(l_cc_apply);
        a.bind(l_cc_7);  a.test(x86::r15d, 5); a.setnz(x86::al); a.jmp(l_cc_apply);
        a.bind(l_cc_8);  a.test(x86::r15d, 5); a.setz(x86::al);  a.jmp(l_cc_apply);
        a.bind(l_cc_9);  a.test(x86::r15d, 4); a.setz(x86::al);  a.jmp(l_cc_apply);
        a.bind(l_cc_10); a.test(x86::r15d, 2); a.setnz(x86::al); a.jmp(l_cc_apply);
        a.bind(l_cc_11); a.test(x86::r15d, 2); a.setz(x86::al);  a.jmp(l_cc_apply);
        a.bind(l_cc_12); a.test(x86::r15d, 8); a.setnz(x86::al); a.jmp(l_cc_apply);
        a.bind(l_cc_13); a.test(x86::r15d, 8); a.setz(x86::al);

        a.bind(l_cc_apply);
        a.test(x86::r10d, x86::r10d);
        a.jnz(l_cc_next);
        a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
        a.inc(x86::r14d); a.jmp(l_vm_loop);

        a.bind(l_cc_next);
        Label l_sel_skip = a.new_label();
        a.test(x86::al, x86::al);
        a.jz(l_sel_skip);
        a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
        a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
        a.bind(l_sel_skip);
        a.inc(x86::r14d); a.jmp(l_vm_loop);
    }

    a.bind(l_op_jmp);
    a.bind(l_take_branch);
    a.mov(x86::r14d, x86::r11d);
    a.jmp(l_vm_loop);

    a.bind(l_op_jeq); a.test(x86::r15d, 1); a.jnz(l_take_branch); a.inc(x86::r14d); a.jmp(l_vm_loop);
    a.bind(l_op_jne); a.test(x86::r15d, 1); a.jz(l_take_branch);  a.inc(x86::r14d); a.jmp(l_vm_loop);
    a.bind(l_op_jlt); a.mov(x86::edx, x86::r15d); a.shr(x86::edx, 2); a.xor_(x86::edx, x86::r15d); a.test(x86::edx, 2); a.jnz(l_take_branch); a.inc(x86::r14d); a.jmp(l_vm_loop);
    a.bind(l_op_jle); a.test(x86::r15d, 1); a.jnz(l_take_branch); a.mov(x86::edx, x86::r15d); a.shr(x86::edx, 2); a.xor_(x86::edx, x86::r15d); a.test(x86::edx, 2); a.jnz(l_take_branch); a.inc(x86::r14d); a.jmp(l_vm_loop);
    {
        Label l_jgt_skip = a.new_label();
        a.bind(l_op_jgt); a.test(x86::r15d, 1); a.jnz(l_jgt_skip); a.mov(x86::edx, x86::r15d); a.shr(x86::edx, 2); a.xor_(x86::edx, x86::r15d); a.test(x86::edx, 2); a.jz(l_take_branch); a.bind(l_jgt_skip); a.inc(x86::r14d); a.jmp(l_vm_loop);
    }
    a.bind(l_op_jge); a.mov(x86::edx, x86::r15d); a.shr(x86::edx, 2); a.xor_(x86::edx, x86::r15d); a.test(x86::edx, 2); a.jz(l_take_branch); a.inc(x86::r14d); a.jmp(l_vm_loop);

    // CallExt bridge: target_va = l_entry + r11 (PIC!)
    a.bind(l_op_callext);
    a.lea(x86::rax, x86::ptr(l_entry));
    a.add(x86::rax, x86::r11);
    if (abi == AbiKind::Win64) {
        a.mov(x86::rcx, x86::qword_ptr(x86::rsp, 1 * 8));
        a.mov(x86::rdx, x86::qword_ptr(x86::rsp, 2 * 8));
        a.mov(x86::r8,  x86::qword_ptr(x86::rsp, 8 * 8));
        a.mov(x86::r9,  x86::qword_ptr(x86::rsp, 9 * 8));
        a.sub(x86::rsp, 32);
        a.call(x86::rax);
        a.add(x86::rsp, 32);
    } else {
        a.mov(x86::rdi, x86::qword_ptr(x86::rsp, 7 * 8));
        a.mov(x86::rsi, x86::qword_ptr(x86::rsp, 6 * 8));
        a.mov(x86::rdx, x86::qword_ptr(x86::rsp, 2 * 8));
        a.mov(x86::rcx, x86::qword_ptr(x86::rsp, 1 * 8));
        a.mov(x86::r8,  x86::qword_ptr(x86::rsp, 8 * 8));
        a.mov(x86::r9,  x86::qword_ptr(x86::rsp, 9 * 8));
        a.call(x86::rax);
    }
    a.mov(x86::qword_ptr(x86::rsp, 0), x86::rax); // R0 = return value
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    if (has_simd) {
        auto voff = [&](const x86::Gp& reg_idx, const x86::Gp& out_off) {
            a.mov(out_off, reg_idx);
            a.shl(out_off, 4);
            a.add(out_off, 1288);
        };
        a.bind(l_op_vmov);
        voff(x86::r8, x86::rax);
        a.movups(x86::xmm0, x86::xmmword_ptr(x86::rsp, x86::rax));
        voff(x86::rcx, x86::rdx);
        a.movups(x86::xmmword_ptr(x86::rsp, x86::rdx), x86::xmm0);
        a.inc(x86::r14d); a.jmp(l_vm_loop);

        auto emit_fp_bin = [&](Label lbl, auto op_fn) {
            a.bind(lbl);
            voff(x86::r8, x86::rax);
            a.movups(x86::xmm0, x86::xmmword_ptr(x86::rsp, x86::rax));
            voff(x86::r9, x86::rdx);
            a.movups(x86::xmm1, x86::xmmword_ptr(x86::rsp, x86::rdx));
            op_fn();
            voff(x86::rcx, x86::rdx);
            a.movups(x86::xmmword_ptr(x86::rsp, x86::rdx), x86::xmm0);
            a.inc(x86::r14d); a.jmp(l_vm_loop);
        };
        emit_fp_bin(l_op_vadd32, [&]() { a.addss(x86::xmm0, x86::xmm1); });
        emit_fp_bin(l_op_vadd64, [&]() { a.addsd(x86::xmm0, x86::xmm1); });
        emit_fp_bin(l_op_vsub32, [&]() { a.subss(x86::xmm0, x86::xmm1); });
        emit_fp_bin(l_op_vsub64, [&]() { a.subsd(x86::xmm0, x86::xmm1); });
        emit_fp_bin(l_op_vmul32, [&]() { a.mulss(x86::xmm0, x86::xmm1); });
        emit_fp_bin(l_op_vmul64, [&]() { a.mulsd(x86::xmm0, x86::xmm1); });
        emit_fp_bin(l_op_vdiv32, [&]() { a.divss(x86::xmm0, x86::xmm1); });
        emit_fp_bin(l_op_vdiv64, [&]() { a.divsd(x86::xmm0, x86::xmm1); });
        emit_fp_bin(l_op_vxor,   [&]() { a.pxor(x86::xmm0, x86::xmm1); });

        auto emit_fp_cmp = [&](Label lbl, bool f32) {
            a.bind(lbl);
            voff(x86::r8, x86::rax);
            a.movups(x86::xmm0, x86::xmmword_ptr(x86::rsp, x86::rax));
            voff(x86::r9, x86::rdx);
            a.movups(x86::xmm1, x86::xmmword_ptr(x86::rsp, x86::rdx));
            if (f32) a.ucomiss(x86::xmm0, x86::xmm1);
            else a.ucomisd(x86::xmm0, x86::xmm1);
            a.setz(x86::r15b);
            a.setb(x86::al);
            a.and_(x86::r15d, 1);
            a.shl(x86::al, 2);
            a.or_(x86::r15b, x86::al);
            a.inc(x86::r14d); a.jmp(l_vm_loop);
        };
        emit_fp_cmp(l_op_vcmp32, true);
        emit_fp_cmp(l_op_vcmp64, false);

        a.bind(l_op_vload);
        a.mov(x86::r10, x86::qword_ptr(x86::rsp, x86::r8, 3));
        a.add(x86::r10, x86::r11);
        a.cmp(x86::r10, 0x1000);
        a.jb(l_vm_done);
        a.movups(x86::xmm0, x86::xmmword_ptr(x86::r10));
        voff(x86::rcx, x86::rdx);
        a.movups(x86::xmmword_ptr(x86::rsp, x86::rdx), x86::xmm0);
        a.inc(x86::r14d); a.jmp(l_vm_loop);

        a.bind(l_op_vstore);
        a.mov(x86::r10, x86::qword_ptr(x86::rsp, x86::rcx, 3));
        a.add(x86::r10, x86::r11);
        a.cmp(x86::r10, 0x1000);
        a.jb(l_vm_done);
        voff(x86::r8, x86::rdx);
        a.movups(x86::xmm0, x86::xmmword_ptr(x86::rsp, x86::rdx));
        a.movups(x86::xmmword_ptr(x86::r10), x86::xmm0);
        a.inc(x86::r14d); a.jmp(l_vm_loop);
    }

    a.bind(l_op_ret);
    a.bind(l_vm_done);
    if (has_simd) {
        a.movups(x86::xmm0, x86::xmmword_ptr(x86::rsp, 1288));
    }
    a.mov(x86::rax, x86::qword_ptr(x86::rsp));
    if (rt_opts.encrypt_bytecode) {
        Label l_exit_wipe = a.new_label();
        a.jmp(l_exit_wipe);
        a.bind(l_aead_fail);
        a.mov(x86::rax, 0xDEADAEADDEADAEADULL);
        a.bind(l_exit_wipe);
        a.xor_(x86::ecx, x86::ecx);
        a.lea(x86::rdi, x86::ptr(x86::rsp, static_cast<std::int32_t>(plain_buf_off)));
        a.mov(x86::edx, static_cast<std::uint32_t>(plain_buf_bytes / 8));
        Label l_wipe_loop = a.new_label();
        a.bind(l_wipe_loop);
        a.mov(x86::qword_ptr(x86::rdi), x86::rcx);
        a.add(x86::rdi, 8);
        a.dec(x86::edx);
        a.jnz(l_wipe_loop);
    }
    a.add(x86::rsp, static_cast<std::uint32_t>(total_frame_bytes));
    if (has_simd) {
        for (int i = 0; i < 10; ++i) {
            a.movups(x86::xmm(6 + i), x86::xmmword_ptr(x86::rsp, i * 16));
        }
        a.add(x86::rsp, 160);
    }
    a.pop(x86::r15);
    a.pop(x86::r14);
    a.pop(x86::r13);
    a.pop(x86::r12);
    a.pop(x86::rsi);
    a.pop(x86::rdi);
    a.pop(x86::rbp);
    a.pop(x86::rbx);
    a.ret();

    if (rt_opts.encrypt_bytecode) {
        emit_x64_aead_open_subroutine(a, l_aead_open, plain_buf_bytes);
        a.align(AlignMode::kData, 8);
        a.bind(l_crypto_key);
        const auto rt_key = CryptoAead::derive_key_from_seed(rt_opts.seed, rt_opts.key_domain);
        a.embed(rt_key.bytes.data(), rt_key.bytes.size());
    }

    a.align(AlignMode::kData, 8);
    const auto rt_key = rt_opts.encrypt_bytecode
        ? CryptoAead::derive_key_from_seed(rt_opts.seed, rt_opts.key_domain)
        : AeadKey{};
    for (std::size_t i = 0; i < progs.size(); ++i) {
        a.align(AlignMode::kData, 8);
        a.bind(l_bytecodes[i]);
        std::vector<std::uint8_t> plain_bytes;
        const std::uint32_t insn_count = static_cast<std::uint32_t>(progs[i].instructions.size());
        write_u32(plain_bytes, insn_count);
        for (const auto& insn : progs[i].instructions) {
            std::uint8_t raw[12]{};
            raw[0] = static_cast<std::uint8_t>(insn.opcode);
            raw[1] = insn.dst;
            raw[2] = insn.src1;
            raw[3] = insn.src2;
            const std::uint64_t imm_u = static_cast<std::uint64_t>(insn.imm);
            std::memcpy(raw + 4, &imm_u, 8);
            plain_bytes.insert(plain_bytes.end(), raw, raw + sizeof(raw));
        }
        if (rt_opts.encrypt_bytecode) {
            std::vector<std::uint8_t> aad;
            write_u32(aad, kBmbcMagic);
            write_u32(aad, kBmbcVersion);
            write_u32(aad, static_cast<std::uint32_t>(i));
            write_u32(aad, static_cast<std::uint32_t>(plain_bytes.size()));
            const auto nonce = CryptoAead::generate_nonce(
                rt_opts.seed ^ (0x9E3779B97F4A7C15ULL * (i + 1)), i + 100);
            auto sealed = CryptoAead::seal(plain_bytes, aad, rt_key, nonce);
            if (!sealed) {
                return diagnostics::Result<std::vector<std::uint8_t>>::err(
                    sealed.error().code, sealed.error().message, "emit_shared_pic_x64_vm_runtime");
            }
            a.embed(aad.data(), aad.size());
            a.embed(sealed.value().nonce.bytes.data(), sealed.value().nonce.bytes.size());
            a.embed(sealed.value().mac.data(), sealed.value().mac.size());
            a.embed(sealed.value().ciphertext.data(), sealed.value().ciphertext.size());
        } else {
            a.embed(plain_bytes.data(), plain_bytes.size());
        }
    }

    code.flatten();
    out_layout.entry_offsets.clear();
    out_layout.entry_offsets.reserve(progs.size());
    for (const auto& lbl : l_stubs) {
        out_layout.entry_offsets.push_back(code.label_offset(lbl));
    }
    out_layout.core_offset = code.label_offset(l_core);
    const auto& sec = code.section_by_id(0);
    return std::vector<std::uint8_t>(sec->buffer().data(), sec->buffer().data() + sec->buffer().size());
#endif
}

#if defined(BYTEMORPH_HAS_ASMJIT)
namespace {

void emit_arm64_aead_open_subroutine(asmjit::a64::Assembler& a,
                                     asmjit::Label l_sub,
                                     std::size_t max_plain_bytes) {
    using namespace asmjit;
    a.bind(l_sub);

    Label l_fail = a.new_label();
    Label l_done = a.new_label();
    Label l_chacha_rounds = a.new_label();
    Label l_poly_block = a.new_label();

    a.stp(a64::x29, a64::x30, a64::ptr_pre(a64::sp, -16));
    a.sub(a64::sp, a64::sp, 320);

    // [sp + 0..63]    chacha state[16]
    // [sp + 64..127]  chacha orig[16]
    // [sp + 128..159] subkey[32]
    // [sp + 160..191] poly_key[32]
    // [sp + 192..207] tmp_blk[16]
    // [sp + 208..231] h[3]
    // [sp + 232..247] r[2]
    // [sp + 248..255] r1_5
    // [sp + 256..271] s[2]
    // [sp + 272..279] blob_ptr
    // [sp + 280..287] out_ptr
    // [sp + 288..295] ct_len
    // [sp + 296..303] key_ptr
    a.str(a64::x0, a64::ptr(a64::sp, 272));
    a.str(a64::x1, a64::ptr(a64::sp, 296));
    a.str(a64::x2, a64::ptr(a64::sp, 280));

    // Validate header: magic, version, 0 < ct_len <= max_plain_bytes
    a.ldr(a64::w9, a64::ptr(a64::x0, 0));
    a.mov(a64::w10, static_cast<std::uint32_t>(kBmbcMagic));
    a.cmp(a64::w9, a64::w10);
    a.b_ne(l_fail);
    a.ldr(a64::w9, a64::ptr(a64::x0, 4));
    a.cmp(a64::w9, kBmbcVersion);
    a.b_ne(l_fail);
    a.ldr(a64::w9, a64::ptr(a64::x0, 12));
    a.cbz(a64::w9, l_fail);
    a.mov(a64::w10, static_cast<std::uint32_t>(max_plain_bytes));
    a.cmp(a64::w9, a64::w10);
    a.b_hi(l_fail);
    a.str(a64::x9, a64::ptr(a64::sp, 288));

    auto load_chacha_consts = [&]() {
        a.mov(a64::w9, 0x61707865u); a.str(a64::w9, a64::ptr(a64::sp, 0));
        a.mov(a64::w9, 0x3320646Eu); a.str(a64::w9, a64::ptr(a64::sp, 4));
        a.mov(a64::w9, 0x79622D32u); a.str(a64::w9, a64::ptr(a64::sp, 8));
        a.mov(a64::w9, 0x6B206574u); a.str(a64::w9, a64::ptr(a64::sp, 12));
    };

    // 1. HChaCha20(subkey, key, nonce[0..15])
    load_chacha_consts();
    for (int i = 0; i < 4; ++i) {
        a.ldr(a64::x9, a64::ptr(a64::x1, i * 8));
        a.str(a64::x9, a64::ptr(a64::sp, 16 + i * 8));
    }
    for (int i = 0; i < 2; ++i) {
        a.ldr(a64::x9, a64::ptr(a64::x0, 16 + i * 8));
        a.str(a64::x9, a64::ptr(a64::sp, 48 + i * 8));
    }
    a.bl(l_chacha_rounds);
    for (int i = 0; i < 2; ++i) {
        a.ldr(a64::x9, a64::ptr(a64::sp, i * 8));
        a.str(a64::x9, a64::ptr(a64::sp, 128 + i * 8));
        a.ldr(a64::x9, a64::ptr(a64::sp, 48 + i * 8));
        a.str(a64::x9, a64::ptr(a64::sp, 144 + i * 8));
    }

    // 2. ChaCha20 block(counter=0) -> poly_key[32]
    load_chacha_consts();
    for (int i = 0; i < 4; ++i) {
        a.ldr(a64::x9, a64::ptr(a64::sp, 128 + i * 8));
        a.str(a64::x9, a64::ptr(a64::sp, 16 + i * 8));
    }
    a.str(a64::xzr, a64::ptr(a64::sp, 48));
    a.ldr(a64::x9, a64::ptr(a64::sp, 272));
    a.ldr(a64::x10, a64::ptr(a64::x9, 32));
    a.str(a64::x10, a64::ptr(a64::sp, 56));
    for (int i = 0; i < 8; ++i) {
        a.ldr(a64::x9, a64::ptr(a64::sp, i * 8));
        a.str(a64::x9, a64::ptr(a64::sp, 64 + i * 8));
    }
    a.bl(l_chacha_rounds);
    for (int i = 0; i < 4; ++i) {
        a.ldr(a64::w9, a64::ptr(a64::sp, i * 4));
        a.ldr(a64::w10, a64::ptr(a64::sp, 64 + i * 4));
        a.add(a64::w9, a64::w9, a64::w10);
        a.str(a64::w9, a64::ptr(a64::sp, 160 + i * 4));
    }
    for (int i = 4; i < 8; ++i) {
        a.ldr(a64::w9, a64::ptr(a64::sp, i * 4));
        a.ldr(a64::w10, a64::ptr(a64::sp, 64 + i * 4));
        a.add(a64::w9, a64::w9, a64::w10);
        a.str(a64::w9, a64::ptr(a64::sp, 160 + i * 4));
    }

    // 3. Poly1305 init
    a.mov(a64::x10, 0x0FFFFFFC0FFFFFFFULL);
    a.ldr(a64::x9, a64::ptr(a64::sp, 160));
    a.and_(a64::x9, a64::x9, a64::x10);
    a.str(a64::x9, a64::ptr(a64::sp, 232));
    a.mov(a64::x10, 0x0FFFFFFC0FFFFFFCULL);
    a.ldr(a64::x9, a64::ptr(a64::sp, 168));
    a.and_(a64::x9, a64::x9, a64::x10);
    a.str(a64::x9, a64::ptr(a64::sp, 240));
    a.add(a64::x9, a64::x9, a64::x9, a64::lsr(2));
    a.str(a64::x9, a64::ptr(a64::sp, 248));
    a.ldr(a64::x9, a64::ptr(a64::sp, 176)); a.str(a64::x9, a64::ptr(a64::sp, 256));
    a.ldr(a64::x9, a64::ptr(a64::sp, 184)); a.str(a64::x9, a64::ptr(a64::sp, 264));
    a.str(a64::xzr, a64::ptr(a64::sp, 208));
    a.str(a64::xzr, a64::ptr(a64::sp, 216));
    a.str(a64::xzr, a64::ptr(a64::sp, 224));

    // Feed AAD (16B)
    a.ldr(a64::x0, a64::ptr(a64::sp, 272));
    a.bl(l_poly_block);

    // Feed ciphertext blocks
    a.ldr(a64::x0, a64::ptr(a64::sp, 272));
    a.add(a64::x0, a64::x0, 56);
    a.ldr(a64::x1, a64::ptr(a64::sp, 288));
    Label l_ct_loop = a.new_label();
    Label l_ct_tail = a.new_label();
    Label l_ct_done = a.new_label();
    a.bind(l_ct_loop);
    a.cmp(a64::x1, 16);
    a.b_lo(l_ct_tail);
    a.bl(l_poly_block);
    a.add(a64::x0, a64::x0, 16);
    a.sub(a64::x1, a64::x1, 16);
    a.b(l_ct_loop);

    a.bind(l_ct_tail);
    a.cbz(a64::x1, l_ct_done);
    a.str(a64::xzr, a64::ptr(a64::sp, 192));
    a.str(a64::xzr, a64::ptr(a64::sp, 200));
    a.mov(a64::x2, 0);
    a.add(a64::x3, a64::sp, 192);
    Label l_copy_t = a.new_label();
    a.bind(l_copy_t);
    a.ldrb(a64::w9, a64::ptr(a64::x0, a64::x2));
    a.strb(a64::w9, a64::ptr(a64::x3, a64::x2));
    a.add(a64::x2, a64::x2, 1);
    a.cmp(a64::x2, a64::x1);
    a.b_lo(l_copy_t);
    a.mov(a64::x0, a64::x3);
    a.bl(l_poly_block);

    // Feed lengths block
    a.bind(l_ct_done);
    a.mov(a64::x9, 16);
    a.str(a64::x9, a64::ptr(a64::sp, 192));
    a.ldr(a64::x9, a64::ptr(a64::sp, 288));
    a.str(a64::x9, a64::ptr(a64::sp, 200));
    a.add(a64::x0, a64::sp, 192);
    a.bl(l_poly_block);

    // Final reduction + MAC compare
    a.ldr(a64::x8, a64::ptr(a64::sp, 208));
    a.ldr(a64::x9, a64::ptr(a64::sp, 216));
    a.ldr(a64::x10, a64::ptr(a64::sp, 224));
    a.adds(a64::x11, a64::x8, 5);
    a.adcs(a64::x12, a64::x9, a64::xzr);
    a.adc(a64::x13, a64::x10, a64::xzr);
    a.subs(a64::x13, a64::x13, 4);
    a.csel(a64::x8, a64::x11, a64::x8, a64::CondCode::kCS);
    a.csel(a64::x9, a64::x12, a64::x9, a64::CondCode::kCS);
    a.ldr(a64::x11, a64::ptr(a64::sp, 256));
    a.ldr(a64::x12, a64::ptr(a64::sp, 264));
    a.adds(a64::x8, a64::x8, a64::x11);
    a.adc(a64::x9, a64::x9, a64::x12);

    a.ldr(a64::x10, a64::ptr(a64::sp, 272));
    a.ldr(a64::x11, a64::ptr(a64::x10, 40));
    a.ldr(a64::x12, a64::ptr(a64::x10, 48));
    a.eor(a64::x8, a64::x8, a64::x11);
    a.eor(a64::x9, a64::x9, a64::x12);
    a.orr(a64::x8, a64::x8, a64::x9);
    a.cbnz(a64::x8, l_fail);

    // 4. Decrypt ciphertext with ChaCha20(counter=1..)
    a.ldr(a64::x0, a64::ptr(a64::sp, 272));
    a.add(a64::x0, a64::x0, 56);
    a.ldr(a64::x1, a64::ptr(a64::sp, 280));
    a.ldr(a64::x2, a64::ptr(a64::sp, 288));
    a.mov(a64::w3, 1);
    Label l_dec_loop = a.new_label();
    Label l_dec_done = a.new_label();
    a.bind(l_dec_loop);
    a.cbz(a64::x2, l_dec_done);
    load_chacha_consts();
    for (int i = 0; i < 4; ++i) {
        a.ldr(a64::x9, a64::ptr(a64::sp, 128 + i * 8));
        a.str(a64::x9, a64::ptr(a64::sp, 16 + i * 8));
    }
    a.str(a64::w3, a64::ptr(a64::sp, 48));
    a.str(a64::wzr, a64::ptr(a64::sp, 52));
    a.ldr(a64::x9, a64::ptr(a64::sp, 272));
    a.ldr(a64::x10, a64::ptr(a64::x9, 32));
    a.str(a64::x10, a64::ptr(a64::sp, 56));
    for (int i = 0; i < 8; ++i) {
        a.ldr(a64::x9, a64::ptr(a64::sp, i * 8));
        a.str(a64::x9, a64::ptr(a64::sp, 64 + i * 8));
    }
    a.bl(l_chacha_rounds);
    for (int i = 0; i < 16; ++i) {
        a.ldr(a64::w9, a64::ptr(a64::sp, i * 4));
        a.ldr(a64::w10, a64::ptr(a64::sp, 64 + i * 4));
        a.add(a64::w9, a64::w9, a64::w10);
        a.str(a64::w9, a64::ptr(a64::sp, i * 4));
    }
    a.mov(a64::x4, a64::x2);
    a.cmp(a64::x4, 64);
    Label l_cnt_ok = a.new_label();
    a.b_ls(l_cnt_ok);
    a.mov(a64::x4, 64);
    a.bind(l_cnt_ok);
    a.mov(a64::x5, 0);
    a.mov(a64::x6, a64::sp);
    Label l_xor_b = a.new_label();
    a.bind(l_xor_b);
    a.ldrb(a64::w9, a64::ptr(a64::x0, a64::x5));
    a.ldrb(a64::w10, a64::ptr(a64::x6, a64::x5));
    a.eor(a64::w9, a64::w9, a64::w10);
    a.strb(a64::w9, a64::ptr(a64::x1, a64::x5));
    a.add(a64::x5, a64::x5, 1);
    a.cmp(a64::x5, a64::x4);
    a.b_lo(l_xor_b);
    a.add(a64::x0, a64::x0, a64::x4);
    a.add(a64::x1, a64::x1, a64::x4);
    a.sub(a64::x2, a64::x2, a64::x4);
    a.add(a64::w3, a64::w3, 1);
    a.b(l_dec_loop);

    a.bind(l_dec_done);
    a.mov(a64::x0, 0);
    a.b(l_done);

    a.bind(l_fail);
    a.mov(a64::x0, -1);

    a.bind(l_done);
    for (int i = 0; i < 34; ++i) {
        a.str(a64::xzr, a64::ptr(a64::sp, i * 8));
    }
    a.add(a64::sp, a64::sp, 320);
    a.ldp(a64::x29, a64::x30, a64::ptr_post(a64::sp, 16));
    a.ret(a64::x30);

    // Leaf ChaCha20 20 rounds on [sp + 0..63]
    a.bind(l_chacha_rounds);
    auto emit_a64_qr = [&](int ai, int bi, int ci, int di) {
        a.ldr(a64::w9,  a64::ptr(a64::sp, ai * 4));
        a.ldr(a64::w10, a64::ptr(a64::sp, bi * 4));
        a.ldr(a64::w11, a64::ptr(a64::sp, ci * 4));
        a.ldr(a64::w12, a64::ptr(a64::sp, di * 4));
        a.add(a64::w9, a64::w9, a64::w10);   a.eor(a64::w12, a64::w12, a64::w9);  a.ror(a64::w12, a64::w12, 16);
        a.add(a64::w11, a64::w11, a64::w12); a.eor(a64::w10, a64::w10, a64::w11); a.ror(a64::w10, a64::w10, 20);
        a.add(a64::w9, a64::w9, a64::w10);   a.eor(a64::w12, a64::w12, a64::w9);  a.ror(a64::w12, a64::w12, 24);
        a.add(a64::w11, a64::w11, a64::w12); a.eor(a64::w10, a64::w10, a64::w11); a.ror(a64::w10, a64::w10, 25);
        a.str(a64::w9,  a64::ptr(a64::sp, ai * 4));
        a.str(a64::w10, a64::ptr(a64::sp, bi * 4));
        a.str(a64::w11, a64::ptr(a64::sp, ci * 4));
        a.str(a64::w12, a64::ptr(a64::sp, di * 4));
    };
    a.mov(a64::w13, 10);
    Label l_a64_rloop = a.new_label();
    a.bind(l_a64_rloop);
    emit_a64_qr(0, 4, 8, 12); emit_a64_qr(1, 5, 9, 13); emit_a64_qr(2, 6, 10, 14); emit_a64_qr(3, 7, 11, 15);
    emit_a64_qr(0, 5, 10, 15); emit_a64_qr(1, 6, 11, 12); emit_a64_qr(2, 7, 8, 13); emit_a64_qr(3, 4, 9, 14);
    a.subs(a64::w13, a64::w13, 1);
    a.b_ne(l_a64_rloop);
    a.ret(a64::x30);

    // Leaf Poly1305 16B block at [x0]
    a.bind(l_poly_block);
    a.ldr(a64::x8, a64::ptr(a64::sp, 208));
    a.ldr(a64::x9, a64::ptr(a64::sp, 216));
    a.ldr(a64::x10, a64::ptr(a64::sp, 224));
    a.ldr(a64::x11, a64::ptr(a64::x0, 0));
    a.ldr(a64::x12, a64::ptr(a64::x0, 8));
    a.adds(a64::x8, a64::x8, a64::x11);
    a.adcs(a64::x9, a64::x9, a64::x12);
    a.mov(a64::x4, 1);
    a.adc(a64::x10, a64::x10, a64::x4);

    a.ldr(a64::x11, a64::ptr(a64::sp, 232)); // r0
    a.ldr(a64::x12, a64::ptr(a64::sp, 240)); // r1
    a.ldr(a64::x13, a64::ptr(a64::sp, 248)); // r1_5

    // t0 = h0 * r0 -> (x15:x14)
    a.mul(a64::x14, a64::x8, a64::x11);
    a.umulh(a64::x15, a64::x8, a64::x11);
    // t1 = h0*r1 + h1*r0 + h2*r1_5 -> (x17:x16)
    a.mul(a64::x16, a64::x8, a64::x12);
    a.umulh(a64::x17, a64::x8, a64::x12);
    a.mul(a64::x4, a64::x9, a64::x11);
    a.umulh(a64::x5, a64::x9, a64::x11);
    a.adds(a64::x16, a64::x16, a64::x4);
    a.adc(a64::x17, a64::x17, a64::x5);
    a.mul(a64::x4, a64::x10, a64::x13);
    a.umulh(a64::x5, a64::x10, a64::x13);
    a.adds(a64::x16, a64::x16, a64::x4);
    a.adc(a64::x17, a64::x17, a64::x5);
    // t2 = h1*r1 + h2*r0 -> (x7:x6)
    a.mul(a64::x6, a64::x9, a64::x12);
    a.umulh(a64::x7, a64::x9, a64::x12);
    a.mul(a64::x4, a64::x10, a64::x11);
    a.umulh(a64::x5, a64::x10, a64::x11);
    a.adds(a64::x6, a64::x6, a64::x4);
    a.adc(a64::x7, a64::x7, a64::x5);

    a.adds(a64::x16, a64::x16, a64::x15);
    a.adc(a64::x17, a64::x17, a64::xzr);
    a.adds(a64::x6, a64::x6, a64::x17);
    a.adc(a64::x7, a64::x7, a64::xzr);

    a.and_(a64::x10, a64::x6, 3);
    a.extr(a64::x6, a64::x7, a64::x6, 2);
    a.lsr(a64::x7, a64::x7, 2);
    a.lsl(a64::x5, a64::x7, 2);
    a.orr(a64::x5, a64::x5, a64::x6, a64::lsr(62));
    a.lsl(a64::x4, a64::x6, 2);
    a.adds(a64::x6, a64::x6, a64::x4);
    a.adc(a64::x7, a64::x7, a64::x5);

    a.adds(a64::x14, a64::x14, a64::x6);
    a.adcs(a64::x16, a64::x16, a64::x7);
    a.adc(a64::x10, a64::x10, a64::xzr);
    a.str(a64::x14, a64::ptr(a64::sp, 208));
    a.str(a64::x16, a64::ptr(a64::sp, 216));
    a.str(a64::x10, a64::ptr(a64::sp, 224));
    a.ret(a64::x30);
}

} // namespace
#endif

diagnostics::Result<std::vector<std::uint8_t>>
emit_pic_arm64_vm_runtime(const BvmProgram& prog) {
    SharedRuntimeLayout layout;
    return emit_shared_pic_arm64_vm_runtime(std::vector<BvmProgram>{prog}, layout);
}

diagnostics::Result<std::vector<std::uint8_t>>
emit_shared_pic_arm64_vm_runtime(const std::vector<BvmProgram>& progs,
                                 SharedRuntimeLayout& out_layout) {
    return emit_shared_pic_arm64_vm_runtime(progs, out_layout, SharedRuntimeOptions{});
}

diagnostics::Result<std::vector<std::uint8_t>>
emit_shared_pic_arm64_vm_runtime(const std::vector<BvmProgram>& progs,
                                 SharedRuntimeLayout& out_layout,
                                 const SharedRuntimeOptions& rt_opts) {
#if !defined(BYTEMORPH_HAS_ASMJIT)
    (void)progs;
    (void)out_layout;
    (void)rt_opts;
    return diagnostics::Result<std::vector<std::uint8_t>>::err(
        diagnostics::ErrorCode::NotImplemented, "AsmJit is disabled", "emit_shared_pic_arm64_vm_runtime");
#else
    if (progs.empty()) {
        return diagnostics::Result<std::vector<std::uint8_t>>::err(
            diagnostics::ErrorCode::EmptyInput, "No BvmPrograms provided", "emit_shared_pic_arm64_vm_runtime");
    }

    asmjit::Environment env(asmjit::Arch::kAArch64);
    asmjit::CodeHolder code;
    code.init(env);
    asmjit::a64::Assembler a(&code);
    using namespace asmjit;

    Label l_entry = a.new_label();
    Label l_core = a.new_label();
    Label l_aead_open = a.new_label();
    Label l_crypto_key = a.new_label();
    Label l_aead_fail = a.new_label();
    std::vector<Label> l_stubs;
    std::vector<Label> l_bytecodes;
    l_stubs.reserve(progs.size());
    l_bytecodes.reserve(progs.size());
    std::size_t max_plain_bytes = 0;
    bool has_simd = false;
    for (std::size_t i = 0; i < progs.size(); ++i) {
        l_stubs.push_back(a.new_label());
        l_bytecodes.push_back(a.new_label());
        const std::size_t pbytes = 4 + progs[i].instructions.size() * 12;
        if (pbytes > max_plain_bytes) max_plain_bytes = pbytes;
        for (const auto& insn : progs[i].instructions) {
            if (insn.opcode >= VmOpcode::VMovReg && insn.opcode <= VmOpcode::VXor) {
                has_simd = true;
            }
        }
    }
    const std::size_t vreg_buf_bytes = has_simd ? 512 : 0;
    const std::size_t plain_buf_bytes = rt_opts.encrypt_bytecode
        ? static_cast<std::size_t>(align_up(std::max<std::size_t>(max_plain_bytes, 64), 16))
        : 0;
    Label l_vm_loop = a.new_label();
    Label l_vm_done = a.new_label();
    Label l_take_branch = a.new_label();

    Label l_op_nop = a.new_label();
    Label l_op_movreg = a.new_label();
    Label l_op_movimm = a.new_label();
    Label l_op_load = a.new_label();
    Label l_op_store = a.new_label();
    Label l_op_add = a.new_label();
    Label l_op_sub = a.new_label();
    Label l_op_mul = a.new_label();
    Label l_op_div = a.new_label();
    Label l_op_and = a.new_label();
    Label l_op_or = a.new_label();
    Label l_op_xor = a.new_label();
    Label l_op_shl = a.new_label();
    Label l_op_shr = a.new_label();
    Label l_op_cmp = a.new_label();
    Label l_op_leapic = a.new_label();
    Label l_op_selectcc = a.new_label();
    Label l_op_setcc = a.new_label();
    Label l_op_jmp = a.new_label();
    Label l_op_jeq = a.new_label();
    Label l_op_jne = a.new_label();
    Label l_op_jlt = a.new_label();
    Label l_op_jle = a.new_label();
    Label l_op_jgt = a.new_label();
    Label l_op_jge = a.new_label();
    Label l_op_ret = a.new_label();
    Label l_op_callext = a.new_label();
    Label l_op_vmov = a.new_label();
    Label l_op_vadd32 = a.new_label(); Label l_op_vadd64 = a.new_label();
    Label l_op_vsub32 = a.new_label(); Label l_op_vsub64 = a.new_label();
    Label l_op_vmul32 = a.new_label(); Label l_op_vmul64 = a.new_label();
    Label l_op_vdiv32 = a.new_label(); Label l_op_vdiv64 = a.new_label();
    Label l_op_vcmp32 = a.new_label(); Label l_op_vcmp64 = a.new_label();
    Label l_op_vload = a.new_label();  Label l_op_vstore = a.new_label();
    Label l_op_vxor = a.new_label();

    a.bind(l_entry);
    for (std::size_t i = 0; i < progs.size(); ++i) {
        a.bind(l_stubs[i]);
        a.adr(a64::x16, l_bytecodes[i]);
        a.b(l_core);
    }

    // AAPCS64 / Apple ARM64 ABI:
    // Save x19-x28, x29, x30 (12 regs = 96B) + 1280B (256B VM regs + 1024B virtual stack frame) = 1376B (16B aligned)
    a.bind(l_core);
    a.stp(a64::x29, a64::x30, a64::ptr_pre(a64::sp, -96));
    a.stp(a64::x19, a64::x20, a64::ptr(a64::sp, 16));
    a.stp(a64::x21, a64::x22, a64::ptr(a64::sp, 32));
    a.stp(a64::x23, a64::x24, a64::ptr(a64::sp, 48));
    a.stp(a64::x25, a64::x26, a64::ptr(a64::sp, 64));
    a.stp(a64::x27, a64::x28, a64::ptr(a64::sp, 80));
    const std::size_t total_frame_bytes = 1280 + vreg_buf_bytes + plain_buf_bytes;
    const std::size_t plain_buf_off = 1280 + vreg_buf_bytes;
    a.sub(a64::sp, a64::sp, static_cast<std::uint32_t>(total_frame_bytes));

    // Zero R0..R31 and virtual stack frame (160 qwords = 1280B)
    a.mov(a64::x10, a64::sp);
    a.mov(a64::w11, 160);
    Label l_zero = a.new_label();
    a.bind(l_zero);
    a.str(a64::xzr, a64::ptr_post(a64::x10, 8));
    a.subs(a64::w11, a64::w11, 1);
    a.b_ne(l_zero);

    // Initialize virtual stack pointer R4 (sp) and frame pointer R5 (x29) to sp + 896
    a.add(a64::x10, a64::sp, 896);
    a.str(a64::x10, a64::ptr(a64::sp, 4 * 8));
    a.str(a64::x10, a64::ptr(a64::sp, 5 * 8));

    // Store AAPCS64 args x0..x7 into R0..R3, R6..R9
    a.str(a64::x0, a64::ptr(a64::sp, 0 * 8));
    a.str(a64::x1, a64::ptr(a64::sp, 1 * 8));
    a.str(a64::x2, a64::ptr(a64::sp, 2 * 8));
    a.str(a64::x3, a64::ptr(a64::sp, 3 * 8));
    a.str(a64::x4, a64::ptr(a64::sp, 6 * 8));
    a.str(a64::x5, a64::ptr(a64::sp, 7 * 8));
    a.str(a64::x6, a64::ptr(a64::sp, 8 * 8));
    a.str(a64::x7, a64::ptr(a64::sp, 9 * 8));
    if (has_simd) {
        for (int i = 0; i < 8; ++i) {
            a.str(a64::q(i), a64::ptr(a64::sp, 1280 + i * 16));
        }
    }

    if (rt_opts.encrypt_bytecode) {
        a.mov(a64::x0, a64::x16);
        a.adr(a64::x1, l_crypto_key);
        a.add(a64::x2, a64::sp, static_cast<std::uint32_t>(plain_buf_off));
        a.bl(l_aead_open);
        a.cbnz(a64::x0, l_aead_fail);
        a.add(a64::x19, a64::sp, static_cast<std::uint32_t>(plain_buf_off));
        a.ldr(a64::w20, a64::ptr(a64::x19));
        a.add(a64::x21, a64::x19, 4);
    } else {
        a.mov(a64::x19, a64::x16);                 // bytecode pointer from stub
        a.ldr(a64::w20, a64::ptr(a64::x19));       // insn_count
        a.add(a64::x21, a64::x19, 4);              // insn_base
    }
    a.mov(a64::w22, 0);                        // pc = 0
    a.mov(a64::w23, 0);                        // flags = 0 (bit0=ZF, bit1=SF)

    a.bind(l_vm_loop);
    a.cmp(a64::w22, a64::w20);
    a.b_hs(l_vm_done);

    // x9 = x21 + x22 * 12
    a.mov(a64::w10, 12);
    a.umull(a64::x9, a64::w22, a64::w10);
    a.add(a64::x9, a64::x21, a64::x9);

    a.ldrb(a64::w10, a64::ptr(a64::x9, 0));    // op
    a.ldrb(a64::w11, a64::ptr(a64::x9, 1));    // dst
    a.ldrb(a64::w12, a64::ptr(a64::x9, 2));    // src1
    a.ldrb(a64::w13, a64::ptr(a64::x9, 3));    // src2
    a.ldur(a64::x14, a64::ptr(a64::x9, 4));    // imm (unaligned 64-bit load)

    a.cmp(a64::w10, static_cast<int>(VmOpcode::Nop));     a.b_eq(l_op_nop);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::MovReg));  a.b_eq(l_op_movreg);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::MovImm));  a.b_eq(l_op_movimm);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Load));    a.b_eq(l_op_load);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Store));   a.b_eq(l_op_store);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Add));     a.b_eq(l_op_add);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Sub));     a.b_eq(l_op_sub);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Mul));     a.b_eq(l_op_mul);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Div));     a.b_eq(l_op_div);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::And));     a.b_eq(l_op_and);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Or));      a.b_eq(l_op_or);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Xor));     a.b_eq(l_op_xor);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Shl));     a.b_eq(l_op_shl);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Shr));     a.b_eq(l_op_shr);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Cmp));      a.b_eq(l_op_cmp);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::LeaPic));   a.b_eq(l_op_leapic);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::SelectCc)); a.b_eq(l_op_selectcc);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::SetCc));    a.b_eq(l_op_setcc);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Jmp));      a.b_eq(l_op_jmp);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Jeq));     a.b_eq(l_op_jeq);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Jne));     a.b_eq(l_op_jne);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Jlt));     a.b_eq(l_op_jlt);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Jle));     a.b_eq(l_op_jle);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Jgt));     a.b_eq(l_op_jgt);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Jge));     a.b_eq(l_op_jge);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Ret));     a.b_eq(l_op_ret);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Halt));    a.b_eq(l_op_ret);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::CallExt)); a.b_eq(l_op_callext);
    if (has_simd) {
        a.cmp(a64::w10, static_cast<int>(VmOpcode::VMovReg)); a.b_eq(l_op_vmov);
        a.cmp(a64::w10, static_cast<int>(VmOpcode::VAddF32)); a.b_eq(l_op_vadd32);
        a.cmp(a64::w10, static_cast<int>(VmOpcode::VAddF64)); a.b_eq(l_op_vadd64);
        a.cmp(a64::w10, static_cast<int>(VmOpcode::VSubF32)); a.b_eq(l_op_vsub32);
        a.cmp(a64::w10, static_cast<int>(VmOpcode::VSubF64)); a.b_eq(l_op_vsub64);
        a.cmp(a64::w10, static_cast<int>(VmOpcode::VMulF32)); a.b_eq(l_op_vmul32);
        a.cmp(a64::w10, static_cast<int>(VmOpcode::VMulF64)); a.b_eq(l_op_vmul64);
        a.cmp(a64::w10, static_cast<int>(VmOpcode::VDivF32)); a.b_eq(l_op_vdiv32);
        a.cmp(a64::w10, static_cast<int>(VmOpcode::VDivF64)); a.b_eq(l_op_vdiv64);
        a.cmp(a64::w10, static_cast<int>(VmOpcode::VCmpF32)); a.b_eq(l_op_vcmp32);
        a.cmp(a64::w10, static_cast<int>(VmOpcode::VCmpF64)); a.b_eq(l_op_vcmp64);
        a.cmp(a64::w10, static_cast<int>(VmOpcode::VLoad));   a.b_eq(l_op_vload);
        a.cmp(a64::w10, static_cast<int>(VmOpcode::VStore));  a.b_eq(l_op_vstore);
        a.cmp(a64::w10, static_cast<int>(VmOpcode::VXor));    a.b_eq(l_op_vxor);
    }
    a.b(l_vm_done);

    auto load_srcs = [&]() {
        a.mov(a64::x15, a64::sp);
        a.ldr(a64::x0, a64::ptr(a64::x15, a64::x12, a64::lsl(3)));
        a.ldr(a64::x1, a64::ptr(a64::x15, a64::x13, a64::lsl(3)));
    };
    auto store_dst = [&]() {
        a.mov(a64::x15, a64::sp);
        a.str(a64::x0, a64::ptr(a64::x15, a64::x11, a64::lsl(3)));
    };
    auto update_flags_x0 = [&]() {
        a.cmp(a64::x0, 0);
        a.cset(a64::w23, a64::CondCode::kEQ);
        a.cset(a64::w15, a64::CondCode::kLT);
        a.orr(a64::w23, a64::w23, a64::w15, a64::lsl(1));
    };

    a.bind(l_op_nop); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);

    a.bind(l_op_movreg);
    a.mov(a64::x15, a64::sp);
    a.ldr(a64::x0, a64::ptr(a64::x15, a64::x12, a64::lsl(3)));
    store_dst(); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);

    a.bind(l_op_movimm);
    a.mov(a64::x0, a64::x14);
    store_dst(); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);

    // Load: dst=w11, src1=w12 (base), src2=w13 (width: 8/16/32/64/0), imm=x14 (disp)
    Label l_a64_load_16 = a.new_label();
    Label l_a64_load_32 = a.new_label();
    Label l_a64_load_64 = a.new_label();
    Label l_a64_load_done = a.new_label();
    a.bind(l_op_load);
    a.mov(a64::x15, a64::sp);
    a.ldr(a64::x9, a64::ptr(a64::x15, a64::x12, a64::lsl(3)));
    a.add(a64::x9, a64::x9, a64::x14);
    a.cmp(a64::x9, 0x1000);
    a.b_lo(l_vm_done);
    a.cmp(a64::w13, 8);  a.b_ne(l_a64_load_16);
    a.ldrb(a64::w0, a64::ptr(a64::x9));
    a.b(l_a64_load_done);
    a.bind(l_a64_load_16);
    a.cmp(a64::w13, 16); a.b_ne(l_a64_load_32);
    a.ldrh(a64::w0, a64::ptr(a64::x9));
    a.b(l_a64_load_done);
    a.bind(l_a64_load_32);
    a.cmp(a64::w13, 32); a.b_ne(l_a64_load_64);
    a.ldr(a64::w0, a64::ptr(a64::x9));
    a.b(l_a64_load_done);
    a.bind(l_a64_load_64);
    a.ldr(a64::x0, a64::ptr(a64::x9));
    a.bind(l_a64_load_done);
    store_dst();
    a.add(a64::w22, a64::w22, 1);
    a.b(l_vm_loop);

    // Store: dst=w11 (base), src1=w12 (val), src2=w13 (width: 8/16/32/64/0), imm=x14 (disp)
    Label l_a64_store_16 = a.new_label();
    Label l_a64_store_32 = a.new_label();
    Label l_a64_store_64 = a.new_label();
    Label l_a64_store_done = a.new_label();
    a.bind(l_op_store);
    a.mov(a64::x15, a64::sp);
    a.ldr(a64::x9, a64::ptr(a64::x15, a64::x11, a64::lsl(3)));
    a.add(a64::x9, a64::x9, a64::x14);
    a.cmp(a64::x9, 0x1000);
    a.b_lo(l_vm_done);
    a.ldr(a64::x0, a64::ptr(a64::x15, a64::x12, a64::lsl(3)));
    a.cmp(a64::w13, 8);  a.b_ne(l_a64_store_16);
    a.strb(a64::w0, a64::ptr(a64::x9));
    a.b(l_a64_store_done);
    a.bind(l_a64_store_16);
    a.cmp(a64::w13, 16); a.b_ne(l_a64_store_32);
    a.strh(a64::w0, a64::ptr(a64::x9));
    a.b(l_a64_store_done);
    a.bind(l_a64_store_32);
    a.cmp(a64::w13, 32); a.b_ne(l_a64_store_64);
    a.str(a64::w0, a64::ptr(a64::x9));
    a.b(l_a64_store_done);
    a.bind(l_a64_store_64);
    a.str(a64::x0, a64::ptr(a64::x9));
    a.bind(l_a64_store_done);
    a.add(a64::w22, a64::w22, 1);
    a.b(l_vm_loop);

    a.bind(l_op_add); load_srcs(); a.add(a64::x0, a64::x0, a64::x1); store_dst(); update_flags_x0(); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    a.bind(l_op_sub); load_srcs(); a.sub(a64::x0, a64::x0, a64::x1); store_dst(); update_flags_x0(); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    a.bind(l_op_mul); load_srcs(); a.mul(a64::x0, a64::x0, a64::x1); store_dst(); update_flags_x0(); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    a.bind(l_op_div); load_srcs(); a.cbz(a64::x1, l_vm_done); a.udiv(a64::x0, a64::x0, a64::x1); store_dst(); update_flags_x0(); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    a.bind(l_op_and); load_srcs(); a.and_(a64::x0, a64::x0, a64::x1); store_dst(); update_flags_x0(); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    a.bind(l_op_or);  load_srcs(); a.orr(a64::x0, a64::x0, a64::x1); store_dst(); update_flags_x0(); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    a.bind(l_op_xor); load_srcs(); a.eor(a64::x0, a64::x0, a64::x1); store_dst(); update_flags_x0(); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    a.bind(l_op_shl); load_srcs(); a.lsl(a64::x0, a64::x0, a64::x1); store_dst(); update_flags_x0(); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    a.bind(l_op_shr); load_srcs(); a.lsr(a64::x0, a64::x0, a64::x1); store_dst(); update_flags_x0(); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);

    a.bind(l_op_cmp);
    load_srcs();
    a.cmp(a64::x0, a64::x1);
    a.cset(a64::w23, a64::CondCode::kEQ);
    a.cset(a64::w15, a64::CondCode::kMI);
    a.orr(a64::w23, a64::w23, a64::w15, a64::lsl(1));
    a.cset(a64::w15, a64::CondCode::kLO);
    a.orr(a64::w23, a64::w23, a64::w15, a64::lsl(2));
    a.cset(a64::w15, a64::CondCode::kVS);
    a.orr(a64::w23, a64::w23, a64::w15, a64::lsl(3));
    a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);

    a.bind(l_op_leapic);
    a.adr(a64::x0, l_entry);
    a.add(a64::x0, a64::x0, a64::x14);
    store_dst();
    a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);

    {
        Label l_eval_cc = a.new_label();
        Label l_cc_apply = a.new_label();
        Label l_sel_skip = a.new_label();
        Label l_cc_0 = a.new_label(); Label l_cc_1 = a.new_label();
        Label l_cc_2 = a.new_label(); Label l_cc_3 = a.new_label();
        Label l_cc_4 = a.new_label(); Label l_cc_5 = a.new_label();
        Label l_cc_6 = a.new_label(); Label l_cc_7 = a.new_label();
        Label l_cc_8 = a.new_label(); Label l_cc_9 = a.new_label();
        Label l_cc_10 = a.new_label(); Label l_cc_11 = a.new_label();
        Label l_cc_12 = a.new_label(); Label l_cc_13 = a.new_label();

        a.bind(l_op_setcc);
        a.mov(a64::w9, 0);
        a.b(l_eval_cc);

        a.bind(l_op_selectcc);
        a.mov(a64::w9, 1);

        a.bind(l_eval_cc);
        a.mov(a64::x0, 0);
        a.cmp(a64::w13, 0);  a.b_eq(l_cc_0);
        a.cmp(a64::w13, 1);  a.b_eq(l_cc_1);
        a.cmp(a64::w13, 2);  a.b_eq(l_cc_2);
        a.cmp(a64::w13, 3);  a.b_eq(l_cc_3);
        a.cmp(a64::w13, 4);  a.b_eq(l_cc_4);
        a.cmp(a64::w13, 5);  a.b_eq(l_cc_5);
        a.cmp(a64::w13, 6);  a.b_eq(l_cc_6);
        a.cmp(a64::w13, 7);  a.b_eq(l_cc_7);
        a.cmp(a64::w13, 8);  a.b_eq(l_cc_8);
        a.cmp(a64::w13, 9);  a.b_eq(l_cc_9);
        a.cmp(a64::w13, 10); a.b_eq(l_cc_10);
        a.cmp(a64::w13, 11); a.b_eq(l_cc_11);
        a.cmp(a64::w13, 12); a.b_eq(l_cc_12);
        a.cmp(a64::w13, 13); a.b_eq(l_cc_13);
        a.b(l_cc_apply);

        a.bind(l_cc_0);  a.tst(a64::w23, 1); a.cset(a64::x0, a64::CondCode::kNE); a.b(l_cc_apply);
        a.bind(l_cc_1);  a.tst(a64::w23, 1); a.cset(a64::x0, a64::CondCode::kEQ); a.b(l_cc_apply);
        a.bind(l_cc_2);  a.lsr(a64::w15, a64::w23, 2); a.eor(a64::w15, a64::w15, a64::w23); a.tst(a64::w15, 2); a.cset(a64::x0, a64::CondCode::kNE); a.b(l_cc_apply);
        a.bind(l_cc_3);  a.tst(a64::w23, 1); a.cset(a64::x0, a64::CondCode::kNE); a.b_ne(l_cc_apply); a.lsr(a64::w15, a64::w23, 2); a.eor(a64::w15, a64::w15, a64::w23); a.tst(a64::w15, 2); a.cset(a64::x0, a64::CondCode::kNE); a.b(l_cc_apply);
        a.bind(l_cc_4);  a.tst(a64::w23, 1); a.b_ne(l_cc_apply); a.lsr(a64::w15, a64::w23, 2); a.eor(a64::w15, a64::w15, a64::w23); a.tst(a64::w15, 2); a.cset(a64::x0, a64::CondCode::kEQ); a.b(l_cc_apply);
        a.bind(l_cc_5);  a.lsr(a64::w15, a64::w23, 2); a.eor(a64::w15, a64::w15, a64::w23); a.tst(a64::w15, 2); a.cset(a64::x0, a64::CondCode::kEQ); a.b(l_cc_apply);
        a.bind(l_cc_6);  a.tst(a64::w23, 4); a.cset(a64::x0, a64::CondCode::kNE); a.b(l_cc_apply);
        a.bind(l_cc_7);  a.tst(a64::w23, 5); a.cset(a64::x0, a64::CondCode::kNE); a.b(l_cc_apply);
        a.bind(l_cc_8);  a.tst(a64::w23, 5); a.cset(a64::x0, a64::CondCode::kEQ); a.b(l_cc_apply);
        a.bind(l_cc_9);  a.tst(a64::w23, 4); a.cset(a64::x0, a64::CondCode::kEQ); a.b(l_cc_apply);
        a.bind(l_cc_10); a.tst(a64::w23, 2); a.cset(a64::x0, a64::CondCode::kNE); a.b(l_cc_apply);
        a.bind(l_cc_11); a.tst(a64::w23, 2); a.cset(a64::x0, a64::CondCode::kEQ); a.b(l_cc_apply);
        a.bind(l_cc_12); a.tst(a64::w23, 8); a.cset(a64::x0, a64::CondCode::kNE); a.b(l_cc_apply);
        a.bind(l_cc_13); a.tst(a64::w23, 8); a.cset(a64::x0, a64::CondCode::kEQ);

        a.bind(l_cc_apply);
        a.cbnz(a64::w9, l_sel_skip);
        store_dst();
        a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);

        a.bind(l_sel_skip);
        Label l_sel_done = a.new_label();
        a.cbz(a64::x0, l_sel_done);
        a.mov(a64::x15, a64::sp);
        a.ldr(a64::x0, a64::ptr(a64::x15, a64::x12, a64::lsl(3)));
        store_dst();
        a.bind(l_sel_done);
        a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    }

    a.bind(l_op_jmp);
    a.bind(l_take_branch);
    a.mov(a64::w22, a64::w14);
    a.b(l_vm_loop);

    a.bind(l_op_jeq); a.tst(a64::w23, 1); a.b_ne(l_take_branch); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    a.bind(l_op_jne); a.tst(a64::w23, 1); a.b_eq(l_take_branch); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    a.bind(l_op_jlt); a.lsr(a64::w15, a64::w23, 2); a.eor(a64::w15, a64::w15, a64::w23); a.tst(a64::w15, 2); a.b_ne(l_take_branch); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    a.bind(l_op_jle); a.tst(a64::w23, 1); a.b_ne(l_take_branch); a.lsr(a64::w15, a64::w23, 2); a.eor(a64::w15, a64::w15, a64::w23); a.tst(a64::w15, 2); a.b_ne(l_take_branch); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    {
        Label l_jgt_skip = a.new_label();
        a.bind(l_op_jgt); a.tst(a64::w23, 1); a.b_ne(l_jgt_skip); a.lsr(a64::w15, a64::w23, 2); a.eor(a64::w15, a64::w15, a64::w23); a.tst(a64::w15, 2); a.b_eq(l_take_branch); a.bind(l_jgt_skip); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    }
    a.bind(l_op_jge); a.lsr(a64::w15, a64::w23, 2); a.eor(a64::w15, a64::w15, a64::w23); a.tst(a64::w15, 2); a.b_eq(l_take_branch); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);

    // CallExt bridge on ARM64: target_va = l_entry + x14 (PIC!)
    a.bind(l_op_callext);
    a.adr(a64::x9, l_entry);
    a.add(a64::x9, a64::x9, a64::x14);
    a.ldr(a64::x0, a64::ptr(a64::sp, 0 * 8));
    a.ldr(a64::x1, a64::ptr(a64::sp, 1 * 8));
    a.ldr(a64::x2, a64::ptr(a64::sp, 2 * 8));
    a.ldr(a64::x3, a64::ptr(a64::sp, 3 * 8));
    a.ldr(a64::x4, a64::ptr(a64::sp, 6 * 8));
    a.ldr(a64::x5, a64::ptr(a64::sp, 7 * 8));
    a.ldr(a64::x6, a64::ptr(a64::sp, 8 * 8));
    a.ldr(a64::x7, a64::ptr(a64::sp, 9 * 8));
    a.blr(a64::x9);
    a.str(a64::x0, a64::ptr(a64::sp, 0 * 8));
    a.add(a64::w22, a64::w22, 1);
    a.b(l_vm_loop);

    if (has_simd) {
        auto vptr = [&](const a64::Gp& idx, const a64::Gp& out_ptr) {
            a.add(out_ptr, a64::sp, 1280);
            a.add(out_ptr, out_ptr, idx, a64::lsl(4));
        };
        a.bind(l_op_vmov);
        vptr(a64::x12, a64::x15); a.ldr(a64::q0, a64::ptr(a64::x15));
        vptr(a64::x11, a64::x15); a.str(a64::q0, a64::ptr(a64::x15));
        a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);

        auto emit_a64_fp_bin = [&](Label lbl, auto op_fn) {
            a.bind(lbl);
            vptr(a64::x12, a64::x15); a.ldr(a64::q0, a64::ptr(a64::x15));
            vptr(a64::x13, a64::x15); a.ldr(a64::q1, a64::ptr(a64::x15));
            op_fn();
            vptr(a64::x11, a64::x15); a.str(a64::q0, a64::ptr(a64::x15));
            a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
        };
        emit_a64_fp_bin(l_op_vadd32, [&]() { a.fadd(a64::s0, a64::s0, a64::s1); });
        emit_a64_fp_bin(l_op_vadd64, [&]() { a.fadd(a64::d0, a64::d0, a64::d1); });
        emit_a64_fp_bin(l_op_vsub32, [&]() { a.fsub(a64::s0, a64::s0, a64::s1); });
        emit_a64_fp_bin(l_op_vsub64, [&]() { a.fsub(a64::d0, a64::d0, a64::d1); });
        emit_a64_fp_bin(l_op_vmul32, [&]() { a.fmul(a64::s0, a64::s0, a64::s1); });
        emit_a64_fp_bin(l_op_vmul64, [&]() { a.fmul(a64::d0, a64::d0, a64::d1); });
        emit_a64_fp_bin(l_op_vdiv32, [&]() { a.fdiv(a64::s0, a64::s0, a64::s1); });
        emit_a64_fp_bin(l_op_vdiv64, [&]() { a.fdiv(a64::d0, a64::d0, a64::d1); });
        emit_a64_fp_bin(l_op_vxor,   [&]() { a.eor(a64::v0.b16(), a64::v0.b16(), a64::v1.b16()); });

        auto emit_a64_fp_cmp = [&](Label lbl, bool f32) {
            a.bind(lbl);
            vptr(a64::x12, a64::x15); a.ldr(a64::q0, a64::ptr(a64::x15));
            vptr(a64::x13, a64::x15); a.ldr(a64::q1, a64::ptr(a64::x15));
            if (f32) a.fcmp(a64::s0, a64::s1);
            else a.fcmp(a64::d0, a64::d1);
            a.cset(a64::w23, a64::CondCode::kEQ);
            a.cset(a64::w15, a64::CondCode::kLO);
            a.orr(a64::w23, a64::w23, a64::w15, a64::lsl(2));
            a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
        };
        emit_a64_fp_cmp(l_op_vcmp32, true);
        emit_a64_fp_cmp(l_op_vcmp64, false);

        a.bind(l_op_vload);
        a.mov(a64::x15, a64::sp);
        a.ldr(a64::x9, a64::ptr(a64::x15, a64::x12, a64::lsl(3)));
        a.add(a64::x9, a64::x9, a64::x14);
        a.cmp(a64::x9, 0x1000);
        a.b_lo(l_vm_done);
        a.ldr(a64::q0, a64::ptr(a64::x9));
        vptr(a64::x11, a64::x15); a.str(a64::q0, a64::ptr(a64::x15));
        a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);

        a.bind(l_op_vstore);
        a.mov(a64::x15, a64::sp);
        a.ldr(a64::x9, a64::ptr(a64::x15, a64::x11, a64::lsl(3)));
        a.add(a64::x9, a64::x9, a64::x14);
        a.cmp(a64::x9, 0x1000);
        a.b_lo(l_vm_done);
        vptr(a64::x12, a64::x15); a.ldr(a64::q0, a64::ptr(a64::x15));
        a.str(a64::q0, a64::ptr(a64::x9));
        a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    }

    a.bind(l_op_ret);
    a.bind(l_vm_done);
    if (has_simd) {
        a.ldr(a64::q0, a64::ptr(a64::sp, 1280));
    }
    a.ldr(a64::x0, a64::ptr(a64::sp, 0));
    if (rt_opts.encrypt_bytecode) {
        Label l_a64_exit_wipe = a.new_label();
        a.b(l_a64_exit_wipe);
        a.bind(l_aead_fail);
        // Set error sentinel
        a.mov(a64::x0, 0xDEADAEADDEADAEADULL);
        a.bind(l_a64_exit_wipe);
        a.add(a64::x10, a64::sp, static_cast<std::uint32_t>(plain_buf_off));
        a.mov(a64::w11, static_cast<std::uint32_t>(plain_buf_bytes / 8));
        Label l_a64_wipe = a.new_label();
        a.bind(l_a64_wipe);
        a.str(a64::xzr, a64::ptr_post(a64::x10, 8));
        a.subs(a64::w11, a64::w11, 1);
        a.b_ne(l_a64_wipe);
    }
    a.add(a64::sp, a64::sp, static_cast<std::uint32_t>(total_frame_bytes));
    a.ldp(a64::x19, a64::x20, a64::ptr(a64::sp, 16));
    a.ldp(a64::x21, a64::x22, a64::ptr(a64::sp, 32));
    a.ldp(a64::x23, a64::x24, a64::ptr(a64::sp, 48));
    a.ldp(a64::x25, a64::x26, a64::ptr(a64::sp, 64));
    a.ldp(a64::x27, a64::x28, a64::ptr(a64::sp, 80));
    a.ldp(a64::x29, a64::x30, a64::ptr_post(a64::sp, 96));
    a.ret(a64::x30);

    if (rt_opts.encrypt_bytecode) {
        emit_arm64_aead_open_subroutine(a, l_aead_open, plain_buf_bytes);
        a.align(AlignMode::kData, 8);
        a.bind(l_crypto_key);
        const auto rt_key = CryptoAead::derive_key_from_seed(rt_opts.seed, rt_opts.key_domain);
        a.embed(rt_key.bytes.data(), rt_key.bytes.size());
    }

    a.align(AlignMode::kData, 8);
    const auto rt_key = rt_opts.encrypt_bytecode
        ? CryptoAead::derive_key_from_seed(rt_opts.seed, rt_opts.key_domain)
        : AeadKey{};
    for (std::size_t i = 0; i < progs.size(); ++i) {
        a.align(AlignMode::kData, 8);
        a.bind(l_bytecodes[i]);
        std::vector<std::uint8_t> plain_bytes;
        const std::uint32_t insn_count = static_cast<std::uint32_t>(progs[i].instructions.size());
        write_u32(plain_bytes, insn_count);
        for (const auto& insn : progs[i].instructions) {
            std::uint8_t raw[12]{};
            raw[0] = static_cast<std::uint8_t>(insn.opcode);
            raw[1] = insn.dst;
            raw[2] = insn.src1;
            raw[3] = insn.src2;
            const std::uint64_t imm_u = static_cast<std::uint64_t>(insn.imm);
            std::memcpy(raw + 4, &imm_u, 8);
            plain_bytes.insert(plain_bytes.end(), raw, raw + sizeof(raw));
        }
        if (rt_opts.encrypt_bytecode) {
            std::vector<std::uint8_t> aad;
            write_u32(aad, kBmbcMagic);
            write_u32(aad, kBmbcVersion);
            write_u32(aad, static_cast<std::uint32_t>(i));
            write_u32(aad, static_cast<std::uint32_t>(plain_bytes.size()));
            const auto nonce = CryptoAead::generate_nonce(
                rt_opts.seed ^ (0x9E3779B97F4A7C15ULL * (i + 1)), i + 100);
            auto sealed = CryptoAead::seal(plain_bytes, aad, rt_key, nonce);
            if (!sealed) {
                return diagnostics::Result<std::vector<std::uint8_t>>::err(
                    sealed.error().code, sealed.error().message, "emit_shared_pic_arm64_vm_runtime");
            }
            a.embed(aad.data(), aad.size());
            a.embed(sealed.value().nonce.bytes.data(), sealed.value().nonce.bytes.size());
            a.embed(sealed.value().mac.data(), sealed.value().mac.size());
            a.embed(sealed.value().ciphertext.data(), sealed.value().ciphertext.size());
        } else {
            a.embed(plain_bytes.data(), plain_bytes.size());
        }
    }

    code.flatten();
    out_layout.entry_offsets.clear();
    out_layout.entry_offsets.reserve(progs.size());
    for (const auto& lbl : l_stubs) {
        out_layout.entry_offsets.push_back(code.label_offset(lbl));
    }
    out_layout.core_offset = code.label_offset(l_core);
    const auto& sec = code.section_by_id(0);
    return std::vector<std::uint8_t>(sec->buffer().data(), sec->buffer().data() + sec->buffer().size());
#endif
}

} // namespace bytemorph::prot::detail
