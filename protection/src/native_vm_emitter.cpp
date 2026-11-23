#include "bytemorph/prot/native_vm_emitter.hpp"

#if defined(BYTEMORPH_HAS_ASMJIT)
#include <asmjit/a64.h>
#include <asmjit/x86.h>
#endif

#include <cstring>

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
    out.push_back(0);
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
    if (read_u16(data, 4) != ProtectionMetadata::kVersion) {
        return diagnostics::Result<ProtectionMetadata>::err(
            ErrorCode::UnsupportedFormat, "Unsupported BMP4 metadata version", "deserialize_metadata");
    }

    ProtectionMetadata m;
    const std::uint8_t prof = data[6];
    if (prof > 2) {
        return diagnostics::Result<ProtectionMetadata>::err(ErrorCode::ParseError, "Invalid protection profile", "deserialize_metadata");
    }
    m.profile = static_cast<ProtectionProfile>(prof);
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

diagnostics::Result<std::vector<std::uint8_t>>
emit_pic_x64_vm_runtime(const BvmProgram& prog, AbiKind abi) {
#if !defined(BYTEMORPH_HAS_ASMJIT)
    (void)prog;
    (void)abi;
    return diagnostics::Result<std::vector<std::uint8_t>>::err(
        diagnostics::ErrorCode::NotImplemented, "AsmJit is disabled", "emit_pic_x64_vm_runtime");
#else
    asmjit::Environment env(asmjit::Arch::kX64);
    asmjit::CodeHolder code;
    code.init(env);
    asmjit::x86::Assembler a(&code);
    using namespace asmjit;

    Label l_entry = a.new_label();
    Label l_bytecode = a.new_label();
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
    Label l_op_jmp = a.new_label();
    Label l_op_jeq = a.new_label();
    Label l_op_jne = a.new_label();
    Label l_op_jlt = a.new_label();
    Label l_op_jle = a.new_label();
    Label l_op_jgt = a.new_label();
    Label l_op_jge = a.new_label();
    Label l_op_ret = a.new_label();
    Label l_op_callext = a.new_label();

    a.bind(l_entry);
    a.push(x86::rbx);
    a.push(x86::rbp);
    a.push(x86::rdi);
    a.push(x86::rsi);
    a.push(x86::r12);
    a.push(x86::r13);
    a.push(x86::r14);
    a.push(x86::r15);

    // 8 pushes (64B) + retaddr (8B) + 1288B (256B VM regs + 1032B virtual stack frame) = 1360B (16-byte aligned)
    a.sub(x86::rsp, 1288);

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

    // Copy 64B of caller stack arguments / shadow space from [caller_rsp + 8] ([rsp + 1352 + 8]) to [R4 + 8]
    for (int i = 1; i <= 8; ++i) {
        a.mov(x86::r10, x86::qword_ptr(x86::rsp, 1352 + i * 8));
        a.mov(x86::qword_ptr(x86::rsp, 896 + i * 8), x86::r10);
    }

    // Restore rdi from saved stack slot for SysV arg0 (push order: rbx, rbp, rdi -> [rsp + 1288 + 5*8])
    if (abi == AbiKind::Win64) {
        a.mov(x86::qword_ptr(x86::rsp, 1 * 8), x86::rcx);
        a.mov(x86::qword_ptr(x86::rsp, 2 * 8), x86::rdx);
        a.mov(x86::qword_ptr(x86::rsp, 8 * 8), x86::r8);
        a.mov(x86::qword_ptr(x86::rsp, 9 * 8), x86::r9);
    } else {
        // System V AMD64: rdi->R7, rsi->R6, rdx->R2, rcx->R1, r8->R8, r9->R9
        a.mov(x86::rax, x86::qword_ptr(x86::rsp, 1288 + 5 * 8));
        a.mov(x86::qword_ptr(x86::rsp, 7 * 8), x86::rax);
        a.mov(x86::qword_ptr(x86::rsp, 6 * 8), x86::rsi);
        a.mov(x86::qword_ptr(x86::rsp, 2 * 8), x86::rdx);
        a.mov(x86::qword_ptr(x86::rsp, 1 * 8), x86::rcx);
        a.mov(x86::qword_ptr(x86::rsp, 8 * 8), x86::r8);
        a.mov(x86::qword_ptr(x86::rsp, 9 * 8), x86::r9);
    }

    a.lea(x86::r10, x86::ptr(l_bytecode));
    a.mov(x86::r12d, x86::dword_ptr(x86::r10));
    a.lea(x86::r13, x86::ptr(x86::r10, 4));
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
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Cmp));     a.je(l_op_cmp);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jmp));     a.je(l_op_jmp);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jeq));     a.je(l_op_jeq);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jne));     a.je(l_op_jne);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jlt));     a.je(l_op_jlt);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jle));     a.je(l_op_jle);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jgt));     a.je(l_op_jgt);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jge));     a.je(l_op_jge);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Ret));     a.je(l_op_ret);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Halt));    a.je(l_op_ret);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::CallExt)); a.je(l_op_callext);
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
    a.shl(x86::dl, 1);
    a.or_(x86::r15b, x86::dl);
    a.inc(x86::r14d); a.jmp(l_vm_loop);

    a.bind(l_op_jmp);
    a.bind(l_take_branch);
    a.mov(x86::r14d, x86::r11d);
    a.jmp(l_vm_loop);

    a.bind(l_op_jeq); a.test(x86::r15d, 1); a.jnz(l_take_branch); a.inc(x86::r14d); a.jmp(l_vm_loop);
    a.bind(l_op_jne); a.test(x86::r15d, 1); a.jz(l_take_branch);  a.inc(x86::r14d); a.jmp(l_vm_loop);
    a.bind(l_op_jlt); a.test(x86::r15d, 2); a.jnz(l_take_branch); a.inc(x86::r14d); a.jmp(l_vm_loop);
    a.bind(l_op_jle); a.test(x86::r15d, 3); a.jnz(l_take_branch); a.inc(x86::r14d); a.jmp(l_vm_loop);
    a.bind(l_op_jgt); a.test(x86::r15d, 3); a.jz(l_take_branch);  a.inc(x86::r14d); a.jmp(l_vm_loop);
    a.bind(l_op_jge); a.test(x86::r15d, 2); a.jz(l_take_branch);  a.inc(x86::r14d); a.jmp(l_vm_loop);

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

    a.bind(l_op_ret);
    a.bind(l_vm_done);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp));
    a.add(x86::rsp, 1288);
    a.pop(x86::r15);
    a.pop(x86::r14);
    a.pop(x86::r13);
    a.pop(x86::r12);
    a.pop(x86::rsi);
    a.pop(x86::rdi);
    a.pop(x86::rbp);
    a.pop(x86::rbx);
    a.ret();

    a.align(AlignMode::kData, 8);
    a.bind(l_bytecode);
    const std::uint32_t insn_count = static_cast<std::uint32_t>(prog.instructions.size());
    a.embed(&insn_count, sizeof(insn_count));
    for (const auto& insn : prog.instructions) {
        std::uint8_t raw[12]{};
        raw[0] = static_cast<std::uint8_t>(insn.opcode);
        raw[1] = insn.dst;
        raw[2] = insn.src1;
        raw[3] = insn.src2;
        const std::uint64_t imm_u = static_cast<std::uint64_t>(insn.imm);
        std::memcpy(raw + 4, &imm_u, 8);
        a.embed(raw, sizeof(raw));
    }

    code.flatten();
    const auto& sec = code.section_by_id(0);
    return std::vector<std::uint8_t>(sec->buffer().data(), sec->buffer().data() + sec->buffer().size());
#endif
}

diagnostics::Result<std::vector<std::uint8_t>>
emit_pic_arm64_vm_runtime(const BvmProgram& prog) {
#if !defined(BYTEMORPH_HAS_ASMJIT)
    (void)prog;
    return diagnostics::Result<std::vector<std::uint8_t>>::err(
        diagnostics::ErrorCode::NotImplemented, "AsmJit is disabled", "emit_pic_arm64_vm_runtime");
#else
    asmjit::Environment env(asmjit::Arch::kAArch64);
    asmjit::CodeHolder code;
    code.init(env);
    asmjit::a64::Assembler a(&code);
    using namespace asmjit;

    Label l_entry = a.new_label();
    Label l_bytecode = a.new_label();
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
    Label l_op_jmp = a.new_label();
    Label l_op_jeq = a.new_label();
    Label l_op_jne = a.new_label();
    Label l_op_jlt = a.new_label();
    Label l_op_jle = a.new_label();
    Label l_op_jgt = a.new_label();
    Label l_op_jge = a.new_label();
    Label l_op_ret = a.new_label();
    Label l_op_callext = a.new_label();

    // AAPCS64 / Apple ARM64 ABI:
    // Save x19-x28, x29, x30 (12 regs = 96B) + 1280B (256B VM regs + 1024B virtual stack frame) = 1376B (16B aligned)
    a.bind(l_entry);
    a.stp(a64::x29, a64::x30, a64::ptr_pre(a64::sp, -96));
    a.stp(a64::x19, a64::x20, a64::ptr(a64::sp, 16));
    a.stp(a64::x21, a64::x22, a64::ptr(a64::sp, 32));
    a.stp(a64::x23, a64::x24, a64::ptr(a64::sp, 48));
    a.stp(a64::x25, a64::x26, a64::ptr(a64::sp, 64));
    a.stp(a64::x27, a64::x28, a64::ptr(a64::sp, 80));
    a.sub(a64::sp, a64::sp, 1280);

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

    a.adr(a64::x19, l_bytecode);
    a.ldr(a64::w20, a64::ptr(a64::x19));       // insn_count
    a.add(a64::x21, a64::x19, 4);              // insn_base
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
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Cmp));     a.b_eq(l_op_cmp);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Jmp));     a.b_eq(l_op_jmp);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Jeq));     a.b_eq(l_op_jeq);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Jne));     a.b_eq(l_op_jne);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Jlt));     a.b_eq(l_op_jlt);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Jle));     a.b_eq(l_op_jle);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Jgt));     a.b_eq(l_op_jgt);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Jge));     a.b_eq(l_op_jge);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Ret));     a.b_eq(l_op_ret);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::Halt));    a.b_eq(l_op_ret);
    a.cmp(a64::w10, static_cast<int>(VmOpcode::CallExt)); a.b_eq(l_op_callext);
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
    a.cset(a64::w15, a64::CondCode::kLT);
    a.orr(a64::w23, a64::w23, a64::w15, a64::lsl(1));
    a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);

    a.bind(l_op_jmp);
    a.bind(l_take_branch);
    a.mov(a64::w22, a64::w14);
    a.b(l_vm_loop);

    a.bind(l_op_jeq); a.tst(a64::w23, 1); a.b_ne(l_take_branch); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    a.bind(l_op_jne); a.tst(a64::w23, 1); a.b_eq(l_take_branch); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    a.bind(l_op_jlt); a.tst(a64::w23, 2); a.b_ne(l_take_branch); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    a.bind(l_op_jle); a.tst(a64::w23, 3); a.b_ne(l_take_branch); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    a.bind(l_op_jgt); a.tst(a64::w23, 3); a.b_eq(l_take_branch); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);
    a.bind(l_op_jge); a.tst(a64::w23, 2); a.b_eq(l_take_branch); a.add(a64::w22, a64::w22, 1); a.b(l_vm_loop);

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

    a.bind(l_op_ret);
    a.bind(l_vm_done);
    a.ldr(a64::x0, a64::ptr(a64::sp, 0));
    a.add(a64::sp, a64::sp, 1280);
    a.ldp(a64::x19, a64::x20, a64::ptr(a64::sp, 16));
    a.ldp(a64::x21, a64::x22, a64::ptr(a64::sp, 32));
    a.ldp(a64::x23, a64::x24, a64::ptr(a64::sp, 48));
    a.ldp(a64::x25, a64::x26, a64::ptr(a64::sp, 64));
    a.ldp(a64::x27, a64::x28, a64::ptr(a64::sp, 80));
    a.ldp(a64::x29, a64::x30, a64::ptr_post(a64::sp, 96));
    a.ret(a64::x30);

    a.align(AlignMode::kData, 8);
    a.bind(l_bytecode);
    const std::uint32_t insn_count = static_cast<std::uint32_t>(prog.instructions.size());
    a.embed(&insn_count, sizeof(insn_count));
    for (const auto& insn : prog.instructions) {
        std::uint8_t raw[12]{};
        raw[0] = static_cast<std::uint8_t>(insn.opcode);
        raw[1] = insn.dst;
        raw[2] = insn.src1;
        raw[3] = insn.src2;
        const std::uint64_t imm_u = static_cast<std::uint64_t>(insn.imm);
        std::memcpy(raw + 4, &imm_u, 8);
        a.embed(raw, sizeof(raw));
    }

    code.flatten();
    const auto& sec = code.section_by_id(0);
    return std::vector<std::uint8_t>(sec->buffer().data(), sec->buffer().data() + sec->buffer().size());
#endif
}

} // namespace bytemorph::prot::detail
