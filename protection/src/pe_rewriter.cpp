#include "bytemorph/prot/pe_rewriter.hpp"

#include "bytemorph/arch/x86_64/x86_64_disasm.hpp"
#include "bytemorph/arch/x86_64/x86_64_lifter.hpp"
#include "bytemorph/core/analysis/analyzer.hpp"
#include "bytemorph/core/binary/loader.hpp"
#include "bytemorph/formats/pe/pe_parser.hpp"
#include "bytemorph/obf/obfuscation_engine.hpp"
#include "bytemorph/virt/bvm_format.hpp"
#include "bytemorph/virt/ir_to_vm.hpp"

#include <LIEF/PE.hpp>

#if defined(BYTEMORPH_HAS_ASMJIT)
#include <asmjit/x86.h>
#endif

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

std::uint32_t align_up(std::uint32_t v, std::uint32_t align) noexcept {
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

#if defined(BYTEMORPH_HAS_ASMJIT)
/// Emits a 100% Position-Independent (PIC) Win64 x86-64 native VM interpreter + embedded bytecode
/// into .bmrt (R-X) so ASLR relocations are unnecessary.
diagnostics::Result<std::vector<std::uint8_t>> emit_pic_x64_vm_runtime(const BvmProgram& prog) {
    asmjit::Environment env(asmjit::Arch::kX64);
    asmjit::CodeHolder code;
    code.init(env);
    asmjit::x86::Assembler a(&code);

    using namespace asmjit;

    Label l_bytecode = a.new_label();
    Label l_vm_loop = a.new_label();
    Label l_vm_done = a.new_label();
    Label l_take_branch = a.new_label();

    Label l_op_nop = a.new_label();
    Label l_op_movreg = a.new_label();
    Label l_op_movimm = a.new_label();
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

    // Entry point (offset 0 of .bmrt):
    // Save non-volatile Win64 registers (8 pushes = 64 bytes; +8 retaddr = 72)
    a.push(x86::rbx);
    a.push(x86::rbp);
    a.push(x86::rdi);
    a.push(x86::rsi);
    a.push(x86::r12);
    a.push(x86::r13);
    a.push(x86::r14);
    a.push(x86::r15);

    // Allocate 32 * 8 = 256 bytes for VM registers + 8 bytes alignment = 264 (total frame 336 = 21 * 16)
    a.sub(x86::rsp, 264);

    // Zero R0..R31
    a.xor_(x86::eax, x86::eax);
    a.mov(x86::rdi, x86::rsp);
    a.mov(x86::r10d, 32);
    Label l_zero_loop = a.new_label();
    a.bind(l_zero_loop);
    a.mov(x86::qword_ptr(x86::rdi), x86::rax);
    a.add(x86::rdi, 8);
    a.dec(x86::r10d);
    a.jnz(l_zero_loop);

    // Populate Win64 ABI argument registers into VM R1 (rcx), R2 (rdx), R8 (r8), R9 (r9)
    a.mov(x86::qword_ptr(x86::rsp, 1 * 8), x86::rcx);
    a.mov(x86::qword_ptr(x86::rsp, 2 * 8), x86::rdx);
    a.mov(x86::qword_ptr(x86::rsp, 8 * 8), x86::r8);
    a.mov(x86::qword_ptr(x86::rsp, 9 * 8), x86::r9);

    // Load RIP-relative pointer to embedded bytecode
    a.lea(x86::r10, x86::ptr(l_bytecode));
    a.mov(x86::r12d, x86::dword_ptr(x86::r10)); // insn_count
    a.lea(x86::r13, x86::ptr(x86::r10, 4));     // insn_base
    a.xor_(x86::r14d, x86::r14d);               // pc = 0
    a.xor_(x86::r15d, x86::r15d);               // flags = 0 (bit0=ZF, bit1=SF)

    a.bind(l_vm_loop);
    a.cmp(x86::r14d, x86::r12d);
    a.jae(l_vm_done);

    // rbx = r13 + r14 * 12
    a.imul(x86::rbx, x86::r14, 12);
    a.add(x86::rbx, x86::r13);

    a.movzx(x86::eax, x86::byte_ptr(x86::rbx, 0));  // opcode
    a.movzx(x86::ecx, x86::byte_ptr(x86::rbx, 1));  // dst
    a.movzx(x86::r8d, x86::byte_ptr(x86::rbx, 2));  // src1
    a.movzx(x86::r9d, x86::byte_ptr(x86::rbx, 3));  // src2
    a.mov(x86::r11, x86::qword_ptr(x86::rbx, 4));   // imm

    a.cmp(x86::eax, static_cast<int>(VmOpcode::Nop));    a.je(l_op_nop);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::MovReg)); a.je(l_op_movreg);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::MovImm)); a.je(l_op_movimm);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Add));    a.je(l_op_add);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Sub));    a.je(l_op_sub);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Mul));    a.je(l_op_mul);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Div));    a.je(l_op_div);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::And));    a.je(l_op_and);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Or));     a.je(l_op_or);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Xor));    a.je(l_op_xor);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Shl));    a.je(l_op_shl);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Shr));    a.je(l_op_shr);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Cmp));    a.je(l_op_cmp);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jmp));    a.je(l_op_jmp);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jeq));    a.je(l_op_jeq);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jne));    a.je(l_op_jne);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jlt));    a.je(l_op_jlt);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jle));    a.je(l_op_jle);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jgt));    a.je(l_op_jgt);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Jge));    a.je(l_op_jge);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Ret));    a.je(l_op_ret);
    a.cmp(x86::eax, static_cast<int>(VmOpcode::Halt));   a.je(l_op_ret);
    a.jmp(l_vm_done);

    auto emit_update_flags = [&]() {
        a.test(x86::rax, x86::rax);
        a.setz(x86::r15b);
        a.sets(x86::dl);
        a.shl(x86::dl, 1);
        a.or_(x86::r15b, x86::dl);
    };

    a.bind(l_op_nop);
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_movreg);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_movimm);
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::r11);
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_add);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.add(x86::rax, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    emit_update_flags();
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_sub);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.sub(x86::rax, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    emit_update_flags();
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_mul);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.imul(x86::rax, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    emit_update_flags();
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_div);
    a.mov(x86::r10, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.test(x86::r10, x86::r10);
    a.jz(l_vm_done);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.xor_(x86::edx, x86::edx);
    a.div(x86::r10);
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    emit_update_flags();
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_and);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.and_(x86::rax, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    emit_update_flags();
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_or);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.or_(x86::rax, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    emit_update_flags();
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_xor);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.xor_(x86::rax, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.mov(x86::qword_ptr(x86::rsp, x86::rcx, 3), x86::rax);
    emit_update_flags();
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_shl);
    a.mov(x86::r10, x86::rcx);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.mov(x86::rcx, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.shl(x86::rax, x86::cl);
    a.mov(x86::qword_ptr(x86::rsp, x86::r10, 3), x86::rax);
    emit_update_flags();
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_shr);
    a.mov(x86::r10, x86::rcx);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.mov(x86::rcx, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.shr(x86::rax, x86::cl);
    a.mov(x86::qword_ptr(x86::rsp, x86::r10, 3), x86::rax);
    emit_update_flags();
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_cmp);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp, x86::r8, 3));
    a.cmp(x86::rax, x86::qword_ptr(x86::rsp, x86::r9, 3));
    a.setz(x86::r15b);
    a.sets(x86::dl);
    a.shl(x86::dl, 1);
    a.or_(x86::r15b, x86::dl);
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_jmp);
    a.bind(l_take_branch);
    a.mov(x86::r14d, x86::r11d);
    a.jmp(l_vm_loop);

    a.bind(l_op_jeq);
    a.test(x86::r15d, 1);
    a.jnz(l_take_branch);
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_jne);
    a.test(x86::r15d, 1);
    a.jz(l_take_branch);
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_jlt);
    a.test(x86::r15d, 2);
    a.jnz(l_take_branch);
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_jle);
    a.test(x86::r15d, 3);
    a.jnz(l_take_branch);
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_jgt);
    a.test(x86::r15d, 3);
    a.jz(l_take_branch);
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_jge);
    a.test(x86::r15d, 2);
    a.jz(l_take_branch);
    a.inc(x86::r14d);
    a.jmp(l_vm_loop);

    a.bind(l_op_ret);
    a.bind(l_vm_done);
    a.mov(x86::rax, x86::qword_ptr(x86::rsp)); // R0
    a.add(x86::rsp, 264);
    a.pop(x86::r15);
    a.pop(x86::r14);
    a.pop(x86::r13);
    a.pop(x86::r12);
    a.pop(x86::rsi);
    a.pop(x86::rdi);
    a.pop(x86::rbp);
    a.pop(x86::rbx);
    a.ret();

    // Embed bytecode table immediately after stub
    a.align(AlignMode::kData, 8);
    a.bind(l_bytecode);
    a.dd(static_cast<uint32_t>(prog.instructions.size()));
    for (const auto& insn : prog.instructions) {
        a.db(static_cast<uint8_t>(insn.opcode));
        a.db(insn.dst);
        a.db(insn.src1);
        a.db(insn.src2);
        a.dq(static_cast<uint64_t>(insn.imm));
    }

    code.flatten();
    const auto& sec = code.section_by_id(0);
    std::vector<std::uint8_t> out(sec->buffer().data(), sec->buffer().data() + sec->buffer().size());
    return out;
}
#endif

} // namespace

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

    auto bvm_res = IrToVmTranslator::translate(ir_fn, options.seed);
    if (!bvm_res) {
        return diagnostics::Result<ProtectionReport>::err(
            bvm_res.error().code,
            "Function is not eligible for v0.4 selective virtualization: " + bvm_res.error().message,
            "PeRewriter::protect_file");
    }

    auto runtime_bytes_res = emit_pic_x64_vm_runtime(bvm_res.value());
    if (!runtime_bytes_res) {
        return diagnostics::Result<ProtectionReport>::err(
            runtime_bytes_res.error().code, runtime_bytes_res.error().message, "PeRewriter::protect_file");
    }
    const auto& runtime_bytes = runtime_bytes_res.value();

    // Find .text section in LIEF PE and compute next aligned RVA for .bmrt and .bmvm
    LIEF::PE::Section* text_sec = pe->get_section(".text");
    if (!text_sec) {
        return diagnostics::Result<ProtectionReport>::err(ErrorCode::ParseError, "PE missing .text section", "PeRewriter::protect_file");
    }

    const std::uint32_t sec_align = pe->optional_header().section_alignment();
    std::uint32_t max_rva_end = 0;
    for (const auto& s : pe->sections()) {
        const std::uint32_t end = static_cast<std::uint32_t>(s.virtual_address() + (std::max)(s.virtual_size(), s.sizeof_raw_data()));
        if (end > max_rva_end) max_rva_end = end;
    }
    const std::uint32_t bmrt_rva = align_up(max_rva_end, sec_align);
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

bool ElfRewriter::supports(BinaryFormat fmt, Architecture arch) const noexcept {
    return fmt == BinaryFormat::ELF64 && arch == Architecture::X86_64;
}

diagnostics::Result<ProtectionReport>
ElfRewriter::protect_file(const std::filesystem::path&, const std::filesystem::path&, const ProtectOptions&) const {
    return diagnostics::Result<ProtectionReport>::err(
        diagnostics::ErrorCode::NotImplemented,
        "ELF64 binary rewriting is planned for v0.5 (v0.4 supports PE32+ x86-64)",
        "ElfRewriter::protect_file");
}

diagnostics::Result<VerifyReport>
ElfRewriter::verify_file(const std::filesystem::path&) const {
    return diagnostics::Result<VerifyReport>::err(
        diagnostics::ErrorCode::NotImplemented,
        "ELF64 protection verification is planned for v0.5",
        "ElfRewriter::verify_file");
}

bool MachORewriter::supports(BinaryFormat fmt, Architecture arch) const noexcept {
    return fmt == BinaryFormat::MachO64 && (arch == Architecture::X86_64 || arch == Architecture::ARM64);
}

diagnostics::Result<ProtectionReport>
MachORewriter::protect_file(const std::filesystem::path&, const std::filesystem::path&, const ProtectOptions&) const {
    return diagnostics::Result<ProtectionReport>::err(
        diagnostics::ErrorCode::NotImplemented,
        "Mach-O 64-bit binary rewriting is planned for v0.5 (code signing requirements respected)",
        "MachORewriter::protect_file");
}

diagnostics::Result<VerifyReport>
MachORewriter::verify_file(const std::filesystem::path&) const {
    return diagnostics::Result<VerifyReport>::err(
        diagnostics::ErrorCode::NotImplemented,
        "Mach-O protection verification is planned for v0.5",
        "MachORewriter::verify_file");
}

} // namespace bytemorph::prot
