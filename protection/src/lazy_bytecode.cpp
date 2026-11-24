#include "bytemorph/prot/lazy_bytecode.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace bytemorph::prot {

namespace {

void append_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFFu));
}

void append_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFFu));
}

std::uint32_t read_u32(const std::uint8_t* p) noexcept {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint64_t read_u64(const std::uint8_t* p) noexcept {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(p[i]) << (i * 8);
    return v;
}

} // namespace

std::vector<std::uint8_t>
LazyBytecodeEngine::build_block_aad(std::uint32_t fn_index,
                                    std::uint32_t block_id,
                                    std::uint32_t start_pc,
                                    std::uint32_t insn_count,
                                    std::uint32_t plain_bytes) {
    std::vector<std::uint8_t> aad;
    aad.reserve(26);
    append_u32(aad, LazyBlockRecord::kMagic);
    aad.push_back(static_cast<std::uint8_t>(LazyBlockRecord::kVersion & 0xFFu));
    aad.push_back(static_cast<std::uint8_t>((LazyBlockRecord::kVersion >> 8) & 0xFFu));
    append_u32(aad, fn_index);
    append_u32(aad, block_id);
    append_u32(aad, start_pc);
    append_u32(aad, insn_count);
    append_u32(aad, plain_bytes);
    return aad;
}

core::diagnostics::Result<LazyFunctionBlob>
LazyBytecodeEngine::seal_function(const virt::BvmProgram& program,
                                  const AeadKey& master_key,
                                  std::uint64_t seed,
                                  std::uint32_t fn_index) {
    using core::diagnostics::ErrorCode;
    if (program.instructions.empty()) {
        return core::diagnostics::Result<LazyFunctionBlob>::err(
            ErrorCode::EmptyInput, "Cannot seal empty BvmProgram", "LazyBytecodeEngine::seal_function");
    }

    const auto blocks = virt::VmInterpreter::split_into_basic_blocks(program);
    const auto op_table = virt::BvmCodec::make_opcode_table(program.build_seed);

    LazyFunctionBlob blob;
    blob.fn_index = fn_index;
    blob.total_insns = static_cast<std::uint32_t>(program.instructions.size());
    blob.build_seed = program.build_seed;
    blob.blocks.reserve(blocks.size());

    for (const auto& blk : blocks) {
        std::vector<std::uint8_t> plain;
        plain.reserve(blk.instructions.size() * virt::BvmProgram::kInstructionSize);
        for (const auto& insn : blk.instructions) {
            const auto logical = static_cast<std::uint8_t>(insn.opcode);
            const std::uint8_t phys = (logical < virt::BvmProgram::kOpcodeTableSize) ? op_table[logical] : logical;
            plain.push_back(phys);
            plain.push_back(insn.dst);
            plain.push_back(insn.src1);
            plain.push_back(insn.src2);
            append_u64(plain, static_cast<std::uint64_t>(insn.imm));
        }

        AeadKey blk_key = CryptoAead::derive_block_key(master_key, fn_index, blk.block_id, "bm.lazy.block.v1");
        const AeadNonce nonce = CryptoAead::generate_block_nonce(seed, fn_index, blk.block_id);
        const auto aad = build_block_aad(
            fn_index, blk.block_id, static_cast<std::uint32_t>(blk.start_pc),
            static_cast<std::uint32_t>(blk.instructions.size()),
            static_cast<std::uint32_t>(plain.size()));

        auto sealed = CryptoAead::seal(plain, aad, blk_key, nonce);
        CryptoAead::secure_wipe(blk_key.bytes);
        CryptoAead::secure_wipe(plain);

        if (!sealed) {
            return core::diagnostics::Result<LazyFunctionBlob>::err(
                sealed.error().code, sealed.error().message, "LazyBytecodeEngine::seal_function");
        }

        LazyBlockRecord rec;
        rec.fn_index = fn_index;
        rec.block_id = blk.block_id;
        rec.start_pc = static_cast<std::uint32_t>(blk.start_pc);
        rec.insn_count = static_cast<std::uint32_t>(blk.instructions.size());
        rec.nonce = sealed.value().nonce;
        rec.mac = sealed.value().mac;
        rec.aad_hash = CryptoAead::blake2b_256(aad);
        rec.ciphertext = std::move(sealed.value().ciphertext);
        blob.blocks.push_back(std::move(rec));
    }

    return blob;
}

core::diagnostics::Result<std::vector<virt::VmInstruction>>
LazyBytecodeEngine::open_block(const LazyBlockRecord& rec,
                               const AeadKey& master_key,
                               std::uint32_t expected_fn_index,
                               std::uint64_t build_seed) {
    using core::diagnostics::ErrorCode;

    if (rec.fn_index != expected_fn_index) {
        return core::diagnostics::Result<std::vector<virt::VmInstruction>>::err(
            ErrorCode::ParseError, "Lazy block fn_index mismatch (possible block substitution)",
            "LazyBytecodeEngine::open_block");
    }
    if (rec.insn_count == 0 ||
        rec.ciphertext.size() != static_cast<std::size_t>(rec.insn_count) * virt::BvmProgram::kInstructionSize) {
        return core::diagnostics::Result<std::vector<virt::VmInstruction>>::err(
            ErrorCode::ParseError, "Lazy block size/instruction count mismatch",
            "LazyBytecodeEngine::open_block");
    }

    const auto aad = build_block_aad(
        rec.fn_index, rec.block_id, rec.start_pc, rec.insn_count,
        static_cast<std::uint32_t>(rec.ciphertext.size()));
    if (CryptoAead::blake2b_256(aad) != rec.aad_hash) {
        return core::diagnostics::Result<std::vector<virt::VmInstruction>>::err(
            ErrorCode::ParseError, "Lazy block AAD hash mismatch", "LazyBytecodeEngine::open_block");
    }

    AeadSealedBox box;
    box.nonce = rec.nonce;
    box.mac = rec.mac;
    box.ciphertext = rec.ciphertext;

    AeadKey blk_key = CryptoAead::derive_block_key(master_key, rec.fn_index, rec.block_id, "bm.lazy.block.v1");
    auto plain_res = CryptoAead::open(box, aad, blk_key);
    CryptoAead::secure_wipe(blk_key.bytes);

    if (!plain_res) {
        return core::diagnostics::Result<std::vector<virt::VmInstruction>>::err(
            plain_res.error().code, plain_res.error().message, "LazyBytecodeEngine::open_block");
    }

    auto& plain = plain_res.value();
    const auto op_table = virt::BvmCodec::make_opcode_table(build_seed);
    std::array<std::uint8_t, virt::BvmProgram::kOpcodeTableSize> inv_table{};
    inv_table.fill(0xFFu);
    for (std::size_t i = 0; i < virt::BvmProgram::kOpcodeTableSize; ++i) {
        if (op_table[i] < virt::BvmProgram::kOpcodeTableSize) {
            inv_table[op_table[i]] = static_cast<std::uint8_t>(i);
        }
    }

    std::vector<virt::VmInstruction> insns;
    insns.reserve(rec.insn_count);
    for (std::uint32_t i = 0; i < rec.insn_count; ++i) {
        const std::uint8_t* p = plain.data() + static_cast<std::size_t>(i) * virt::BvmProgram::kInstructionSize;
        const std::uint8_t phys = p[0];
        const std::uint8_t logical = (phys < virt::BvmProgram::kOpcodeTableSize) ? inv_table[phys] : 0xFFu;
        if (logical >= static_cast<std::uint8_t>(virt::VmOpcode::MaxOpcode)) {
            CryptoAead::secure_wipe(plain);
            return core::diagnostics::Result<std::vector<virt::VmInstruction>>::err(
                ErrorCode::ParseError, "Invalid decoded opcode in lazy block", "LazyBytecodeEngine::open_block");
        }
        virt::VmInstruction vi;
        vi.opcode = static_cast<virt::VmOpcode>(logical);
        vi.dst = p[1];
        vi.src1 = p[2];
        vi.src2 = p[3];
        vi.imm = static_cast<std::int64_t>(read_u64(p + 4));
        insns.push_back(vi);
    }

    CryptoAead::secure_wipe(plain);
    return insns;
}

core::diagnostics::Result<bool>
LazyBytecodeEngine::verify_block_aead(const LazyBlockRecord& rec, const AeadKey& master_key) {
    using core::diagnostics::ErrorCode;
    if (rec.insn_count == 0 ||
        rec.ciphertext.size() != static_cast<std::size_t>(rec.insn_count) * virt::BvmProgram::kInstructionSize) {
        return core::diagnostics::Result<bool>::err(
            ErrorCode::ParseError, "Lazy block size/instruction count mismatch",
            "LazyBytecodeEngine::verify_block_aead");
    }
    const auto aad = build_block_aad(
        rec.fn_index, rec.block_id, rec.start_pc, rec.insn_count,
        static_cast<std::uint32_t>(rec.ciphertext.size()));
    if (CryptoAead::blake2b_256(aad) != rec.aad_hash) {
        return core::diagnostics::Result<bool>::err(
            ErrorCode::ParseError, "Lazy block AAD hash mismatch", "LazyBytecodeEngine::verify_block_aead");
    }
    AeadSealedBox box;
    box.nonce = rec.nonce;
    box.mac = rec.mac;
    box.ciphertext = rec.ciphertext;
    AeadKey blk_key = CryptoAead::derive_block_key(master_key, rec.fn_index, rec.block_id, "bm.lazy.block.v1");
    auto plain_res = CryptoAead::open(box, aad, blk_key);
    CryptoAead::secure_wipe(blk_key.bytes);
    if (!plain_res) {
        return core::diagnostics::Result<bool>::err(
            plain_res.error().code, plain_res.error().message, "LazyBytecodeEngine::verify_block_aead");
    }
    CryptoAead::secure_wipe(plain_res.value());
    return true;
}

core::diagnostics::Result<bool>
LazyBytecodeEngine::verify_all_blocks(const LazyFunctionBlob& blob, const AeadKey& master_key) {
    using core::diagnostics::ErrorCode;
    if (blob.blocks.empty()) {
        return core::diagnostics::Result<bool>::err(
            ErrorCode::EmptyInput, "LazyFunctionBlob has no blocks", "LazyBytecodeEngine::verify_all_blocks");
    }

    std::unordered_set<std::uint32_t> seen_ids;
    std::unordered_set<std::string> seen_nonces;
    std::uint32_t expected_pc = 0;
    for (const auto& blk : blob.blocks) {
        if (!seen_ids.insert(blk.block_id).second) {
            return core::diagnostics::Result<bool>::err(
                ErrorCode::ParseError, "Duplicate lazy block_id detected", "LazyBytecodeEngine::verify_all_blocks");
        }
        std::string nkey(reinterpret_cast<const char*>(blk.nonce.bytes.data()), blk.nonce.bytes.size());
        if (!seen_nonces.insert(std::move(nkey)).second) {
            return core::diagnostics::Result<bool>::err(
                ErrorCode::ParseError, "Duplicate lazy block nonce detected", "LazyBytecodeEngine::verify_all_blocks");
        }
        if (blk.start_pc != expected_pc) {
            return core::diagnostics::Result<bool>::err(
                ErrorCode::ParseError, "Non-contiguous or reordered lazy block start_pc detected",
                "LazyBytecodeEngine::verify_all_blocks");
        }
        expected_pc += blk.insn_count;

        auto opened = open_block(blk, master_key, blob.fn_index, blob.build_seed);
        if (!opened) {
            return core::diagnostics::Result<bool>::err(
                opened.error().code, opened.error().message, "LazyBytecodeEngine::verify_all_blocks");
        }
    }
    if (expected_pc != blob.total_insns) {
        return core::diagnostics::Result<bool>::err(
            ErrorCode::ParseError, "Lazy block instruction count sum does not match total_insns",
            "LazyBytecodeEngine::verify_all_blocks");
    }
    return true;
}

core::diagnostics::Result<virt::VmExecState>
LazyBytecodeEngine::execute_lazy(const LazyFunctionBlob& blob,
                                 const AeadKey& master_key,
                                 virt::VmBytecodeCache& cache,
                                 const virt::VmExecOptions& options) {
    using core::diagnostics::ErrorCode;
    if (blob.blocks.empty() || blob.total_insns == 0) {
        return core::diagnostics::Result<virt::VmExecState>::err(
            ErrorCode::EmptyInput, "LazyFunctionBlob is empty", "LazyBytecodeEngine::execute_lazy");
    }

    std::vector<std::size_t> block_starts;
    block_starts.reserve(blob.blocks.size());
    for (const auto& b : blob.blocks) {
        block_starts.push_back(b.start_pc);
    }

    const std::uint64_t ctx_id =
        (static_cast<std::uint64_t>(blob.fn_index) << 32) ^ blob.build_seed;

    auto fetcher = [&](std::size_t start_pc) -> core::diagnostics::Result<std::vector<virt::VmInstruction>> {
        for (const auto& blk : blob.blocks) {
            if (blk.start_pc == start_pc) {
                return open_block(blk, master_key, blob.fn_index, blob.build_seed);
            }
        }
        return core::diagnostics::Result<std::vector<virt::VmInstruction>>::err(
            ErrorCode::OutOfBounds, "Requested lazy block start_pc not found", "LazyBytecodeEngine::execute_lazy");
    };

    return virt::VmInterpreter::execute_lazy(
        blob.total_insns, ctx_id, block_starts, fetcher, cache, options);
}

} // namespace bytemorph::prot
