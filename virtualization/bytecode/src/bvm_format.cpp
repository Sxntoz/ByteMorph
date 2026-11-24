#include "bytemorph/virt/bvm_format.hpp"

#include <fstream>
#include <numeric>
#include <random>

namespace bytemorph::virt {

namespace {

std::uint32_t fnv1a_32(std::span<const std::uint8_t> data) noexcept {
    std::uint32_t h = 2166136261u;
    for (std::uint8_t b : data) {
        h ^= b;
        h *= 16777619u;
    }
    return h;
}

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

std::string_view to_string(VmOpcode op) noexcept {
    switch (op) {
        case VmOpcode::Nop: return "vm.nop";
        case VmOpcode::MovReg: return "vm.mov";
        case VmOpcode::MovImm: return "vm.movi";
        case VmOpcode::Load: return "vm.load";
        case VmOpcode::Store: return "vm.store";
        case VmOpcode::Add: return "vm.add";
        case VmOpcode::Sub: return "vm.sub";
        case VmOpcode::Mul: return "vm.mul";
        case VmOpcode::Div: return "vm.div";
        case VmOpcode::And: return "vm.and";
        case VmOpcode::Or: return "vm.or";
        case VmOpcode::Xor: return "vm.xor";
        case VmOpcode::Shl: return "vm.shl";
        case VmOpcode::Shr: return "vm.shr";
        case VmOpcode::Cmp: return "vm.cmp";
        case VmOpcode::Jmp: return "vm.jmp";
        case VmOpcode::Jeq: return "vm.jeq";
        case VmOpcode::Jne: return "vm.jne";
        case VmOpcode::Jlt: return "vm.jlt";
        case VmOpcode::Jle: return "vm.jle";
        case VmOpcode::Jgt: return "vm.jgt";
        case VmOpcode::Jge: return "vm.jge";
        case VmOpcode::Call: return "vm.call";
        case VmOpcode::Ret: return "vm.ret";
        case VmOpcode::Halt: return "vm.halt";
        case VmOpcode::CallExt: return "vm.callext";
        case VmOpcode::LeaPic: return "vm.leapic";
        case VmOpcode::SelectCc: return "vm.selectcc";
        case VmOpcode::SetCc: return "vm.setcc";
        case VmOpcode::MaxOpcode: return "vm.invalid";
    }
    return "vm.invalid";
}

std::array<std::uint8_t, BvmProgram::kOpcodeTableSize>
BvmCodec::make_opcode_table(std::uint64_t build_seed) noexcept {
    std::array<std::uint8_t, BvmProgram::kOpcodeTableSize> table{};
    std::iota(table.begin(), table.end(), std::uint8_t{0});
    if (build_seed != 0) {
        std::mt19937_64 rng(build_seed);
        for (std::size_t i = table.size() - 1; i > 0; --i) {
            const std::size_t j = static_cast<std::size_t>(rng() % (i + 1));
            std::swap(table[i], table[j]);
        }
    }
    return table;
}

core::diagnostics::Result<std::vector<std::uint8_t>>
BvmCodec::encode(const BvmProgram& program) {
    using core::diagnostics::ErrorCode;
    if (program.instructions.size() > BvmProgram::kMaxInstructions) {
        return core::diagnostics::Result<std::vector<std::uint8_t>>::err(
            ErrorCode::OutOfBounds, "Program exceeds max VM instruction count", "BvmCodec::encode");
    }

    const auto table = make_opcode_table(program.build_seed);
    std::vector<std::uint8_t> payload;
    payload.reserve(BvmProgram::kOpcodeTableSize + program.instructions.size() * BvmProgram::kInstructionSize);

    // Store logical -> physical mapping table
    payload.insert(payload.end(), table.begin(), table.end());

    for (const auto& insn : program.instructions) {
        const auto raw_op = static_cast<std::uint8_t>(insn.opcode);
        if (raw_op >= static_cast<std::uint8_t>(VmOpcode::MaxOpcode)) {
            return core::diagnostics::Result<std::vector<std::uint8_t>>::err(
                ErrorCode::ParseError, "Invalid VmOpcode in encode", "BvmCodec::encode");
        }
        const bool dst_is_trap = (insn.opcode == VmOpcode::Halt && insn.dst == 0xFF);
        const bool src2_is_width = (insn.opcode == VmOpcode::Load || insn.opcode == VmOpcode::Store);
        const bool valid_width = (insn.src2 == 0 || insn.src2 == 8 || insn.src2 == 16 || insn.src2 == 32 || insn.src2 == 64);
        if ((!dst_is_trap && insn.dst >= BvmProgram::kNumRegisters) ||
            insn.src1 >= BvmProgram::kNumRegisters ||
            (src2_is_width ? !valid_width : insn.src2 >= BvmProgram::kNumRegisters)) {
            return core::diagnostics::Result<std::vector<std::uint8_t>>::err(
                ErrorCode::OutOfBounds, "Register index out of bounds (>= 32)", "BvmCodec::encode");
        }
        payload.push_back(table[raw_op]);
        payload.push_back(insn.dst);
        payload.push_back(insn.src1);
        payload.push_back(insn.src2);
        write_u64(payload, static_cast<std::uint64_t>(insn.imm));
    }

    const std::uint32_t code_bytes = static_cast<std::uint32_t>(program.instructions.size() * BvmProgram::kInstructionSize);
    std::vector<std::uint8_t> out;
    out.reserve(24 + payload.size());
    write_u32(out, BvmProgram::kMagic);
    write_u16(out, BvmProgram::kVersion);
    write_u16(out, 0);
    write_u64(out, program.build_seed);
    write_u32(out, code_bytes);
    write_u32(out, fnv1a_32(payload));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

core::diagnostics::Result<BvmProgram>
BvmCodec::decode(std::span<const std::uint8_t> data) {
    using core::diagnostics::ErrorCode;
    constexpr std::size_t kHeaderSize = 24;
    if (data.size() < kHeaderSize + BvmProgram::kOpcodeTableSize) {
        return core::diagnostics::Result<BvmProgram>::err(
            ErrorCode::TruncatedData, "Bytecode buffer smaller than .bvm header", "BvmCodec::decode");
    }

    const std::uint32_t magic = read_u32(data, 0);
    const std::uint16_t version = read_u16(data, 4);
    const std::uint64_t seed = read_u64(data, 8);
    const std::uint32_t code_bytes = read_u32(data, 16);
    const std::uint32_t checksum = read_u32(data, 20);

    if (magic != BvmProgram::kMagic) {
        return core::diagnostics::Result<BvmProgram>::err(
            ErrorCode::InvalidMagic, "Invalid .bvm magic (expected BMVM)", "BvmCodec::decode");
    }
    if (version != BvmProgram::kVersion) {
        return core::diagnostics::Result<BvmProgram>::err(
            ErrorCode::UnsupportedFormat, "Unsupported .bvm version", "BvmCodec::decode");
    }
    if ((code_bytes % BvmProgram::kInstructionSize) != 0) {
        return core::diagnostics::Result<BvmProgram>::err(
            ErrorCode::ParseError, "Misaligned .bvm code size", "BvmCodec::decode");
    }
    const std::size_t insn_count = code_bytes / BvmProgram::kInstructionSize;
    if (insn_count > BvmProgram::kMaxInstructions) {
        return core::diagnostics::Result<BvmProgram>::err(
            ErrorCode::OutOfBounds, "Bytecode exceeds max instruction limit", "BvmCodec::decode");
    }

    const std::size_t expected_total = kHeaderSize + BvmProgram::kOpcodeTableSize + code_bytes;
    if (data.size() != expected_total) {
        return core::diagnostics::Result<BvmProgram>::err(
            ErrorCode::TruncatedData, "Bytecode size does not match header CodeSize", "BvmCodec::decode");
    }

    const auto payload = data.subspan(kHeaderSize);
    if (fnv1a_32(payload) != checksum) {
        return core::diagnostics::Result<BvmProgram>::err(
            ErrorCode::ParseError, "Bytecode checksum mismatch", "BvmCodec::decode");
    }

    // Build inverse mapping physical -> logical
    std::array<std::uint8_t, 256> inv{};
    inv.fill(0xFF);
    for (std::size_t logical = 0; logical < BvmProgram::kOpcodeTableSize; ++logical) {
        const std::uint8_t phys = payload[logical];
        if (phys >= BvmProgram::kOpcodeTableSize || inv[phys] != 0xFF) {
            return core::diagnostics::Result<BvmProgram>::err(
                ErrorCode::ParseError, "Corrupted .bvm opcode permutation table", "BvmCodec::decode");
        }
        inv[phys] = static_cast<std::uint8_t>(logical);
    }

    BvmProgram prog;
    prog.build_seed = seed;
    prog.instructions.reserve(insn_count);

    std::size_t off = BvmProgram::kOpcodeTableSize;
    for (std::size_t i = 0; i < insn_count; ++i) {
        const std::uint8_t phys_op = payload[off];
        const std::uint8_t logical_op = inv[phys_op];
        if (logical_op >= static_cast<std::uint8_t>(VmOpcode::MaxOpcode)) {
            return core::diagnostics::Result<BvmProgram>::err(
                ErrorCode::ParseError, "Invalid opcode in .bvm stream", "BvmCodec::decode");
        }
        const VmOpcode op = static_cast<VmOpcode>(logical_op);
        const std::uint8_t dst = payload[off + 1];
        const std::uint8_t src1 = payload[off + 2];
        const std::uint8_t src2 = payload[off + 3];
        const bool dst_is_trap = (op == VmOpcode::Halt && dst == 0xFF);
        const bool src2_is_width = (op == VmOpcode::Load || op == VmOpcode::Store);
        const bool valid_width = (src2 == 0 || src2 == 8 || src2 == 16 || src2 == 32 || src2 == 64);
        if ((!dst_is_trap && dst >= BvmProgram::kNumRegisters) ||
            src1 >= BvmProgram::kNumRegisters ||
            (src2_is_width ? !valid_width : src2 >= BvmProgram::kNumRegisters)) {
            return core::diagnostics::Result<BvmProgram>::err(
                ErrorCode::OutOfBounds, "Register index out of bounds in .bvm stream", "BvmCodec::decode");
        }
        const std::int64_t imm = static_cast<std::int64_t>(read_u64(payload, off + 4));
        prog.instructions.push_back(VmInstruction{
            static_cast<VmOpcode>(logical_op), dst, src1, src2, imm
        });
        off += BvmProgram::kInstructionSize;
    }

    return prog;
}

core::diagnostics::Result<void>
BvmCodec::save_to_file(const BvmProgram& program, const std::filesystem::path& path) {
    auto enc = encode(program);
    if (!enc) {
        return core::diagnostics::Result<void>::err(enc.error().code, enc.error().message, enc.error().context);
    }
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) {
        return core::diagnostics::Result<void>::err(core::diagnostics::ErrorCode::IoError, "Failed to open .bvm file for writing", "BvmCodec::save_to_file");
    }
    ofs.write(reinterpret_cast<const char*>(enc.value().data()),
              static_cast<std::streamsize>(enc.value().size()));
    if (!ofs) {
        return core::diagnostics::Result<void>::err(core::diagnostics::ErrorCode::IoError, "Failed to write .bvm file", "BvmCodec::save_to_file");
    }
    return core::diagnostics::Result<void>::ok();
}

core::diagnostics::Result<BvmProgram>
BvmCodec::load_from_file(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || ec) {
        return core::diagnostics::Result<BvmProgram>::err(core::diagnostics::ErrorCode::FileNotFound, "BVM file not found", "BvmCodec::load_from_file");
    }
    const auto sz = std::filesystem::file_size(path, ec);
    if (ec || sz == 0 || sz > 64ULL * 1024ULL * 1024ULL) {
        return core::diagnostics::Result<BvmProgram>::err(core::diagnostics::ErrorCode::OutOfBounds, "Invalid BVM file size", "BvmCodec::load_from_file");
    }
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
        return core::diagnostics::Result<BvmProgram>::err(core::diagnostics::ErrorCode::IoError, "Failed to open .bvm file", "BvmCodec::load_from_file");
    }
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(sz));
    if (!ifs.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()))) {
        return core::diagnostics::Result<BvmProgram>::err(core::diagnostics::ErrorCode::IoError, "Failed to read .bvm file", "BvmCodec::load_from_file");
    }
    return decode(buf);
}

} // namespace bytemorph::virt
