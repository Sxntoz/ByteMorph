#include "bytemorph/core/ir/ir_serializer.hpp"

#include <cstring>
#include <fstream>

namespace bytemorph::core::ir {

namespace {

std::uint32_t fnv1a_32(std::span<const std::uint8_t> data) noexcept {
    std::uint32_t h = 2166136261u;
    for (std::uint8_t b : data) {
        h ^= b;
        h *= 16777619u;
    }
    return h;
}

void write_u8(std::vector<std::uint8_t>& out, std::uint8_t v) { out.push_back(v); }

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
    const std::uint32_t len = static_cast<std::uint32_t>(s.size());
    write_u32(out, len);
    out.insert(out.end(), s.begin(), s.end());
}

struct Reader {
    std::span<const std::uint8_t> data;
    std::size_t pos{0};

    bool has(std::size_t n) const noexcept { return pos <= data.size() && n <= (data.size() - pos); }

    bool read_u8(std::uint8_t& v) noexcept {
        if (!has(1)) return false;
        v = data[pos++];
        return true;
    }
    bool read_u16(std::uint16_t& v) noexcept {
        if (!has(2)) return false;
        v = static_cast<std::uint16_t>(data[pos]) | (static_cast<std::uint16_t>(data[pos + 1]) << 8);
        pos += 2;
        return true;
    }
    bool read_u32(std::uint32_t& v) noexcept {
        if (!has(4)) return false;
        v = 0;
        for (int i = 0; i < 4; ++i) v |= static_cast<std::uint32_t>(data[pos + i]) << (i * 8);
        pos += 4;
        return true;
    }
    bool read_u64(std::uint64_t& v) noexcept {
        if (!has(8)) return false;
        v = 0;
        for (int i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(data[pos + i]) << (i * 8);
        pos += 8;
        return true;
    }
    bool read_str(std::string& s, std::size_t max_len = 65536) {
        std::uint32_t len = 0;
        if (!read_u32(len) || len > max_len || !has(len)) return false;
        s.assign(reinterpret_cast<const char*>(data.data() + pos), len);
        pos += len;
        return true;
    }
};

void write_operand(std::vector<std::uint8_t>& out, const IrOperand& op) {
    write_u8(out, static_cast<std::uint8_t>(op.kind));
    write_u8(out, op.bit_width);
    write_u64(out, static_cast<std::uint64_t>(op.imm));
    write_str(out, op.name);
}

bool read_operand(Reader& r, IrOperand& op) {
    std::uint8_t kind = 0;
    std::uint64_t imm_u = 0;
    if (!r.read_u8(kind) || kind > static_cast<std::uint8_t>(IrOperand::Kind::Label)) return false;
    op.kind = static_cast<IrOperand::Kind>(kind);
    if (!r.read_u8(op.bit_width)) return false;
    if (!r.read_u64(imm_u)) return false;
    op.imm = static_cast<std::int64_t>(imm_u);
    return r.read_str(op.name);
}

} // namespace

diagnostics::Result<std::vector<std::uint8_t>>
IrSerializer::serialize(const IrModule& mod) {
    std::vector<std::uint8_t> payload;
    write_str(payload, mod.name);
    write_u32(payload, static_cast<std::uint32_t>(mod.source_arch));
    write_u32(payload, static_cast<std::uint32_t>(mod.functions.size()));

    for (const auto& fn : mod.functions) {
        write_str(payload, fn.name);
        write_u64(payload, fn.entry_va);
        write_u32(payload, static_cast<std::uint32_t>(fn.blocks.size()));
        for (const auto& bb : fn.blocks) {
            write_u64(payload, bb.id);
            write_u64(payload, bb.start_va);
            write_u32(payload, static_cast<std::uint32_t>(bb.successors.size()));
            for (const auto s : bb.successors) write_u64(payload, s);
            write_u32(payload, static_cast<std::uint32_t>(bb.instructions.size()));
            for (const auto& insn : bb.instructions) {
                write_u64(payload, insn.source_va);
                write_u8(payload, static_cast<std::uint8_t>(insn.opcode));
                write_u8(payload, static_cast<std::uint8_t>(insn.dsts.size()));
                for (const auto& d : insn.dsts) write_operand(payload, d);
                write_u8(payload, static_cast<std::uint8_t>(insn.srcs.size()));
                for (const auto& s : insn.srcs) write_operand(payload, s);
                write_str(payload, insn.cond);
                write_str(payload, insn.comment);
            }
        }
    }

    std::vector<std::uint8_t> out;
    out.reserve(20 + payload.size());
    write_u32(out, kMagic);
    write_u16(out, kVersion);
    write_u16(out, 0); // flags
    write_u32(out, static_cast<std::uint32_t>(payload.size()));
    write_u32(out, fnv1a_32(payload));
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

diagnostics::Result<IrModule>
IrSerializer::deserialize(std::span<const std::uint8_t> data) {
    using diagnostics::ErrorCode;
    if (data.size() < 16) {
        return diagnostics::Result<IrModule>::err(
            ErrorCode::TruncatedData, "IR buffer smaller than 16-byte header", "IrSerializer::deserialize");
    }

    Reader r{data, 0};
    std::uint32_t magic = 0, payload_size = 0, checksum = 0;
    std::uint16_t version = 0, flags = 0;
    if (!r.read_u32(magic) || !r.read_u16(version) || !r.read_u16(flags) ||
        !r.read_u32(payload_size) || !r.read_u32(checksum)) {
        return diagnostics::Result<IrModule>::err(
            ErrorCode::TruncatedData, "Truncated IR header", "IrSerializer::deserialize");
    }
    if (magic != kMagic) {
        return diagnostics::Result<IrModule>::err(
            ErrorCode::InvalidMagic, "Invalid IR magic (expected BMIR)", "IrSerializer::deserialize");
    }
    if (version != kVersion) {
        return diagnostics::Result<IrModule>::err(
            ErrorCode::UnsupportedFormat, "Unsupported IR version", "IrSerializer::deserialize");
    }
    if (!r.has(payload_size) || r.data.size() - r.pos != payload_size) {
        return diagnostics::Result<IrModule>::err(
            ErrorCode::TruncatedData, "IR payload size mismatch", "IrSerializer::deserialize");
    }
    const auto payload_span = data.subspan(r.pos, payload_size);
    if (fnv1a_32(payload_span) != checksum) {
        return diagnostics::Result<IrModule>::err(
            ErrorCode::ParseError, "IR checksum mismatch (corrupted payload)", "IrSerializer::deserialize");
    }

    IrModule mod;
    std::uint32_t arch_u = 0, fn_count = 0;
    if (!r.read_str(mod.name) || !r.read_u32(arch_u) || !r.read_u32(fn_count) || fn_count > kMaxFunctions) {
        return diagnostics::Result<IrModule>::err(
            ErrorCode::ParseError, "Malformed IR module header", "IrSerializer::deserialize");
    }
    if (arch_u > static_cast<std::uint32_t>(binary::Architecture::ARM64)) {
        return diagnostics::Result<IrModule>::err(
            ErrorCode::ParseError, "Invalid IR source architecture", "IrSerializer::deserialize");
    }
    mod.source_arch = static_cast<binary::Architecture>(arch_u);

    mod.functions.reserve(fn_count);
    for (std::uint32_t fi = 0; fi < fn_count; ++fi) {
        IrFunction fn;
        std::uint32_t bb_count = 0;
        if (!r.read_str(fn.name) || !r.read_u64(fn.entry_va) || !r.read_u32(bb_count) || bb_count > kMaxBlocksPerFn) {
            return diagnostics::Result<IrModule>::err(
                ErrorCode::ParseError, "Malformed IR function", "IrSerializer::deserialize");
        }
        fn.blocks.reserve(bb_count);
        for (std::uint32_t bi = 0; bi < bb_count; ++bi) {
            IrBasicBlock bb;
            std::uint32_t succ_count = 0, insn_count = 0;
            if (!r.read_u64(bb.id) || !r.read_u64(bb.start_va) || !r.read_u32(succ_count) || succ_count > kMaxBlocksPerFn) {
                return diagnostics::Result<IrModule>::err(
                    ErrorCode::ParseError, "Malformed IR basic block", "IrSerializer::deserialize");
            }
            bb.successors.reserve(succ_count);
            for (std::uint32_t si = 0; si < succ_count; ++si) {
                std::uint64_t succ = 0;
                if (!r.read_u64(succ)) {
                    return diagnostics::Result<IrModule>::err(ErrorCode::TruncatedData, "Truncated IR successor", "IrSerializer::deserialize");
                }
                bb.successors.push_back(succ);
            }
            if (!r.read_u32(insn_count) || insn_count > kMaxInsnsPerBlock) {
                return diagnostics::Result<IrModule>::err(ErrorCode::ParseError, "Invalid IR instruction count", "IrSerializer::deserialize");
            }
            bb.instructions.reserve(insn_count);
            for (std::uint32_t ii = 0; ii < insn_count; ++ii) {
                IrInstruction insn;
                std::uint8_t op_u = 0, ndst = 0, nsrc = 0;
                if (!r.read_u64(insn.source_va) || !r.read_u8(op_u) ||
                    op_u > static_cast<std::uint8_t>(IrOpcode::Unknown)) {
                    return diagnostics::Result<IrModule>::err(ErrorCode::ParseError, "Invalid IR opcode", "IrSerializer::deserialize");
                }
                insn.opcode = static_cast<IrOpcode>(op_u);
                if (!r.read_u8(ndst) || ndst > 16) {
                    return diagnostics::Result<IrModule>::err(ErrorCode::ParseError, "Invalid IR dst count", "IrSerializer::deserialize");
                }
                for (std::uint8_t k = 0; k < ndst; ++k) {
                    IrOperand op;
                    if (!read_operand(r, op)) {
                        return diagnostics::Result<IrModule>::err(ErrorCode::ParseError, "Malformed IR dst operand", "IrSerializer::deserialize");
                    }
                    insn.dsts.push_back(std::move(op));
                }
                if (!r.read_u8(nsrc) || nsrc > 16) {
                    return diagnostics::Result<IrModule>::err(ErrorCode::ParseError, "Invalid IR src count", "IrSerializer::deserialize");
                }
                for (std::uint8_t k = 0; k < nsrc; ++k) {
                    IrOperand op;
                    if (!read_operand(r, op)) {
                        return diagnostics::Result<IrModule>::err(ErrorCode::ParseError, "Malformed IR src operand", "IrSerializer::deserialize");
                    }
                    insn.srcs.push_back(std::move(op));
                }
                if (!r.read_str(insn.cond) || !r.read_str(insn.comment)) {
                    return diagnostics::Result<IrModule>::err(ErrorCode::TruncatedData, "Truncated IR metadata", "IrSerializer::deserialize");
                }
                bb.instructions.push_back(std::move(insn));
            }
            fn.blocks.push_back(std::move(bb));
        }
        mod.functions.push_back(std::move(fn));
    }

    return mod;
}

diagnostics::Result<void>
IrSerializer::save_to_file(const IrModule& mod, const std::filesystem::path& path) {
    auto bytes_res = serialize(mod);
    if (!bytes_res) {
        return diagnostics::Result<void>::err(bytes_res.error().code, bytes_res.error().message, bytes_res.error().context);
    }
    std::ofstream ofs(path, std::ios::binary);
    if (!ofs) {
        return diagnostics::Result<void>::err(diagnostics::ErrorCode::IoError, "Failed to open output .ir file", "IrSerializer::save_to_file");
    }
    ofs.write(reinterpret_cast<const char*>(bytes_res.value().data()),
              static_cast<std::streamsize>(bytes_res.value().size()));
    if (!ofs) {
        return diagnostics::Result<void>::err(diagnostics::ErrorCode::IoError, "Failed to write .ir file", "IrSerializer::save_to_file");
    }
    return diagnostics::Result<void>::ok();
}

diagnostics::Result<IrModule>
IrSerializer::load_from_file(const std::filesystem::path& path) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || ec) {
        return diagnostics::Result<IrModule>::err(diagnostics::ErrorCode::FileNotFound, "IR file not found", "IrSerializer::load_from_file");
    }
    const auto sz = std::filesystem::file_size(path, ec);
    if (ec || sz == 0 || sz > 64ULL * 1024ULL * 1024ULL) {
        return diagnostics::Result<IrModule>::err(diagnostics::ErrorCode::OutOfBounds, "Invalid IR file size", "IrSerializer::load_from_file");
    }
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) {
        return diagnostics::Result<IrModule>::err(diagnostics::ErrorCode::IoError, "Failed to open .ir file", "IrSerializer::load_from_file");
    }
    std::vector<std::uint8_t> buf(static_cast<std::size_t>(sz));
    if (!ifs.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()))) {
        return diagnostics::Result<IrModule>::err(diagnostics::ErrorCode::IoError, "Failed to read .ir file", "IrSerializer::load_from_file");
    }
    return deserialize(buf);
}

} // namespace bytemorph::core::ir
