#include "bytemorph/virt/ir_to_vm.hpp"

#include <algorithm>
#include <cctype>
#include <unordered_map>
#include <vector>

namespace bytemorph::virt {

using namespace bytemorph::core;
using namespace bytemorph::core::ir;

namespace {

class RegAllocator {
public:
    RegAllocator() {
        map_["rax"] = 0; map_["eax"] = 0; map_["ax"] = 0; map_["al"] = 0; map_["x0"] = 0; map_["w0"] = 0; map_["r0"] = 0;
        map_["rcx"] = 1; map_["ecx"] = 1; map_["cx"] = 1; map_["cl"] = 1; map_["x1"] = 1; map_["w1"] = 1; map_["r1"] = 1;
        map_["rdx"] = 2; map_["edx"] = 2; map_["dx"] = 2; map_["dl"] = 2; map_["x2"] = 2; map_["w2"] = 2; map_["r2"] = 2;
        map_["rbx"] = 3; map_["ebx"] = 3; map_["bx"] = 3; map_["bl"] = 3; map_["x3"] = 3; map_["w3"] = 3; map_["r3"] = 3;
        map_["rsp"] = 4; map_["esp"] = 4; map_["sp"] = 4;
        map_["rbp"] = 5; map_["ebp"] = 5; map_["x29"] = 5; map_["w29"] = 5;
        map_["rsi"] = 6; map_["esi"] = 6; map_["si"] = 6; map_["sil"] = 6; map_["x4"] = 6; map_["w4"] = 6;
        map_["rdi"] = 7; map_["edi"] = 7; map_["di"] = 7; map_["dil"] = 7; map_["x5"] = 7; map_["w5"] = 7;
        map_["r8"]  = 8; map_["r8d"] = 8; map_["r8w"] = 8; map_["r8b"] = 8; map_["x6"] = 8; map_["w6"] = 8;
        map_["r9"]  = 9; map_["r9d"] = 9; map_["r9w"] = 9; map_["r9b"] = 9; map_["x7"] = 9; map_["w7"] = 9;
        map_["r10"] = 10; map_["r10d"] = 10; map_["r10w"] = 10; map_["r10b"] = 10; map_["x8"] = 10; map_["w8"] = 10;
        map_["r11"] = 11; map_["r11d"] = 11; map_["r11w"] = 11; map_["r11b"] = 11; map_["x9"] = 11; map_["w9"] = 11;
    }

    diagnostics::Result<std::uint8_t> get_or_alloc(const std::string& raw_name) {
        std::string name = raw_name;
        if (name == "xzr" || name == "wzr") {
            return static_cast<std::uint8_t>(31);
        }
        if (name.size() >= 2 && name[0] == 'w' && std::isdigit(static_cast<unsigned char>(name[1]))) {
            name = "x" + name.substr(1);
        } else if (name.size() >= 3 && name[0] == 'r' && name.back() == 'd' && std::isdigit(static_cast<unsigned char>(name[1]))) {
            name = name.substr(0, name.size() - 1);
        }
        auto it = map_.find(name);
        if (it != map_.end()) {
            return it->second;
        }
        if (next_reg_ >= 28) {
            return diagnostics::Result<std::uint8_t>::err(
                diagnostics::ErrorCode::OutOfBounds,
                "Exceeded available VM virtual register slots (28)",
                "IrToVmTranslator::RegAllocator");
        }
        const std::uint8_t r = next_reg_++;
        map_[name] = r;
        return r;
    }

private:
    std::unordered_map<std::string, std::uint8_t> map_;
    std::uint8_t next_reg_{12}; // R28..R31 reserved as scratch
};

VmOpcode map_cond_opcode(const std::string& cond) noexcept {
    if (cond == "je" || cond == "jz" || cond == "b.eq") return VmOpcode::Jeq;
    if (cond == "jne" || cond == "jnz" || cond == "b.ne") return VmOpcode::Jne;
    if (cond == "jl" || cond == "jnge" || cond == "jb" || cond == "jnae" || cond == "jc" || cond == "js" ||
        cond == "b.lt" || cond == "b.lo" || cond == "b.cc" || cond == "b.mi") return VmOpcode::Jlt;
    if (cond == "jle" || cond == "jng" || cond == "jbe" || cond == "jna" ||
        cond == "b.le" || cond == "b.ls") return VmOpcode::Jle;
    if (cond == "jg" || cond == "jnle" || cond == "ja" || cond == "jnbe" ||
        cond == "b.gt" || cond == "b.hi") return VmOpcode::Jgt;
    if (cond == "jge" || cond == "jnl" || cond == "jae" || cond == "jnb" || cond == "jnc" || cond == "jns" ||
        cond == "b.ge" || cond == "b.hs" || cond == "b.cs" || cond == "b.pl") return VmOpcode::Jge;
    return VmOpcode::Jne;
}

VmCondCode map_vm_cond_code(const std::string& cond) noexcept {
    if (cond == "eq" || cond == "je" || cond == "jz" || cond == "b.eq") return VmCondCode::Eq;
    if (cond == "ne" || cond == "jne" || cond == "jnz" || cond == "b.ne") return VmCondCode::Ne;
    if (cond == "lt" || cond == "jl" || cond == "jnge" || cond == "b.lt") return VmCondCode::Lt;
    if (cond == "le" || cond == "jle" || cond == "jng" || cond == "b.le") return VmCondCode::Le;
    if (cond == "gt" || cond == "jg" || cond == "jnle" || cond == "b.gt") return VmCondCode::Gt;
    if (cond == "ge" || cond == "jge" || cond == "jnl" || cond == "b.ge") return VmCondCode::Ge;
    if (cond == "b" || cond == "jb" || cond == "jnae" || cond == "jc" || cond == "c" ||
        cond == "b.lo" || cond == "b.cc" || cond == "lo" || cond == "cc") return VmCondCode::Below;
    if (cond == "be" || cond == "jbe" || cond == "jna" || cond == "b.ls" || cond == "ls") return VmCondCode::BelowEq;
    if (cond == "a" || cond == "ja" || cond == "jnbe" || cond == "b.hi" || cond == "hi") return VmCondCode::Above;
    if (cond == "ae" || cond == "jae" || cond == "jnb" || cond == "jnc" || cond == "nc" ||
        cond == "b.hs" || cond == "b.cs" || cond == "hs" || cond == "cs") return VmCondCode::AboveEq;
    if (cond == "s" || cond == "js" || cond == "b.mi" || cond == "mi") return VmCondCode::Sign;
    if (cond == "ns" || cond == "jns" || cond == "b.pl" || cond == "pl") return VmCondCode::NotSign;
    if (cond == "o" || cond == "jo" || cond == "b.vs" || cond == "vs") return VmCondCode::Overflow;
    if (cond == "no" || cond == "jno" || cond == "b.vc" || cond == "vc") return VmCondCode::NotOverflow;
    return VmCondCode::Ne;
}

std::uint8_t normalize_mem_width(std::uint8_t w) noexcept {
    if (w == 8 || w == 16 || w == 32 || w == 64 || w == 128) return w;
    return 64;
}

std::optional<std::uint8_t> try_parse_vreg_index(const std::string& name) noexcept {
    if (name.size() >= 4 && (name.rfind("xmm", 0) == 0 || name.rfind("ymm", 0) == 0)) {
        std::size_t idx = 0;
        for (std::size_t i = 3; i < name.size(); ++i) {
            if (!std::isdigit(static_cast<unsigned char>(name[i]))) return std::nullopt;
            idx = idx * 10 + static_cast<std::size_t>(name[i] - '0');
        }
        return (idx < 32) ? std::optional<std::uint8_t>(static_cast<std::uint8_t>(idx)) : std::nullopt;
    }
    if (name.size() >= 2 && (name[0] == 'v' || name[0] == 'd' || name[0] == 's' || name[0] == 'q')) {
        std::size_t idx = 0;
        for (std::size_t i = 1; i < name.size(); ++i) {
            if (name[i] == '.') break;
            if (!std::isdigit(static_cast<unsigned char>(name[i]))) return std::nullopt;
            idx = idx * 10 + static_cast<std::size_t>(name[i] - '0');
        }
        return (idx < 32) ? std::optional<std::uint8_t>(static_cast<std::uint8_t>(idx)) : std::nullopt;
    }
    return std::nullopt;
}

} // namespace

diagnostics::Result<BvmProgram>
IrToVmTranslator::translate(const IrFunction& fn, std::uint64_t build_seed) {
    TranslateOptions opts;
    opts.build_seed = build_seed;
    return translate(fn, opts);
}

diagnostics::Result<BvmProgram>
IrToVmTranslator::translate(const IrFunction& fn, const TranslateOptions& options) {
    using diagnostics::ErrorCode;
    if (fn.blocks.empty()) {
        return diagnostics::Result<BvmProgram>::err(
            ErrorCode::EmptyInput, "Cannot translate empty IrFunction", "IrToVmTranslator::translate");
    }

    BvmProgram prog;
    prog.build_seed = options.build_seed;

    RegAllocator reg_alloc;
    std::unordered_map<std::uint64_t, std::size_t> block_pc;
    struct PendingPatch {
        std::size_t vm_pc;
        std::uint64_t target_va;
    };
    std::vector<PendingPatch> patches;

    auto materialize_src = [&](const IrOperand& op, std::uint8_t scratch_reg) -> diagnostics::Result<std::uint8_t> {
        if (op.kind == IrOperand::Kind::Immediate) {
            prog.instructions.push_back(VmInstruction{VmOpcode::MovImm, scratch_reg, 0, 0, op.imm});
            return scratch_reg;
        }
        if (op.kind == IrOperand::Kind::VirtualReg || op.kind == IrOperand::Kind::ArchReg) {
            if (op.name == "xzr" || op.name == "wzr") {
                prog.instructions.push_back(VmInstruction{VmOpcode::MovImm, scratch_reg, 0, 0, 0});
                return scratch_reg;
            }
            return reg_alloc.get_or_alloc(op.name);
        }
        if (op.kind == IrOperand::Kind::Memory) {
            auto base_r = reg_alloc.get_or_alloc(op.name);
            if (!base_r) return base_r;
            prog.instructions.push_back(
                VmInstruction{VmOpcode::Load, scratch_reg, base_r.value(), normalize_mem_width(op.bit_width), op.imm});
            return scratch_reg;
        }
        return diagnostics::Result<std::uint8_t>::err(
            ErrorCode::UnsupportedFormat, "Unsupported IR source operand kind in VM translator", "IrToVmTranslator::translate");
    };

    for (const auto& bb : fn.blocks) {
        block_pc[bb.start_va] = prog.instructions.size();

        for (const auto& insn : bb.instructions) {
            switch (insn.opcode) {
                case IrOpcode::Nop:
                    prog.instructions.push_back(VmInstruction{VmOpcode::Nop, 0, 0, 0, 0});
                    break;
                case IrOpcode::Mov: {
                    if (insn.dsts.size() != 1 || insn.srcs.size() != 1) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::ParseError, "Invalid Mov arity", "IrToVmTranslator::translate");
                    }
                    if (insn.dsts[0].kind == IrOperand::Kind::Memory) {
                        auto base_r = reg_alloc.get_or_alloc(insn.dsts[0].name);
                        auto src_r = materialize_src(insn.srcs[0], 29);
                        if (!base_r || !src_r) return diagnostics::Result<BvmProgram>::err(ErrorCode::OutOfBounds, "Register allocation failed", "IrToVmTranslator::translate");
                        prog.instructions.push_back(
                            VmInstruction{VmOpcode::Store, base_r.value(), src_r.value(), normalize_mem_width(insn.dsts[0].bit_width), insn.dsts[0].imm});
                        break;
                    }
                    auto dst_r = reg_alloc.get_or_alloc(insn.dsts[0].name);
                    if (!dst_r) return diagnostics::Result<BvmProgram>::err(dst_r.error().code, dst_r.error().message, dst_r.error().context);
                    if (insn.srcs[0].kind == IrOperand::Kind::Immediate) {
                        prog.instructions.push_back(VmInstruction{VmOpcode::MovImm, dst_r.value(), 0, 0, insn.srcs[0].imm});
                    } else if (insn.srcs[0].kind == IrOperand::Kind::Memory) {
                        auto base_r = reg_alloc.get_or_alloc(insn.srcs[0].name);
                        if (!base_r) return diagnostics::Result<BvmProgram>::err(base_r.error().code, base_r.error().message, base_r.error().context);
                        prog.instructions.push_back(
                            VmInstruction{VmOpcode::Load, dst_r.value(), base_r.value(), normalize_mem_width(insn.srcs[0].bit_width), insn.srcs[0].imm});
                    } else {
                        auto src_r = materialize_src(insn.srcs[0], 29);
                        if (!src_r) return diagnostics::Result<BvmProgram>::err(src_r.error().code, src_r.error().message, src_r.error().context);
                        prog.instructions.push_back(VmInstruction{VmOpcode::MovReg, dst_r.value(), src_r.value(), 0, 0});
                    }
                    break;
                }
                case IrOpcode::Load: {
                    if (insn.dsts.size() != 1 || insn.srcs.size() != 1) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::ParseError, "Invalid Load arity", "IrToVmTranslator::translate");
                    }
                    auto dst_r = reg_alloc.get_or_alloc(insn.dsts[0].name);
                    auto base_r = reg_alloc.get_or_alloc(insn.srcs[0].name);
                    if (!dst_r || !base_r) return diagnostics::Result<BvmProgram>::err(ErrorCode::OutOfBounds, "Register allocation failed", "IrToVmTranslator::translate");
                    const std::uint8_t width = normalize_mem_width(insn.srcs[0].bit_width);
                    prog.instructions.push_back(VmInstruction{VmOpcode::Load, dst_r.value(), base_r.value(), width, insn.srcs[0].imm});
                    break;
                }
                case IrOpcode::Store: {
                    if (insn.dsts.size() != 1 || insn.srcs.size() != 1) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::ParseError, "Invalid Store arity", "IrToVmTranslator::translate");
                    }
                    auto base_r = reg_alloc.get_or_alloc(insn.dsts[0].name);
                    auto src_r = materialize_src(insn.srcs[0], 29);
                    if (!base_r || !src_r) return diagnostics::Result<BvmProgram>::err(ErrorCode::OutOfBounds, "Register allocation failed", "IrToVmTranslator::translate");
                    const std::uint8_t width = normalize_mem_width(insn.dsts[0].bit_width);
                    prog.instructions.push_back(VmInstruction{VmOpcode::Store, base_r.value(), src_r.value(), width, insn.dsts[0].imm});
                    break;
                }
                case IrOpcode::Add:
                case IrOpcode::Sub:
                case IrOpcode::Mul:
                case IrOpcode::Div:
                case IrOpcode::And:
                case IrOpcode::Or:
                case IrOpcode::Xor:
                    if (insn.dsts.size() == 1 && insn.srcs.size() >= 2) {
                        if (auto d_v = try_parse_vreg_index(insn.dsts[0].name)) {
                            auto s1_v = try_parse_vreg_index(insn.srcs[0].name);
                            auto s2_v = try_parse_vreg_index(insn.srcs[1].name);
                            if (s1_v && s2_v) {
                                const VmOpcode vop = (insn.opcode == IrOpcode::And) ? VmOpcode::VAnd
                                                   : (insn.opcode == IrOpcode::Or) ? VmOpcode::VOr
                                                                                   : VmOpcode::VXor;
                                prog.instructions.push_back(VmInstruction{vop, *d_v, *s1_v, *s2_v, 0});
                                break;
                            }
                        }
                    }
                    [[fallthrough]];
                case IrOpcode::Shl:
                case IrOpcode::Shr: {
                    if (insn.dsts.size() != 1 || insn.srcs.size() < 2) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::ParseError, "Invalid binary ALU op arity", "IrToVmTranslator::translate");
                    }
                    auto dst_r = reg_alloc.get_or_alloc(insn.dsts[0].name);
                    auto s1 = materialize_src(insn.srcs[0], 29);
                    auto s2 = materialize_src(insn.srcs[1], 30);
                    if (!dst_r || !s1 || !s2) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::OutOfBounds, "Register allocation failed", "IrToVmTranslator::translate");
                    }
                    VmOpcode vop = VmOpcode::Add;
                    switch (insn.opcode) {
                        case IrOpcode::Add: vop = VmOpcode::Add; break;
                        case IrOpcode::Sub: vop = VmOpcode::Sub; break;
                        case IrOpcode::Mul: vop = VmOpcode::Mul; break;
                        case IrOpcode::Div: vop = VmOpcode::Div; break;
                        case IrOpcode::And: vop = VmOpcode::And; break;
                        case IrOpcode::Or:  vop = VmOpcode::Or;  break;
                        case IrOpcode::Xor: vop = VmOpcode::Xor; break;
                        case IrOpcode::Shl: vop = VmOpcode::Shl; break;
                        case IrOpcode::Shr: vop = VmOpcode::Shr; break;
                        default: break;
                    }
                    prog.instructions.push_back(VmInstruction{vop, dst_r.value(), s1.value(), s2.value(), 0});
                    break;
                }
                case IrOpcode::Cmp: {
                    if (insn.srcs.size() < 2) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::ParseError, "Invalid Cmp arity", "IrToVmTranslator::translate");
                    }
                    auto s1 = materialize_src(insn.srcs[0], 29);
                    auto s2 = materialize_src(insn.srcs[1], 30);
                    if (!s1 || !s2) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::OutOfBounds, "Register allocation failed", "IrToVmTranslator::translate");
                    }
                    prog.instructions.push_back(VmInstruction{VmOpcode::Cmp, 0, s1.value(), s2.value(), 0});
                    break;
                }
                case IrOpcode::LeaGlobal: {
                    if (insn.dsts.size() != 1 || insn.srcs.empty()) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::ParseError, "Invalid LeaGlobal arity", "IrToVmTranslator::translate");
                    }
                    auto dst_r = reg_alloc.get_or_alloc(insn.dsts[0].name);
                    if (!dst_r) return diagnostics::Result<BvmProgram>::err(dst_r.error().code, dst_r.error().message, dst_r.error().context);
                    const std::int64_t rel_off = static_cast<std::int64_t>(insn.srcs[0].imm) -
                                                 static_cast<std::int64_t>(options.stub_base_va);
                    prog.instructions.push_back(VmInstruction{VmOpcode::LeaPic, dst_r.value(), 0, 0, rel_off});
                    break;
                }
                case IrOpcode::SelectCc: {
                    if (insn.dsts.size() != 1 || insn.srcs.empty()) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::ParseError, "Invalid SelectCc arity", "IrToVmTranslator::translate");
                    }
                    auto dst_r = reg_alloc.get_or_alloc(insn.dsts[0].name);
                    auto src_r = materialize_src(insn.srcs[0], 29);
                    if (!dst_r || !src_r) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::OutOfBounds, "Register allocation failed", "IrToVmTranslator::translate");
                    }
                    const std::string& c = insn.cond.empty() ? insn.comment : insn.cond;
                    const std::uint8_t cc = static_cast<std::uint8_t>(map_vm_cond_code(c));
                    prog.instructions.push_back(VmInstruction{VmOpcode::SelectCc, dst_r.value(), src_r.value(), cc, 0});
                    break;
                }
                case IrOpcode::SetCc: {
                    if (insn.dsts.size() != 1) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::ParseError, "Invalid SetCc arity", "IrToVmTranslator::translate");
                    }
                    auto dst_r = reg_alloc.get_or_alloc(insn.dsts[0].name);
                    if (!dst_r) return diagnostics::Result<BvmProgram>::err(dst_r.error().code, dst_r.error().message, dst_r.error().context);
                    const std::string& c = insn.cond.empty() ? insn.comment : insn.cond;
                    const std::uint8_t cc = static_cast<std::uint8_t>(map_vm_cond_code(c));
                    prog.instructions.push_back(VmInstruction{VmOpcode::SetCc, dst_r.value(), 0, cc, 0});
                    break;
                }
                case IrOpcode::Adc:
                case IrOpcode::Sbb: {
                    if (insn.dsts.size() != 1 || insn.srcs.size() < 2) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::ParseError, "Invalid Adc/Sbb arity", "IrToVmTranslator::translate");
                    }
                    auto dst_r = reg_alloc.get_or_alloc(insn.dsts[0].name);
                    auto s1 = materialize_src(insn.srcs[0], 29);
                    auto s2 = materialize_src(insn.srcs[1], 30);
                    if (!dst_r || !s1 || !s2) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::OutOfBounds, "Register allocation failed", "IrToVmTranslator::translate");
                    }
                    const std::uint8_t cf_cc = static_cast<std::uint8_t>(VmCondCode::Below);
                    const VmOpcode bin_op = (insn.opcode == IrOpcode::Adc) ? VmOpcode::Add : VmOpcode::Sub;
                    prog.instructions.push_back(VmInstruction{VmOpcode::SetCc, 31, 0, cf_cc, 0});
                    prog.instructions.push_back(VmInstruction{bin_op, 28, s1.value(), s2.value(), 0});
                    prog.instructions.push_back(VmInstruction{bin_op, dst_r.value(), 28, 31, 0});
                    break;
                }
                case IrOpcode::VMov: {
                    if (insn.dsts.size() != 1 || insn.srcs.size() != 1) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::ParseError, "Invalid VMov arity", "IrToVmTranslator::translate");
                    }
                    const auto d_v = try_parse_vreg_index(insn.dsts[0].name);
                    const auto s_v = try_parse_vreg_index(insn.srcs[0].name);
                    if (d_v && s_v) {
                        prog.instructions.push_back(VmInstruction{VmOpcode::VMovReg, *d_v, *s_v, 0, insn.dsts[0].bit_width});
                    } else if (d_v && insn.srcs[0].kind == IrOperand::Kind::Memory) {
                        auto base_r = reg_alloc.get_or_alloc(insn.srcs[0].name);
                        if (!base_r) return diagnostics::Result<BvmProgram>::err(base_r.error().code, base_r.error().message, base_r.error().context);
                        prog.instructions.push_back(VmInstruction{
                            VmOpcode::VLoad, *d_v, base_r.value(), normalize_mem_width(insn.srcs[0].bit_width), insn.srcs[0].imm});
                    } else if (s_v && insn.dsts[0].kind == IrOperand::Kind::Memory) {
                        auto base_r = reg_alloc.get_or_alloc(insn.dsts[0].name);
                        if (!base_r) return diagnostics::Result<BvmProgram>::err(base_r.error().code, base_r.error().message, base_r.error().context);
                        prog.instructions.push_back(VmInstruction{
                            VmOpcode::VStore, base_r.value(), *s_v, normalize_mem_width(insn.dsts[0].bit_width), insn.dsts[0].imm});
                    } else if (d_v && (insn.srcs[0].kind == IrOperand::Kind::ArchReg || insn.srcs[0].kind == IrOperand::Kind::VirtualReg || insn.srcs[0].kind == IrOperand::Kind::Immediate)) {
                        auto src_r = materialize_src(insn.srcs[0], 29);
                        if (!src_r) return diagnostics::Result<BvmProgram>::err(src_r.error().code, src_r.error().message, src_r.error().context);
                        prog.instructions.push_back(VmInstruction{
                            VmOpcode::VMovGprToVec, *d_v, src_r.value(), 0, insn.dsts[0].bit_width == 32 ? 32 : 64});
                    } else if (s_v && (insn.dsts[0].kind == IrOperand::Kind::ArchReg || insn.dsts[0].kind == IrOperand::Kind::VirtualReg)) {
                        auto dst_r = reg_alloc.get_or_alloc(insn.dsts[0].name);
                        if (!dst_r) return diagnostics::Result<BvmProgram>::err(dst_r.error().code, dst_r.error().message, dst_r.error().context);
                        prog.instructions.push_back(VmInstruction{
                            VmOpcode::VMovVecToGpr, dst_r.value(), *s_v, 0, insn.dsts[0].bit_width == 32 ? 32 : 64});
                    } else {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::UnsupportedFormat, "Unsupported VMov operand combination", "IrToVmTranslator::translate");
                    }
                    break;
                }
                case IrOpcode::FCvt: {
                    if (insn.dsts.size() != 1 || insn.srcs.size() < 2) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::ParseError, "Invalid FCvt arity", "IrToVmTranslator::translate");
                    }
                    const std::int64_t mode = insn.srcs[1].imm;
                    const auto d_v = try_parse_vreg_index(insn.dsts[0].name);
                    const auto s_v = try_parse_vreg_index(insn.srcs[0].name);
                    if (mode == 0 || mode == 1) {
                        if (!d_v) return diagnostics::Result<BvmProgram>::err(ErrorCode::UnsupportedFormat, "FCvt I2F requires vector dst", "IrToVmTranslator::translate");
                        auto src_r = materialize_src(insn.srcs[0], 29);
                        if (!src_r) return diagnostics::Result<BvmProgram>::err(src_r.error().code, src_r.error().message, src_r.error().context);
                        const std::int64_t flags = (mode == 1 ? 1 : 0) | (insn.dsts[0].bit_width == 64 ? 2 : 0) | (insn.srcs[0].bit_width == 64 ? 4 : 0);
                        prog.instructions.push_back(VmInstruction{VmOpcode::VCvtI2F, *d_v, src_r.value(), 0, flags});
                    } else if (mode == 2 || mode == 3) {
                        if (!s_v) return diagnostics::Result<BvmProgram>::err(ErrorCode::UnsupportedFormat, "FCvt F2I requires vector src", "IrToVmTranslator::translate");
                        auto dst_r = reg_alloc.get_or_alloc(insn.dsts[0].name);
                        if (!dst_r) return diagnostics::Result<BvmProgram>::err(dst_r.error().code, dst_r.error().message, dst_r.error().context);
                        const std::int64_t flags = (mode == 3 ? 1 : 0) | (insn.srcs[0].bit_width == 64 ? 2 : 0) | (insn.dsts[0].bit_width == 64 ? 4 : 0);
                        prog.instructions.push_back(VmInstruction{VmOpcode::VCvtF2I, dst_r.value(), *s_v, 0, flags});
                    } else if (mode == 4 && d_v && s_v) {
                        prog.instructions.push_back(VmInstruction{VmOpcode::VCvtF2F, *d_v, *s_v, 0, insn.dsts[0].bit_width == 64 ? 64 : 32});
                    } else {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::UnsupportedFormat, "Unsupported FCvt mode", "IrToVmTranslator::translate");
                    }
                    break;
                }
                case IrOpcode::VPAdd:
                case IrOpcode::VPSub: {
                    if (insn.dsts.size() != 1 || insn.srcs.size() < 2) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::ParseError, "Invalid packed vector arithmetic arity", "IrToVmTranslator::translate");
                    }
                    const auto d_v = try_parse_vreg_index(insn.dsts[0].name);
                    const auto s1_v = try_parse_vreg_index(insn.srcs[0].name);
                    const auto s2_v = try_parse_vreg_index(insn.srcs[1].name);
                    if (!d_v || !s1_v || !s2_v) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::UnsupportedFormat, "Packed vector op requires vector registers", "IrToVmTranslator::translate");
                    }
                    const bool is_64 = (insn.dsts[0].bit_width == 64);
                    const VmOpcode vop = (insn.opcode == IrOpcode::VPAdd)
                        ? (is_64 ? VmOpcode::VPAdd64 : VmOpcode::VPAdd32)
                        : (is_64 ? VmOpcode::VPSub64 : VmOpcode::VPSub32);
                    prog.instructions.push_back(VmInstruction{vop, *d_v, *s1_v, *s2_v, 0});
                    break;
                }
                case IrOpcode::FAdd:
                case IrOpcode::FSub:
                case IrOpcode::FMul:
                case IrOpcode::FDiv: {
                    if (insn.dsts.size() != 1 || insn.srcs.size() < 2) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::ParseError, "Invalid FP arithmetic arity", "IrToVmTranslator::translate");
                    }
                    const auto d_v = try_parse_vreg_index(insn.dsts[0].name);
                    const auto s1_v = try_parse_vreg_index(insn.srcs[0].name);
                    const auto s2_v = try_parse_vreg_index(insn.srcs[1].name);
                    if (!d_v || !s1_v || !s2_v) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::UnsupportedFormat, "FP arithmetic requires vector registers", "IrToVmTranslator::translate");
                    }
                    const bool is_f32 = (insn.dsts[0].bit_width == 32);
                    VmOpcode vop = VmOpcode::VAddF64;
                    if (insn.opcode == IrOpcode::FAdd) vop = is_f32 ? VmOpcode::VAddF32 : VmOpcode::VAddF64;
                    else if (insn.opcode == IrOpcode::FSub) vop = is_f32 ? VmOpcode::VSubF32 : VmOpcode::VSubF64;
                    else if (insn.opcode == IrOpcode::FMul) vop = is_f32 ? VmOpcode::VMulF32 : VmOpcode::VMulF64;
                    else vop = is_f32 ? VmOpcode::VDivF32 : VmOpcode::VDivF64;
                    prog.instructions.push_back(VmInstruction{vop, *d_v, *s1_v, *s2_v, 0});
                    break;
                }
                case IrOpcode::FCmp: {
                    if (insn.srcs.size() < 2) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::ParseError, "Invalid FCmp arity", "IrToVmTranslator::translate");
                    }
                    const auto s1_v = try_parse_vreg_index(insn.srcs[0].name);
                    const auto s2_v = try_parse_vreg_index(insn.srcs[1].name);
                    if (!s1_v || !s2_v) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::UnsupportedFormat, "FCmp requires vector registers", "IrToVmTranslator::translate");
                    }
                    const VmOpcode vop = (insn.srcs[0].bit_width == 32) ? VmOpcode::VCmpF32 : VmOpcode::VCmpF64;
                    prog.instructions.push_back(VmInstruction{vop, 0, *s1_v, *s2_v, 0});
                    break;
                }
                case IrOpcode::Jump: {
                    if (insn.srcs.empty()) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::ParseError, "Empty Jump operand", "IrToVmTranslator::translate");
                    }
                    if (insn.srcs[0].kind == IrOperand::Kind::Label) {
                        const std::size_t pc = prog.instructions.size();
                        prog.instructions.push_back(VmInstruction{VmOpcode::Jmp, 0, 0, 0, 0});
                        patches.push_back(PendingPatch{pc, static_cast<std::uint64_t>(insn.srcs[0].imm)});
                        break;
                    }
                    if ((insn.srcs[0].kind == IrOperand::Kind::ArchReg || insn.srcs[0].kind == IrOperand::Kind::VirtualReg) &&
                        (!options.jump_table_targets.empty() || !options.authorized_jump_targets.empty())) {
                        auto idx_r = reg_alloc.get_or_alloc(insn.srcs[0].name);
                        if (!idx_r) return diagnostics::Result<BvmProgram>::err(idx_r.error().code, idx_r.error().message, idx_r.error().context);
                        for (std::size_t idx = 0; idx < options.jump_table_targets.size(); ++idx) {
                            prog.instructions.push_back(VmInstruction{VmOpcode::MovImm, 30, 0, 0, static_cast<std::int64_t>(idx)});
                            prog.instructions.push_back(VmInstruction{VmOpcode::Cmp, 0, idx_r.value(), 30, 0});
                            const std::size_t br_pc = prog.instructions.size();
                            prog.instructions.push_back(VmInstruction{VmOpcode::Jeq, 0, 0, 0, 0});
                            patches.push_back(PendingPatch{br_pc, options.jump_table_targets[idx]});
                        }
                        std::vector<std::uint64_t> sorted_jtargets(options.authorized_jump_targets.begin(), options.authorized_jump_targets.end());
                        std::sort(sorted_jtargets.begin(), sorted_jtargets.end());
                        for (const auto tva : sorted_jtargets) {
                            prog.instructions.push_back(VmInstruction{VmOpcode::MovImm, 30, 0, 0, static_cast<std::int64_t>(tva)});
                            prog.instructions.push_back(VmInstruction{VmOpcode::Cmp, 0, idx_r.value(), 30, 0});
                            const std::size_t br_pc = prog.instructions.size();
                            prog.instructions.push_back(VmInstruction{VmOpcode::Jeq, 0, 0, 0, 0});
                            patches.push_back(PendingPatch{br_pc, tva});
                        }
                        prog.instructions.push_back(VmInstruction{VmOpcode::Halt, 0xFF, 0, 0, 0});
                        break;
                    }
                    return diagnostics::Result<BvmProgram>::err(
                        ErrorCode::UnsupportedFormat, "Indirect/non-label Jump not supported in VM translator without validated jump table", "IrToVmTranslator::translate");
                }
                case IrOpcode::JumpCond: {
                    if (insn.srcs.empty() || insn.srcs[0].kind != IrOperand::Kind::Label) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::UnsupportedFormat, "Indirect/non-label JumpCond not supported in VM translator", "IrToVmTranslator::translate");
                    }
                    const std::string& c = insn.cond.empty() ? insn.comment : insn.cond;
                    const std::size_t pc = prog.instructions.size();
                    prog.instructions.push_back(VmInstruction{map_cond_opcode(c), 0, 0, 0, 0});
                    patches.push_back(PendingPatch{pc, static_cast<std::uint64_t>(insn.srcs[0].imm)});
                    break;
                }
                case IrOpcode::Ret:
                    prog.instructions.push_back(VmInstruction{VmOpcode::Ret, 0, 0, 0, 0});
                    break;
                case IrOpcode::Call: {
                    if (!options.allow_external_calls || insn.srcs.empty()) {
                        return diagnostics::Result<BvmProgram>::err(
                            ErrorCode::UnsupportedFormat,
                            "Unsupported Call in VM translator (indirect or external calls disabled)",
                            "IrToVmTranslator::translate");
                    }
                    if (insn.srcs[0].kind == IrOperand::Kind::Label) {
                        const std::uint64_t target_va = static_cast<std::uint64_t>(insn.srcs[0].imm);
                        if (!options.authorized_call_targets.empty() &&
                            !options.authorized_call_targets.contains(target_va)) {
                            return diagnostics::Result<BvmProgram>::err(
                                ErrorCode::UnsupportedFormat,
                                "Unauthorized external call target in VM translator",
                                "IrToVmTranslator::translate");
                        }
                        const std::int64_t rel_off = static_cast<std::int64_t>(target_va) -
                                                     static_cast<std::int64_t>(options.stub_base_va);
                        prog.instructions.push_back(VmInstruction{VmOpcode::CallExt, 0, 0, 0, rel_off});
                        break;
                    }
                    if ((insn.srcs[0].kind == IrOperand::Kind::ArchReg || insn.srcs[0].kind == IrOperand::Kind::VirtualReg) &&
                        !options.authorized_call_targets.empty()) {
                        auto reg_r = reg_alloc.get_or_alloc(insn.srcs[0].name);
                        if (!reg_r) return diagnostics::Result<BvmProgram>::err(reg_r.error().code, reg_r.error().message, reg_r.error().context);
                        std::vector<std::uint64_t> sorted_ctargets(options.authorized_call_targets.begin(), options.authorized_call_targets.end());
                        std::sort(sorted_ctargets.begin(), sorted_ctargets.end());
                        const std::size_t k = sorted_ctargets.size();
                        const std::size_t base_pc = prog.instructions.size();
                        const std::size_t dispatch_start = base_pc + k * 3 + 1;
                        const std::size_t after_pc = dispatch_start + k * 2;
                        for (std::size_t i = 0; i < k; ++i) {
                            prog.instructions.push_back(VmInstruction{VmOpcode::MovImm, 30, 0, 0, static_cast<std::int64_t>(sorted_ctargets[i])});
                            prog.instructions.push_back(VmInstruction{VmOpcode::Cmp, 0, reg_r.value(), 30, 0});
                            prog.instructions.push_back(VmInstruction{VmOpcode::Jeq, 0, 0, 0, static_cast<std::int64_t>(dispatch_start + i * 2)});
                        }
                        prog.instructions.push_back(VmInstruction{VmOpcode::Halt, 0xFF, 0, 0, 0});
                        for (std::size_t i = 0; i < k; ++i) {
                            const std::int64_t rel_off = static_cast<std::int64_t>(sorted_ctargets[i]) -
                                                         static_cast<std::int64_t>(options.stub_base_va);
                            prog.instructions.push_back(VmInstruction{VmOpcode::CallExt, 0, 0, 0, rel_off});
                            prog.instructions.push_back(VmInstruction{VmOpcode::Jmp, 0, 0, 0, static_cast<std::int64_t>(after_pc)});
                        }
                        break;
                    }
                    return diagnostics::Result<BvmProgram>::err(
                        ErrorCode::UnsupportedFormat,
                        "Unsupported Call in VM translator (indirect call requires authorized_call_targets)",
                        "IrToVmTranslator::translate");
                }
                case IrOpcode::Syscall:
                case IrOpcode::Unknown:
                    return diagnostics::Result<BvmProgram>::err(
                        ErrorCode::UnsupportedFormat,
                        std::string("Unsupported IR opcode for VM translation: ") + std::string(ir::to_string(insn.opcode)),
                        "IrToVmTranslator::translate");
            }
        }
    }

    for (const auto& p : patches) {
        auto it = block_pc.find(p.target_va);
        if (it == block_pc.end()) {
            return diagnostics::Result<BvmProgram>::err(
                ErrorCode::OutOfBounds, "Branch target label not found in translated function", "IrToVmTranslator::translate");
        }
        prog.instructions[p.vm_pc].imm = static_cast<std::int64_t>(it->second);
    }

    return prog;
}

} // namespace bytemorph::virt
