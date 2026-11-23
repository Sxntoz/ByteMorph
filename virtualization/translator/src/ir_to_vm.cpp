#include "bytemorph/virt/ir_to_vm.hpp"

#include <unordered_map>

namespace bytemorph::virt {

using namespace bytemorph::core;
using namespace bytemorph::core::ir;

namespace {

class RegAllocator {
public:
    RegAllocator() {
        map_["rax"] = 0; map_["eax"] = 0; map_["x0"] = 0; map_["w0"] = 0; map_["r0"] = 0;
        map_["rcx"] = 1; map_["ecx"] = 1; map_["x1"] = 1; map_["w1"] = 1; map_["r1"] = 1;
        map_["rdx"] = 2; map_["edx"] = 2; map_["x2"] = 2; map_["w2"] = 2; map_["r2"] = 2;
        map_["rbx"] = 3; map_["ebx"] = 3; map_["x3"] = 3; map_["w3"] = 3; map_["r3"] = 3;
        map_["rsp"] = 4; map_["sp"]  = 4;
        map_["rbp"] = 5; map_["x29"] = 5;
        map_["rsi"] = 6; map_["esi"] = 6; map_["x4"] = 6;
        map_["rdi"] = 7; map_["edi"] = 7; map_["x5"] = 7;
        map_["r8"]  = 8; map_["r8d"] = 8;
        map_["r9"]  = 9; map_["r9d"] = 9;
        map_["r10"] = 10; map_["r10d"] = 10;
        map_["r11"] = 11; map_["r11d"] = 11;
    }

    diagnostics::Result<std::uint8_t> get_or_alloc(const std::string& name) {
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
    if (cond == "jl" || cond == "b.lt") return VmOpcode::Jlt;
    if (cond == "jle" || cond == "b.le") return VmOpcode::Jle;
    if (cond == "jg" || cond == "b.gt") return VmOpcode::Jgt;
    if (cond == "jge" || cond == "b.ge") return VmOpcode::Jge;
    return VmOpcode::Jne;
}

} // namespace

diagnostics::Result<BvmProgram>
IrToVmTranslator::translate(const IrFunction& fn, std::uint64_t build_seed) {
    using diagnostics::ErrorCode;
    if (fn.blocks.empty()) {
        return diagnostics::Result<BvmProgram>::err(
            ErrorCode::EmptyInput, "Cannot translate empty IrFunction", "IrToVmTranslator::translate");
    }

    BvmProgram prog;
    prog.build_seed = build_seed;

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
            return reg_alloc.get_or_alloc(op.name);
        }
        if (op.kind == IrOperand::Kind::Memory) {
            auto base_r = reg_alloc.get_or_alloc(op.name);
            if (!base_r) return base_r;
            prog.instructions.push_back(VmInstruction{VmOpcode::Load, scratch_reg, base_r.value(), 0, 0});
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
                    auto dst_r = reg_alloc.get_or_alloc(insn.dsts[0].name);
                    if (!dst_r) return diagnostics::Result<BvmProgram>::err(dst_r.error().code, dst_r.error().message, dst_r.error().context);
                    if (insn.srcs[0].kind == IrOperand::Kind::Immediate) {
                        prog.instructions.push_back(VmInstruction{VmOpcode::MovImm, dst_r.value(), 0, 0, insn.srcs[0].imm});
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
                    prog.instructions.push_back(VmInstruction{VmOpcode::Load, dst_r.value(), base_r.value(), 0, 0});
                    break;
                }
                case IrOpcode::Store: {
                    if (insn.dsts.size() != 1 || insn.srcs.size() != 1) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::ParseError, "Invalid Store arity", "IrToVmTranslator::translate");
                    }
                    auto base_r = reg_alloc.get_or_alloc(insn.dsts[0].name);
                    auto src_r = materialize_src(insn.srcs[0], 29);
                    if (!base_r || !src_r) return diagnostics::Result<BvmProgram>::err(ErrorCode::OutOfBounds, "Register allocation failed", "IrToVmTranslator::translate");
                    prog.instructions.push_back(VmInstruction{VmOpcode::Store, base_r.value(), src_r.value(), 0, 0});
                    break;
                }
                case IrOpcode::Add:
                case IrOpcode::Sub:
                case IrOpcode::Mul:
                case IrOpcode::Div:
                case IrOpcode::And:
                case IrOpcode::Or:
                case IrOpcode::Xor:
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
                case IrOpcode::Jump: {
                    if (insn.srcs.empty() || insn.srcs[0].kind != IrOperand::Kind::Label) {
                        return diagnostics::Result<BvmProgram>::err(ErrorCode::UnsupportedFormat, "Indirect/non-label Jump not supported in VM translator", "IrToVmTranslator::translate");
                    }
                    const std::size_t pc = prog.instructions.size();
                    prog.instructions.push_back(VmInstruction{VmOpcode::Jmp, 0, 0, 0, 0});
                    patches.push_back(PendingPatch{pc, static_cast<std::uint64_t>(insn.srcs[0].imm)});
                    break;
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
                case IrOpcode::Call:
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
