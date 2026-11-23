#include "bytemorph/core/ir/ir.hpp"

#include <sstream>

namespace bytemorph::core::ir {

std::string_view to_string(IrOpcode op) noexcept {
    switch (op) {
        case IrOpcode::Nop: return "nop";
        case IrOpcode::Mov: return "mov";
        case IrOpcode::Load: return "load";
        case IrOpcode::Store: return "store";
        case IrOpcode::Add: return "add";
        case IrOpcode::Sub: return "sub";
        case IrOpcode::Mul: return "mul";
        case IrOpcode::Div: return "div";
        case IrOpcode::And: return "and";
        case IrOpcode::Or: return "or";
        case IrOpcode::Xor: return "xor";
        case IrOpcode::Shl: return "shl";
        case IrOpcode::Shr: return "shr";
        case IrOpcode::Cmp: return "cmp";
        case IrOpcode::Jump: return "jmp";
        case IrOpcode::JumpCond: return "jcc";
        case IrOpcode::Call: return "call";
        case IrOpcode::Ret: return "ret";
        case IrOpcode::Syscall: return "syscall";
        case IrOpcode::Unknown: return "unknown";
    }
    return "unknown";
}

IrOperand IrOperand::vreg(std::string name, std::uint8_t width) {
    return IrOperand{Kind::VirtualReg, std::move(name), 0, width};
}

IrOperand IrOperand::reg(std::string name, std::uint8_t width) {
    return IrOperand{Kind::ArchReg, std::move(name), 0, width};
}

IrOperand IrOperand::immediate(std::int64_t value, std::uint8_t width) {
    return IrOperand{Kind::Immediate, {}, value, width};
}

IrOperand IrOperand::memory(std::string expr, std::uint8_t width) {
    return IrOperand{Kind::Memory, std::move(expr), 0, width};
}

IrOperand IrOperand::memory_disp(std::string base_reg, std::int64_t disp, std::uint8_t width) {
    return IrOperand{Kind::Memory, std::move(base_reg), disp, width};
}

IrOperand IrOperand::label(std::uint64_t va) {
    std::ostringstream oss;
    oss << "loc_0x" << std::hex << va;
    return IrOperand{Kind::Label, oss.str(), static_cast<std::int64_t>(va), 64};
}

std::string IrOperand::to_string() const {
    std::ostringstream oss;
    switch (kind) {
        case Kind::None:
            return "<none>";
        case Kind::VirtualReg:
            oss << "%" << name << ":i" << static_cast<unsigned>(bit_width);
            return oss.str();
        case Kind::ArchReg:
            oss << "$" << name << ":i" << static_cast<unsigned>(bit_width);
            return oss.str();
        case Kind::Immediate:
            oss << "0x" << std::hex << imm << ":i" << std::dec << static_cast<unsigned>(bit_width);
            return oss.str();
        case Kind::Memory:
            oss << "[" << name;
            if (imm > 0) {
                oss << "+0x" << std::hex << imm << std::dec;
            } else if (imm < 0) {
                oss << "-0x" << std::hex << (-imm) << std::dec;
            }
            oss << "]:i" << static_cast<unsigned>(bit_width);
            return oss.str();
        case Kind::Label:
            return name;
    }
    return "<unknown>";
}

std::string IrInstruction::to_string() const {
    std::ostringstream oss;
    oss << "0x" << std::hex << source_va << std::dec << ": ";
    if (!dsts.empty()) {
        for (std::size_t i = 0; i < dsts.size(); ++i) {
            if (i > 0) oss << ", ";
            oss << dsts[i].to_string();
        }
        oss << " = ";
    }
    oss << bytemorph::core::ir::to_string(opcode);
    if (!srcs.empty()) {
        oss << " ";
        for (std::size_t i = 0; i < srcs.size(); ++i) {
            if (i > 0) oss << ", ";
            oss << srcs[i].to_string();
        }
    }
    if (!comment.empty()) {
        oss << " ; " << comment;
    }
    return oss.str();
}

} // namespace bytemorph::core::ir
