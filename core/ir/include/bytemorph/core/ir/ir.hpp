#pragma once

#include "bytemorph/core/binary/types.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace bytemorph::core::ir {

enum class IrOpcode {
    Nop = 0,
    Mov,
    Load,
    Store,
    Add,
    Sub,
    Mul,
    Div,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Cmp,
    Jump,
    JumpCond,
    Call,
    Ret,
    Syscall,
    LeaGlobal,
    SelectCc,
    SetCc,
    Adc,
    Sbb,
    VMov,
    FAdd,
    FSub,
    FMul,
    FDiv,
    FCmp,
    Unknown
};

[[nodiscard]] std::string_view to_string(IrOpcode op) noexcept;

struct IrOperand {
    enum class Kind {
        None = 0,
        VirtualReg,
        ArchReg,
        Immediate,
        Memory,
        Label
    };

    Kind kind{Kind::None};
    std::string name;
    std::int64_t imm{0};
    std::uint8_t bit_width{64};

    [[nodiscard]] static IrOperand vreg(std::string name, std::uint8_t width = 64);
    [[nodiscard]] static IrOperand reg(std::string name, std::uint8_t width = 64);
    [[nodiscard]] static IrOperand immediate(std::int64_t value, std::uint8_t width = 64);
    [[nodiscard]] static IrOperand memory(std::string expr, std::uint8_t width = 64);
    [[nodiscard]] static IrOperand memory_disp(std::string base_reg, std::int64_t disp, std::uint8_t width = 64);
    [[nodiscard]] static IrOperand label(std::uint64_t va);

    [[nodiscard]] std::string to_string() const;
};

struct IrInstruction {
    std::uint64_t source_va{0};
    IrOpcode opcode{IrOpcode::Nop};
    std::vector<IrOperand> dsts;
    std::vector<IrOperand> srcs;
    std::string cond;
    std::string comment;

    [[nodiscard]] std::string to_string() const;
};

struct IrBasicBlock {
    std::uint64_t id{0};
    std::uint64_t start_va{0};
    std::vector<IrInstruction> instructions;
    std::vector<std::uint64_t> successors;
};

struct IrFunction {
    std::string name;
    std::uint64_t entry_va{0};
    std::vector<IrBasicBlock> blocks;
};

struct IrModule {
    std::string name;
    binary::Architecture source_arch{binary::Architecture::Unknown};
    std::vector<IrFunction> functions;
};

} // namespace bytemorph::core::ir
