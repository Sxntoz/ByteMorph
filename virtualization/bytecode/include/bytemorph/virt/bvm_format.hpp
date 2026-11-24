#pragma once

#include "bytemorph/core/diagnostics/error.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string_view>
#include <vector>

namespace bytemorph::virt {

enum class VmOpcode : std::uint8_t {
    Nop = 0x00,
    MovReg = 0x01,
    MovImm = 0x02,
    Load = 0x03,
    Store = 0x04,
    Add = 0x05,
    Sub = 0x06,
    Mul = 0x07,
    Div = 0x08,
    And = 0x09,
    Or = 0x0A,
    Xor = 0x0B,
    Shl = 0x0C,
    Shr = 0x0D,
    Cmp = 0x0E,
    Jmp = 0x0F,
    Jeq = 0x10,
    Jne = 0x11,
    Jlt = 0x12,
    Jle = 0x13,
    Jgt = 0x14,
    Jge = 0x15,
    Call = 0x16,
    Ret = 0x17,
    Halt = 0x18,
    CallExt = 0x19,
    LeaPic = 0x1A,
    SelectCc = 0x1B,
    SetCc = 0x1C,
    VMovReg = 0x1D,
    VAddF32 = 0x1E,
    VAddF64 = 0x1F,
    VSubF32 = 0x20,
    VSubF64 = 0x21,
    VMulF32 = 0x22,
    VMulF64 = 0x23,
    VDivF32 = 0x24,
    VDivF64 = 0x25,
    VCmpF32 = 0x26,
    VCmpF64 = 0x27,
    VLoad = 0x28,
    VStore = 0x29,
    VXor = 0x2A,
    MaxOpcode = 0x2B
};

enum class VmCondCode : std::uint8_t {
    Eq = 0,
    Ne = 1,
    Lt = 2,
    Le = 3,
    Gt = 4,
    Ge = 5,
    Below = 6,      // CF == 1 (unsigned <)
    BelowEq = 7,    // CF == 1 || ZF == 1 (unsigned <=)
    Above = 8,      // CF == 0 && ZF == 0 (unsigned >)
    AboveEq = 9,    // CF == 0 (unsigned >=)
    Sign = 10,      // SF == 1
    NotSign = 11,   // SF == 0
    Overflow = 12,  // OF == 1
    NotOverflow = 13
};

[[nodiscard]] std::string_view to_string(VmOpcode op) noexcept;

struct VmInstruction {
    VmOpcode opcode{VmOpcode::Nop};
    std::uint8_t dst{0};
    std::uint8_t src1{0};
    std::uint8_t src2{0};
    std::int64_t imm{0};
};

struct BvmProgram {
    static constexpr std::uint32_t kMagic = 0x4D564D42u; // "BMVM" LE
    static constexpr std::uint16_t kVersion = 1;
    static constexpr std::size_t kInstructionSize = 12;
    static constexpr std::size_t kNumRegisters = 32;
    static constexpr std::size_t kOpcodeTableSize = 64;
    static constexpr std::size_t kMaxInstructions = 1048576;

    std::uint64_t build_seed{0};
    std::vector<VmInstruction> instructions;
};

class BvmCodec {
public:
    /// Generates a deterministic physical-opcode permutation table from build_seed.
    [[nodiscard]] static std::array<std::uint8_t, BvmProgram::kOpcodeTableSize>
    make_opcode_table(std::uint64_t build_seed) noexcept;

    [[nodiscard]] static core::diagnostics::Result<std::vector<std::uint8_t>>
    encode(const BvmProgram& program);

    [[nodiscard]] static core::diagnostics::Result<BvmProgram>
    decode(std::span<const std::uint8_t> data);

    [[nodiscard]] static core::diagnostics::Result<void>
    save_to_file(const BvmProgram& program, const std::filesystem::path& path);

    [[nodiscard]] static core::diagnostics::Result<BvmProgram>
    load_from_file(const std::filesystem::path& path);
};

} // namespace bytemorph::virt
