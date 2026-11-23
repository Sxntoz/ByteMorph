#include "bytemorph/arch/aarch64/aarch64_disasm.hpp"

#include <capstone/capstone.h>

#include <iomanip>
#include <sstream>

namespace bytemorph::arch::aarch64 {

using namespace bytemorph::core;
using namespace bytemorph::core::analysis;

diagnostics::Result<std::vector<DisassembledInstruction>>
AArch64Disassembler::disassemble(std::span<const std::uint8_t> code,
                                 std::uint64_t base_va,
                                 std::size_t max_instructions) const {
    if (code.empty()) {
        return std::vector<DisassembledInstruction>{};
    }

    csh handle = 0;
    if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        return diagnostics::Result<std::vector<DisassembledInstruction>>::err(
            diagnostics::ErrorCode::InternalError,
            "Failed to initialize Capstone AArch64 decoder",
            "AArch64Disassembler::disassemble");
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    cs_insn* insn = cs_malloc(handle);
    if (!insn) {
        cs_close(&handle);
        return diagnostics::Result<std::vector<DisassembledInstruction>>::err(
            diagnostics::ErrorCode::InternalError,
            "Failed to allocate Capstone instruction buffer",
            "AArch64Disassembler::disassemble");
    }

    std::vector<DisassembledInstruction> out;
    const uint8_t* ptr = code.data();
    size_t remaining = code.size();
    uint64_t addr = base_va;

    while (remaining > 0) {
        if (max_instructions > 0 && out.size() >= max_instructions) {
            break;
        }

        if (remaining < 4) {
            // Trailing partial bytes
            DisassembledInstruction invalid;
            invalid.address = addr;
            invalid.bytes.assign(ptr, ptr + remaining);
            invalid.mnemonic = "db";
            std::ostringstream oss;
            oss << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(*ptr);
            invalid.operands_text = oss.str();
            invalid.full_text = "db " + invalid.operands_text;
            invalid.flow = ControlFlowKind::Sequential;
            out.push_back(std::move(invalid));
            break;
        }

        if (!cs_disasm_iter(handle, &ptr, &remaining, &addr, insn)) {
            // Invalid 4-byte AArch64 opcode: emit .word data placeholder and advance 4 bytes
            DisassembledInstruction invalid;
            invalid.address = addr;
            invalid.bytes.assign(ptr, ptr + 4);
            invalid.mnemonic = "dcd";
            const std::uint32_t word = static_cast<std::uint32_t>(ptr[0]) |
                                       (static_cast<std::uint32_t>(ptr[1]) << 8) |
                                       (static_cast<std::uint32_t>(ptr[2]) << 16) |
                                       (static_cast<std::uint32_t>(ptr[3]) << 24);
            std::ostringstream oss;
            oss << "0x" << std::hex << std::setw(8) << std::setfill('0') << word;
            invalid.operands_text = oss.str();
            invalid.full_text = "dcd " + invalid.operands_text;
            invalid.flow = ControlFlowKind::Sequential;
            out.push_back(std::move(invalid));

            ptr += 4;
            remaining -= 4;
            addr += 4;
            continue;
        }

        DisassembledInstruction di;
        di.address = insn->address;
        di.bytes.assign(insn->bytes, insn->bytes + insn->size);
        di.mnemonic = insn->mnemonic;
        di.operands_text = insn->op_str;
        di.full_text = di.operands_text.empty()
            ? di.mnemonic
            : (di.mnemonic + " " + di.operands_text);

        const auto id = insn->id;
        const auto* detail = insn->detail;

        if (id == ARM64_INS_RET || id == ARM64_INS_RETAA || id == ARM64_INS_RETAB || id == ARM64_INS_ERET) {
            di.flow = ControlFlowKind::Return;
        } else if (id == ARM64_INS_BL) {
            di.flow = ControlFlowKind::Call;
        } else if (id == ARM64_INS_BLR || id == ARM64_INS_BLRAA || id == ARM64_INS_BLRAB) {
            di.flow = ControlFlowKind::Call;
            di.is_indirect = true;
        } else if (id == ARM64_INS_BR || id == ARM64_INS_BRAA || id == ARM64_INS_BRAB) {
            di.flow = ControlFlowKind::UnconditionalJump;
            di.is_indirect = true;
        } else if (id == ARM64_INS_B) {
            const bool is_cond = detail &&
                detail->arm64.cc != ARM64_CC_INVALID &&
                detail->arm64.cc != ARM64_CC_AL &&
                detail->arm64.cc != ARM64_CC_NV;
            di.flow = is_cond ? ControlFlowKind::ConditionalJump : ControlFlowKind::UnconditionalJump;
        } else if (id == ARM64_INS_CBZ || id == ARM64_INS_CBNZ || id == ARM64_INS_TBZ || id == ARM64_INS_TBNZ) {
            di.flow = ControlFlowKind::ConditionalJump;
        } else if (id == ARM64_INS_SVC || id == ARM64_INS_HVC || id == ARM64_INS_SMC || id == ARM64_INS_BRK) {
            di.flow = ControlFlowKind::Interrupt;
        } else if (id == ARM64_INS_HLT) {
            di.flow = ControlFlowKind::Halt;
        } else {
            di.flow = ControlFlowKind::Sequential;
        }

        if (detail && (di.flow == ControlFlowKind::UnconditionalJump ||
                       di.flow == ControlFlowKind::ConditionalJump ||
                       di.flow == ControlFlowKind::Call) && !di.is_indirect) {
            for (uint8_t i = 0; i < detail->arm64.op_count; ++i) {
                const auto& op = detail->arm64.operands[i];
                if (op.type == ARM64_OP_IMM) {
                    di.branch_target = static_cast<std::uint64_t>(op.imm);
                    break;
                }
            }
        }

        out.push_back(std::move(di));
    }

    cs_free(insn, 1);
    cs_close(&handle);
    return out;
}

} // namespace bytemorph::arch::aarch64
