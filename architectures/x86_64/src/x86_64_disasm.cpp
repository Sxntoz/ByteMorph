#include "bytemorph/arch/x86_64/x86_64_disasm.hpp"

#include <Zydis/Zydis.h>

#include <cstdio>
#include <iomanip>
#include <sstream>

namespace bytemorph::arch::x86_64 {

using namespace bytemorph::core;
using namespace bytemorph::core::analysis;

diagnostics::Result<std::vector<DisassembledInstruction>>
X86_64Disassembler::disassemble(std::span<const std::uint8_t> code,
                                std::uint64_t base_va,
                                std::size_t max_instructions) const {
    if (code.empty()) {
        return std::vector<DisassembledInstruction>{};
    }

    ZydisDecoder decoder;
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64))) {
        return diagnostics::Result<std::vector<DisassembledInstruction>>::err(
            diagnostics::ErrorCode::InternalError, "Failed to initialize Zydis x86-64 decoder", "X86_64Disassembler::disassemble");
    }

    ZydisFormatter formatter;
    if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL))) {
        return diagnostics::Result<std::vector<DisassembledInstruction>>::err(
            diagnostics::ErrorCode::InternalError, "Failed to initialize Zydis Intel formatter", "X86_64Disassembler::disassemble");
    }

    std::vector<DisassembledInstruction> out;
    std::size_t offset = 0;

    while (offset < code.size()) {
        if (max_instructions > 0 && out.size() >= max_instructions) {
            break;
        }

        const std::uint64_t va = base_va + offset;
        ZydisDecodedInstruction insn;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        const ZyanStatus status = ZydisDecoderDecodeFull(
            &decoder,
            code.data() + offset,
            code.size() - offset,
            &insn,
            operands);

        if (!ZYAN_SUCCESS(status)) {
            // Emit 1-byte data placeholder on invalid/truncated opcode so linear scan recovers safely
            DisassembledInstruction invalid;
            invalid.address = va;
            invalid.bytes.push_back(code[offset]);
            invalid.mnemonic = "db";
            std::ostringstream oss;
            oss << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(code[offset]);
            invalid.operands_text = oss.str();
            invalid.full_text = "db " + invalid.operands_text;
            invalid.flow = ControlFlowKind::Sequential;
            out.push_back(std::move(invalid));
            offset += 1;
            continue;
        }

        char buffer[256] = {};
        if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter, &insn, operands, insn.operand_count_visible, buffer, sizeof(buffer), va, ZYAN_NULL))) {
            std::snprintf(buffer, sizeof(buffer), "%s", ZydisMnemonicGetString(insn.mnemonic));
        }

        DisassembledInstruction di;
        di.address = va;
        di.bytes.assign(code.data() + offset, code.data() + offset + insn.length);
        di.full_text = buffer;

        const char* mnem = ZydisMnemonicGetString(insn.mnemonic);
        di.mnemonic = mnem ? mnem : "unknown";

        const auto space_pos = di.full_text.find(' ');
        if (space_pos != std::string::npos) {
            di.operands_text = di.full_text.substr(space_pos + 1);
        }

        switch (insn.meta.category) {
            case ZYDIS_CATEGORY_UNCOND_BR:
                di.flow = ControlFlowKind::UnconditionalJump;
                break;
            case ZYDIS_CATEGORY_COND_BR:
                di.flow = ControlFlowKind::ConditionalJump;
                break;
            case ZYDIS_CATEGORY_CALL:
                di.flow = ControlFlowKind::Call;
                break;
            case ZYDIS_CATEGORY_RET:
                di.flow = ControlFlowKind::Return;
                break;
            case ZYDIS_CATEGORY_INTERRUPT:
                di.flow = ControlFlowKind::Interrupt;
                break;
            default:
                di.flow = (insn.mnemonic == ZYDIS_MNEMONIC_HLT)
                    ? ControlFlowKind::Halt
                    : ControlFlowKind::Sequential;
                break;
        }

        if (di.flow == ControlFlowKind::UnconditionalJump ||
            di.flow == ControlFlowKind::ConditionalJump ||
            di.flow == ControlFlowKind::Call) {
            if (insn.operand_count_visible > 0) {
                const auto& op0 = operands[0];
                if (op0.type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    ZyanU64 target = 0;
                    if (ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &op0, va, &target))) {
                        di.branch_target = static_cast<std::uint64_t>(target);
                    }
                } else {
                    di.is_indirect = true;
                }
            }
        }

        out.push_back(std::move(di));
        offset += insn.length;
    }

    return out;
}

} // namespace bytemorph::arch::x86_64
