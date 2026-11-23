#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace bytemorph::core::analysis {

enum class ControlFlowKind {
    Sequential = 0,
    UnconditionalJump,
    ConditionalJump,
    Call,
    Return,
    Interrupt,
    Halt
};

enum class AnalysisConfidence {
    Low = 0,
    Medium,
    High
};

[[nodiscard]] inline std::string_view to_string(AnalysisConfidence c) noexcept {
    switch (c) {
        case AnalysisConfidence::Low: return "Low";
        case AnalysisConfidence::Medium: return "Medium";
        case AnalysisConfidence::High: return "High";
    }
    return "Low";
}

struct DisassembledInstruction {
    std::uint64_t address{0};
    std::vector<std::uint8_t> bytes;
    std::string mnemonic;
    std::string operands_text;
    std::string full_text;
    ControlFlowKind flow{ControlFlowKind::Sequential};
    std::optional<std::uint64_t> branch_target;
    bool is_indirect{false};
};

struct BasicBlock {
    std::uint64_t start_va{0};
    std::uint64_t end_va{0};
    std::vector<DisassembledInstruction> instructions;
    std::vector<std::uint64_t> successors;
    std::vector<std::uint64_t> predecessors;
    bool is_unreachable{false};
    bool is_loop_header{false};
    bool has_indirect_branch{false};
    bool has_invalid_instruction{false};
};

struct FunctionInfo {
    std::string name;
    std::uint64_t entry_va{0};
    std::uint64_t size_bytes{0};
    std::optional<std::uint64_t> metadata_end_va;
    std::vector<BasicBlock> blocks;
    bool from_symbol{false};
    bool from_entry_point{false};
    bool from_call_target{false};
    bool from_unwind_metadata{false};
    bool overlaps_another_function{false};
    std::string discovery_source;
    std::size_t loop_count{0};
    std::size_t unreachable_block_count{0};
    std::size_t indirect_call_count{0};
    std::size_t indirect_jump_count{0};
    AnalysisConfidence confidence{AnalysisConfidence::Medium};
};

struct AnalysisLimitation {
    std::string area;
    std::string description;
};

struct AnalysisResult {
    std::vector<FunctionInfo> functions;
    std::vector<AnalysisLimitation> limitations;
    std::size_t total_instructions{0};
    std::size_t total_loops{0};
    std::size_t total_unreachable_blocks{0};
    std::size_t total_indirect_branches{0};
    AnalysisConfidence overall_confidence{AnalysisConfidence::Medium};
};

} // namespace bytemorph::core::analysis
