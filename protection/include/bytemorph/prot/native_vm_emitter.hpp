#pragma once

#include "bytemorph/core/analysis/analyzer.hpp"
#include "bytemorph/core/binary/binary_file.hpp"
#include "bytemorph/core/diagnostics/error.hpp"
#include "bytemorph/prot/pe_rewriter.hpp"
#include "bytemorph/virt/bvm_format.hpp"

#include <cstdint>
#include <span>
#include <unordered_set>
#include <vector>

namespace bytemorph::prot::detail {

enum class AbiKind {
    Win64 = 0,
    SysV_AMD64 = 1
};

struct SharedRuntimeLayout {
    std::vector<std::uint64_t> entry_offsets;
    std::uint64_t core_offset{0};
};

struct PreparedFunction {
    std::string name;
    std::uint64_t entry_va{0};
    std::uint64_t size_bytes{0};
    std::uint32_t orig_ir_ops{0};
    std::uint32_t obf_ir_ops{0};
    virt::BvmProgram program;
};

struct MultiFunctionPlan {
    std::uint32_t total_analyzed{0};
    std::uint32_t eligible_count{0};
    std::vector<PreparedFunction> prepared;
    std::vector<FunctionCompatibilityEntry> rejected;
};

[[nodiscard]] FunctionCompatibilityEntry
evaluate_function_eligibility(const core::binary::IBinaryFile& bin,
                              const core::analysis::AnalysisResult& analysis,
                              const core::analysis::FunctionInfo& fn,
                              const std::unordered_set<std::uint64_t>& auth_calls,
                              bool allow_external_calls,
                              bool is_arm64,
                              virt::BvmProgram* out_program = nullptr,
                              std::uint32_t* out_orig_ir_ops = nullptr);

[[nodiscard]] core::diagnostics::Result<MultiFunctionPlan>
prepare_target_functions(const core::binary::IBinaryFile& bin,
                         const core::analysis::AnalysisResult& analysis,
                         core::analysis::IDisassemblerEngine& disasm,
                         const ProtectOptions& options,
                         std::uint64_t stub_base_va,
                         bool is_arm64);

[[nodiscard]] std::uint64_t align_up(std::uint64_t v, std::uint64_t align) noexcept;

[[nodiscard]] std::vector<std::uint8_t> serialize_metadata(const ProtectionMetadata& m);

[[nodiscard]] core::diagnostics::Result<ProtectionMetadata>
deserialize_metadata(std::span<const std::uint8_t> data);

[[nodiscard]] std::vector<std::uint8_t>
collect_printable_strings(std::span<const std::uint8_t> data, std::uint32_t& out_count);

[[nodiscard]] std::unordered_set<std::uint64_t>
build_authorized_call_targets(const core::binary::IBinaryFile& bin,
                              const core::analysis::AnalysisResult& analysis);

[[nodiscard]] core::diagnostics::Result<std::vector<std::uint8_t>>
emit_pic_x64_vm_runtime(const virt::BvmProgram& prog, AbiKind abi);

[[nodiscard]] core::diagnostics::Result<std::vector<std::uint8_t>>
emit_pic_arm64_vm_runtime(const virt::BvmProgram& prog);

[[nodiscard]] core::diagnostics::Result<std::vector<std::uint8_t>>
emit_shared_pic_x64_vm_runtime(const std::vector<virt::BvmProgram>& progs,
                               AbiKind abi,
                               SharedRuntimeLayout& out_layout);

[[nodiscard]] core::diagnostics::Result<std::vector<std::uint8_t>>
emit_shared_pic_arm64_vm_runtime(const std::vector<virt::BvmProgram>& progs,
                                 SharedRuntimeLayout& out_layout);

} // namespace bytemorph::prot::detail
