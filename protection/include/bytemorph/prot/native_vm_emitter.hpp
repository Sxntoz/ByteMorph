#pragma once

#include "bytemorph/core/diagnostics/error.hpp"
#include "bytemorph/prot/pe_rewriter.hpp"
#include "bytemorph/virt/bvm_format.hpp"

#include <cstdint>
#include <span>
#include <vector>

namespace bytemorph::prot::detail {

enum class AbiKind {
    Win64 = 0,
    SysV_AMD64 = 1
};

[[nodiscard]] std::uint64_t align_up(std::uint64_t v, std::uint64_t align) noexcept;

[[nodiscard]] std::vector<std::uint8_t> serialize_metadata(const ProtectionMetadata& m);

[[nodiscard]] core::diagnostics::Result<ProtectionMetadata>
deserialize_metadata(std::span<const std::uint8_t> data);

[[nodiscard]] std::vector<std::uint8_t>
collect_printable_strings(std::span<const std::uint8_t> data, std::uint32_t& out_count);

[[nodiscard]] core::diagnostics::Result<std::vector<std::uint8_t>>
emit_pic_x64_vm_runtime(const virt::BvmProgram& prog, AbiKind abi);

[[nodiscard]] core::diagnostics::Result<std::vector<std::uint8_t>>
emit_pic_arm64_vm_runtime(const virt::BvmProgram& prog);

} // namespace bytemorph::prot::detail
