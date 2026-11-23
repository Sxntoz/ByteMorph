#pragma once

#include "bytemorph/core/diagnostics/error.hpp"
#include "bytemorph/core/ir/ir.hpp"
#include "bytemorph/virt/bvm_format.hpp"

#include <cstdint>
#include <optional>
#include <unordered_set>

namespace bytemorph::virt {

struct TranslateOptions {
    std::uint64_t build_seed{0};
    bool allow_external_calls{false};
    std::uint64_t stub_base_va{0};
    std::unordered_set<std::uint64_t> authorized_call_targets;
};

/// Translates an architecture-independent IrFunction into a ByteMorph VM program (.bvm).
class IrToVmTranslator {
public:
    [[nodiscard]] static core::diagnostics::Result<BvmProgram>
    translate(const core::ir::IrFunction& fn, std::uint64_t build_seed = 0);

    [[nodiscard]] static core::diagnostics::Result<BvmProgram>
    translate(const core::ir::IrFunction& fn, const TranslateOptions& options);
};

} // namespace bytemorph::virt
