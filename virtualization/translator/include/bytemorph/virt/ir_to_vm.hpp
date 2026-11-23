#pragma once

#include "bytemorph/core/diagnostics/error.hpp"
#include "bytemorph/core/ir/ir.hpp"
#include "bytemorph/virt/bvm_format.hpp"

#include <cstdint>

namespace bytemorph::virt {

/// Translates an architecture-independent IrFunction into a ByteMorph VM program (.bvm).
class IrToVmTranslator {
public:
    [[nodiscard]] static core::diagnostics::Result<BvmProgram>
    translate(const core::ir::IrFunction& fn, std::uint64_t build_seed = 0);
};

} // namespace bytemorph::virt
