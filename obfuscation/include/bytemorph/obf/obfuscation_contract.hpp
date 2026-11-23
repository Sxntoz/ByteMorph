#pragma once

#include "bytemorph/core/diagnostics/error.hpp"
#include "bytemorph/core/ir/ir.hpp"

#include <string_view>

namespace bytemorph::obf {

/// Future contract (v0.2+) for semantics-preserving IR obfuscation passes
/// (control-flow flattening, opaque predicates, instruction mutation).
class IObfuscationPass {
public:
    virtual ~IObfuscationPass() = default;

    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
    [[nodiscard]] virtual core::diagnostics::Result<void>
    run(core::ir::IrFunction& fn) const = 0;
};

} // namespace bytemorph::obf
