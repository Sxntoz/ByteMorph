#pragma once

#include "bytemorph/core/diagnostics/error.hpp"
#include "bytemorph/core/ir/ir.hpp"
#include "bytemorph/virt/bytecode_contract.hpp"

namespace bytemorph::virt {

/// Future contract (v0.2+) for translating architecture-independent IR into VM bytecode.
class IIrToVmTranslator {
public:
    virtual ~IIrToVmTranslator() = default;

    [[nodiscard]] virtual core::diagnostics::Result<BytecodeStream>
    translate(const core::ir::IrFunction& fn, const BytecodeSpec& spec) const = 0;
};

} // namespace bytemorph::virt
