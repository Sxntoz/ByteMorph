#pragma once

#include "bytemorph/core/binary/types.hpp"
#include "bytemorph/core/diagnostics/error.hpp"
#include "bytemorph/virt/bytecode_contract.hpp"

#include <cstdint>
#include <vector>

namespace bytemorph::virt {

/// Future contract (v0.2+) for emitting target-native VM dispatcher stubs (via AsmJit).
class IVmBackend {
public:
    virtual ~IVmBackend() = default;

    [[nodiscard]] virtual core::binary::Architecture target_architecture() const noexcept = 0;
    [[nodiscard]] virtual core::binary::TargetOS target_os() const noexcept = 0;

    [[nodiscard]] virtual core::diagnostics::Result<std::vector<std::uint8_t>>
    emit_vm_runtime(const BytecodeSpec& spec) const = 0;
};

} // namespace bytemorph::virt
