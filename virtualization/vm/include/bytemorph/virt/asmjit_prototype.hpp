#pragma once

#include "bytemorph/core/diagnostics/error.hpp"

#include <cstdint>

namespace bytemorph::virt {

struct AsmJitBenchResult {
    std::uint64_t native_result{0};
    std::uint64_t vm_result{0};
    double native_ms{0.0};
    double vm_ms{0.0};
    bool available{false};
};

/// Controlled x86-64 AsmJit prototype comparing native JIT execution vs ByteMorph VM interpreter.
class AsmJitPrototype {
public:
    [[nodiscard]] static core::diagnostics::Result<AsmJitBenchResult>
    run_arithmetic_comparison(std::uint64_t a, std::uint64_t b, int iterations = 10000);
};

} // namespace bytemorph::virt
