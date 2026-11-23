#pragma once

#include "bytemorph/core/binary/types.hpp"
#include "bytemorph/core/diagnostics/error.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace bytemorph::prot {

enum class FunctionProtectionMode {
    None = 0,
    Mutation,
    Virtualization,
    Hybrid
};

struct FunctionProtectionPolicy {
    std::uint64_t function_va{0};
    std::string symbol_name;
    FunctionProtectionMode mode{FunctionProtectionMode::None};
};

struct ProtectionPlan {
    std::vector<FunctionProtectionPolicy> functions;
    bool protect_strings{false};
    bool protect_constants{false};
    bool protect_resources{false};
    bool enable_integrity_verification{false};
    bool optimize_performance{true};
    std::uint64_t diversification_seed{0};
};

/// Future contract (v0.3+) for cross-platform binary protection pipeline.
class IProtectionPipeline {
public:
    virtual ~IProtectionPipeline() = default;

    [[nodiscard]] virtual core::diagnostics::Result<std::vector<std::uint8_t>>
    protect(const core::binary::IBinaryFile& input, const ProtectionPlan& plan) const = 0;
};

} // namespace bytemorph::prot
