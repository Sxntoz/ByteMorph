#pragma once

#include "bytemorph/core/diagnostics/error.hpp"
#include "bytemorph/core/ir/ir.hpp"
#include "bytemorph/core/ir/ir_interpreter.hpp"
#include "bytemorph/obf/obfuscation_contract.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace bytemorph::obf {

struct ObfuscationConfig {
    std::uint64_t seed{0x42595445ULL};
    double max_expansion_factor{6.0};
    bool enable_substitution{true};
    bool enable_mba{true};
    bool enable_cfg{true};
};

struct ObfuscationReport {
    std::size_t original_instructions{0};
    std::size_t obfuscated_instructions{0};
    double expansion_ratio{1.0};
    std::vector<std::string> passes_applied;
};

class SemanticSubstitutionPass final : public IObfuscationPass {
public:
    explicit SemanticSubstitutionPass(std::uint64_t seed) : seed_(seed) {}
    [[nodiscard]] std::string_view name() const noexcept override { return "SemanticSubstitution"; }
    [[nodiscard]] core::diagnostics::Result<void> run(core::ir::IrFunction& fn) const override;

private:
    std::uint64_t seed_;
};

class ArithmeticBooleanMbaPass final : public IObfuscationPass {
public:
    explicit ArithmeticBooleanMbaPass(std::uint64_t seed) : seed_(seed) {}
    [[nodiscard]] std::string_view name() const noexcept override { return "ArithmeticBooleanMBA"; }
    [[nodiscard]] core::diagnostics::Result<void> run(core::ir::IrFunction& fn) const override;

private:
    std::uint64_t seed_;
};

class ControlFlowObfuscationPass final : public IObfuscationPass {
public:
    explicit ControlFlowObfuscationPass(std::uint64_t seed) : seed_(seed) {}
    [[nodiscard]] std::string_view name() const noexcept override { return "ControlFlowObfuscation"; }
    [[nodiscard]] core::diagnostics::Result<void> run(core::ir::IrFunction& fn) const override;

private:
    std::uint64_t seed_;
};

class ObfuscationPipeline {
public:
    [[nodiscard]] static core::diagnostics::Result<ObfuscationReport>
    obfuscate_function(core::ir::IrFunction& fn, const ObfuscationConfig& config);

    [[nodiscard]] static core::diagnostics::Result<ObfuscationReport>
    obfuscate_module(core::ir::IrModule& mod, const ObfuscationConfig& config);
};

class EquivalenceValidator {
public:
    [[nodiscard]] static core::diagnostics::Result<bool>
    verify(const core::ir::IrFunction& original,
           const core::ir::IrFunction& obfuscated,
           const std::vector<core::ir::IrExecOptions>& test_cases);
};

} // namespace bytemorph::obf
