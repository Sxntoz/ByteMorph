#pragma once

#include "bytemorph/core/ir/ir.hpp"

#include <cstddef>
#include <string>
#include <unordered_set>
#include <vector>

namespace bytemorph::core::ir {

struct IrOptimizeOptions {
    int level{2}; // 0=none, 1=basic, 2=balanced, 3=aggressive
    bool enable_constant_folding{true};
    bool enable_constant_propagation{true};
    bool enable_copy_propagation{true};
    bool enable_algebraic_simplification{true};
    bool enable_branch_simplification{true};
    bool enable_dce{true};
    bool enable_redundant_elim{true};
    bool enable_vreg_coalescing{true};
};

struct IrOptimizeStats {
    std::size_t instructions_before{0};
    std::size_t instructions_after{0};
    std::size_t constants_folded{0};
    std::size_t copies_propagated{0};
    std::size_t algebraic_simplifications{0};
    std::size_t dead_instructions_removed{0};
    std::size_t redundant_ops_removed{0};
    std::size_t branches_simplified{0};
    std::size_t vregs_coalesced{0};
    std::size_t passes_run{0};
};

struct BlockLiveness {
    std::uint64_t block_id{0};
    std::unordered_set<std::string> live_in;
    std::unordered_set<std::string> live_out;
};

class IrOptimizer {
public:
    [[nodiscard]] static IrOptimizeStats optimize(
        IrFunction& fn, const IrOptimizeOptions& options = {});

    [[nodiscard]] static IrOptimizeStats optimize(
        IrModule& mod, const IrOptimizeOptions& options = {});

    static std::size_t simplify_expressions(IrFunction& fn);
    static std::size_t propagate_and_fold_constants(IrFunction& fn);
    static std::size_t propagate_copies(IrFunction& fn);
    static std::size_t eliminate_redundant_instructions(IrFunction& fn);
    static std::size_t simplify_branches(IrFunction& fn);
    static std::size_t eliminate_dead_code(IrFunction& fn);
    static std::size_t coalesce_virtual_registers(IrFunction& fn);

    [[nodiscard]] static std::vector<BlockLiveness> compute_liveness(const IrFunction& fn);
};

} // namespace bytemorph::core::ir
