#pragma once

#include "bytemorph/core/diagnostics/error.hpp"
#include "bytemorph/virt/bvm_format.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <list>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace bytemorph::virt {

struct VmExecOptions {
    std::uint64_t max_steps{1000000};
    std::size_t memory_slots{4096};
    std::size_t max_call_depth{256};
    bool use_memory_pool{true};
    std::uint64_t pic_base_va{0};
    std::array<std::uint64_t, BvmProgram::kNumRegisters> initial_regs{};
    std::array<std::array<std::uint64_t, 2>, BvmProgram::kNumRegisters> initial_vregs{};
    std::function<std::optional<std::uint64_t>(std::int64_t, const std::array<std::uint64_t, BvmProgram::kNumRegisters>&)> external_call_handler;
};

struct VmExecState {
    std::array<std::uint64_t, BvmProgram::kNumRegisters> regs{};
    std::array<std::array<std::uint64_t, 2>, BvmProgram::kNumRegisters> vregs{};
    std::vector<std::uint64_t> memory;
    std::vector<std::size_t> call_stack;
    std::size_t pc{0};
    bool zf{false};
    bool sf{false};
    bool cf{false};
    bool of{false};
    bool pf{false};
    std::uint32_t mxcsr{0x1F80};
    std::uint32_t fpcr{0};
    std::uint32_t fpsr{0};
    std::uint64_t steps_executed{0};
    std::uint64_t allocations_count{0};
    std::uint64_t return_value{0};
};

struct FastVmInstruction {
    VmOpcode opcode{VmOpcode::Nop};
    std::uint8_t dst{0};
    std::uint8_t src1{0};
    std::uint8_t src2{0};
    std::uint32_t aux{0};
    std::int64_t imm{0};
};

struct PreparedBvmProgram {
    std::vector<FastVmInstruction> insns;
    std::size_t code_len{0};
    std::uint64_t build_seed{0};
    std::uint64_t fingerprint{0};
    bool has_mem_ops{false};
    bool has_simd_ops{false};
};

struct BvmBasicBlock {
    std::uint32_t block_id{0};
    std::size_t start_pc{0};
    std::vector<VmInstruction> instructions;
};

struct VmCacheStats {
    std::uint64_t hits{0};
    std::uint64_t misses{0};
    std::uint64_t evictions{0};
    std::uint64_t invalidations{0};
    std::size_t current_bytes{0};
    std::size_t peak_bytes{0};
    std::size_t cached_blocks{0};
};

/// Thread-safe LRU cache for authenticated decoded BVM basic blocks with secure wiping on eviction.
class VmBytecodeCache {
public:
    explicit VmBytecodeCache(std::size_t max_bytes = 64 * 1024, std::size_t max_entries = 128)
        : max_bytes_(max_bytes), max_entries_(max_entries) {}
    ~VmBytecodeCache();

    VmBytecodeCache(const VmBytecodeCache&) = delete;
    VmBytecodeCache& operator=(const VmBytecodeCache&) = delete;

    struct CachedBlock {
        std::vector<FastVmInstruction> insns;
        bool has_mem_ops{false};
        bool has_simd_ops{false};
        std::size_t byte_size() const noexcept {
            return insns.size() * sizeof(FastVmInstruction);
        }
    };

    [[nodiscard]] std::optional<CachedBlock> get(std::uint64_t context_id, std::size_t block_start_pc);
    void put(std::uint64_t context_id, std::size_t block_start_pc, CachedBlock block);
    void invalidate_context(std::uint64_t context_id);
    void invalidate_all();
    [[nodiscard]] VmCacheStats stats() const;

private:
    struct Key {
        std::uint64_t context_id{0};
        std::size_t start_pc{0};
        bool operator==(const Key& o) const noexcept {
            return context_id == o.context_id && start_pc == o.start_pc;
        }
    };
    struct KeyHash {
        std::size_t operator()(const Key& k) const noexcept {
            return std::hash<std::uint64_t>{}(k.context_id ^ (static_cast<std::uint64_t>(k.start_pc) * 0x9E3779B97F4A7C15ULL));
        }
    };
    struct LruNode {
        Key key;
        CachedBlock block;
    };

    static void wipe_block(CachedBlock& blk) noexcept;
    void evict_lru_locked();

    std::size_t max_bytes_{64 * 1024};
    std::size_t max_entries_{128};
    mutable std::mutex mutex_;
    std::list<LruNode> lru_;
    std::unordered_map<Key, std::list<LruNode>::iterator, KeyHash> index_;
    VmCacheStats stats_;
};

using LazyBlockFetcher = std::function<core::diagnostics::Result<std::vector<VmInstruction>>(std::size_t block_start_pc)>;

/// Register-based 64-bit ByteMorph Virtual Machine interpreter.
class VmInterpreter {
public:
    [[nodiscard]] static std::vector<BvmBasicBlock>
    split_into_basic_blocks(const BvmProgram& program);

    [[nodiscard]] static core::diagnostics::Result<PreparedBvmProgram>
    prepare(const BvmProgram& program);

    [[nodiscard]] static core::diagnostics::Result<VmExecState>
    execute_prepared(const PreparedBvmProgram& prepared, const VmExecOptions& options = {});

    [[nodiscard]] static core::diagnostics::Result<VmExecState>
    execute_lazy(std::size_t total_insns,
                 std::uint64_t context_id,
                 const std::vector<std::size_t>& block_starts,
                 const LazyBlockFetcher& fetcher,
                 VmBytecodeCache& cache,
                 const VmExecOptions& options = {});

    [[nodiscard]] static core::diagnostics::Result<VmExecState>
    execute(const BvmProgram& program, const VmExecOptions& options = {});
};

} // namespace bytemorph::virt
