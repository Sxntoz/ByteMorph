#pragma once

#include "bytemorph/core/diagnostics/error.hpp"
#include "bytemorph/prot/crypto_aead.hpp"
#include "bytemorph/virt/bvm_format.hpp"
#include "bytemorph/virt/vm_interpreter.hpp"

#include <array>
#include <cstdint>
#include <vector>

namespace bytemorph::prot {

struct LazyBlockRecord {
    static constexpr std::uint32_t kMagic = 0x424C4D42u; // "BMLB" LE
    static constexpr std::uint16_t kVersion = 1;

    std::uint32_t fn_index{0};
    std::uint32_t block_id{0};
    std::uint32_t start_pc{0};
    std::uint32_t insn_count{0};
    AeadNonce nonce;
    std::array<std::uint8_t, 16> mac{};
    std::array<std::uint8_t, 32> aad_hash{};
    std::vector<std::uint8_t> ciphertext;
};

struct LazyFunctionBlob {
    std::uint32_t fn_index{0};
    std::uint32_t total_insns{0};
    std::uint64_t build_seed{0};
    std::vector<LazyBlockRecord> blocks;
};

class LazyBytecodeEngine {
public:
    [[nodiscard]] static std::vector<std::uint8_t>
    build_block_aad(std::uint32_t fn_index,
                    std::uint32_t block_id,
                    std::uint32_t start_pc,
                    std::uint32_t insn_count,
                    std::uint32_t plain_bytes);

    [[nodiscard]] static core::diagnostics::Result<LazyFunctionBlob>
    seal_function(const virt::BvmProgram& program,
                  const AeadKey& master_key,
                  std::uint64_t seed,
                  std::uint32_t fn_index);

    [[nodiscard]] static core::diagnostics::Result<std::vector<virt::VmInstruction>>
    open_block(const LazyBlockRecord& rec,
               const AeadKey& master_key,
               std::uint32_t expected_fn_index,
               std::uint64_t build_seed);

    [[nodiscard]] static core::diagnostics::Result<bool>
    verify_block_aead(const LazyBlockRecord& rec,
                      const AeadKey& master_key);

    [[nodiscard]] static core::diagnostics::Result<bool>
    verify_all_blocks(const LazyFunctionBlob& blob,
                      const AeadKey& master_key);

    [[nodiscard]] static core::diagnostics::Result<virt::VmExecState>
    execute_lazy(const LazyFunctionBlob& blob,
                 const AeadKey& master_key,
                 virt::VmBytecodeCache& cache,
                 const virt::VmExecOptions& options = {});
};

} // namespace bytemorph::prot
