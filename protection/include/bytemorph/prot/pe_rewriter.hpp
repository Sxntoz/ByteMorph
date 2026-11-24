#pragma once

#include "bytemorph/core/binary/types.hpp"
#include "bytemorph/core/diagnostics/error.hpp"
#include "bytemorph/prot/crypto_aead.hpp"

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace bytemorph::prot {

enum class ProtectionProfile : std::uint8_t {
    Fast = 0,
    Balanced = 1,
    Maximum = 2
};

[[nodiscard]] inline std::string_view to_string(ProtectionProfile p) noexcept {
    switch (p) {
        case ProtectionProfile::Fast: return "fast";
        case ProtectionProfile::Balanced: return "balanced";
        case ProtectionProfile::Maximum: return "maximum";
    }
    return "balanced";
}

struct ProtectOptions {
    ProtectionProfile profile{ProtectionProfile::Balanced};
    std::uint64_t seed{0x425954453034ULL};
    std::optional<std::uint64_t> target_function_rva;
    std::string target_function_name;
    std::vector<std::uint64_t> target_function_rvas;
    std::vector<std::string> target_function_names;
    bool protect_strings{true};
    bool allow_strip_signature{false};
    bool allow_external_calls{false};
    bool auto_select_functions{false};
    bool protect_all_eligible{false};
    bool rollback_on_failure{true};
    bool encrypt_bytecode{false};
};

struct FunctionCompatibilityEntry {
    std::string name;
    std::uint64_t entry_va{0};
    std::uint64_t size_bytes{0};
    bool eligible{false};
    bool uses_simd{false};
    bool has_exception_unwind{false};
    std::uint32_t ir_ops{0};
    std::uint32_t vm_ops{0};
    std::string category;
    std::uint32_t estimated_overhead_pct{0};
    std::uint32_t estimated_runtime_bytes{0};
    std::vector<std::string> unsupported_instructions;
    std::string exception_detail;
    std::string rejection_reason;
};

struct ExceptionUnwindEntry {
    std::string function_name;
    std::uint64_t entry_va{0};
    std::string mechanism;
    bool has_handler{false};
    bool compatible_with_vm{true};
    std::string detail;
};

struct CompatibilityReport {
    core::binary::BinaryFormat format{core::binary::BinaryFormat::Unknown};
    core::binary::Architecture architecture{core::binary::Architecture::Unknown};
    bool binary_supported{false};
    std::vector<FunctionCompatibilityEntry> eligible_functions;
    std::vector<FunctionCompatibilityEntry> rejected_functions;
    std::vector<std::string> os_requirements;
    std::vector<std::string> known_limitations;
};

struct ProtectedFunctionRecord {
    std::string name;
    std::uint64_t original_rva{0};
    std::uint64_t stub_rva{0};
    std::uint32_t patch_size{0};
    std::uint32_t orig_ir_ops{0};
    std::uint32_t obf_ir_ops{0};
    std::uint32_t vm_ops{0};
};

struct EncryptedBytecodeRecord {
    std::uint32_t fn_index{0};
    AeadNonce nonce;
    std::array<std::uint8_t, 16> mac{};
    std::uint32_t plaintext_size{0};
    std::array<std::uint8_t, 32> aad_hash{};
};

struct ProtectionMetadata {
    static constexpr std::uint32_t kMagic = 0x34504D42u; // "BMP4" LE
    static constexpr std::uint16_t kVersion = 2;

    ProtectionProfile profile{ProtectionProfile::Balanced};
    std::uint64_t seed{0};
    bool bytecode_encrypted{false};
    std::array<std::uint8_t, 32> text_blake2b{};
    std::array<std::uint8_t, 32> runtime_blake2b{};
    AeadSealedBox sealed_payload; // AEAD-encrypted BVM + protected strings/constants
    std::vector<ProtectedFunctionRecord> functions;
    std::uint32_t protected_strings_count{0};
    std::vector<EncryptedBytecodeRecord> encrypted_functions;
};

struct ProtectionReport {
    core::binary::BinaryFormat format{core::binary::BinaryFormat::Unknown};
    core::binary::Architecture architecture{core::binary::Architecture::Unknown};
    ProtectionProfile profile{ProtectionProfile::Balanced};
    std::uint64_t seed{0};
    std::uint64_t input_size{0};
    std::uint64_t output_size{0};
    std::vector<ProtectedFunctionRecord> protected_functions;
    std::uint32_t protected_strings_count{0};
    std::uint32_t total_functions_analyzed{0};
    std::uint32_t eligible_functions_count{0};
    std::vector<FunctionCompatibilityEntry> rejected_functions;
    double transform_time_ms{0.0};
    bool shared_runtime_used{false};
    std::uint64_t runtime_bytes_size{0};
    bool aslr_preserved{false};
    bool dep_preserved{false};
};

struct VerifyReport {
    bool valid{false};
    bool aead_authenticated{false};
    bool text_integrity_ok{false};
    bool runtime_integrity_ok{false};
    ProtectionMetadata metadata;
    std::string summary;
};

class IBinaryRewriter {
public:
    virtual ~IBinaryRewriter() = default;

    [[nodiscard]] virtual bool supports(core::binary::BinaryFormat fmt,
                                        core::binary::Architecture arch) const noexcept = 0;

    [[nodiscard]] virtual core::diagnostics::Result<ProtectionReport>
    protect_file(const std::filesystem::path& input,
                 const std::filesystem::path& output,
                 const ProtectOptions& options) const = 0;

    [[nodiscard]] virtual core::diagnostics::Result<VerifyReport>
    verify_file(const std::filesystem::path& path) const = 0;
};

class PeRewriter final : public IBinaryRewriter {
public:
    [[nodiscard]] bool supports(core::binary::BinaryFormat fmt,
                                core::binary::Architecture arch) const noexcept override;

    [[nodiscard]] core::diagnostics::Result<ProtectionReport>
    protect_file(const std::filesystem::path& input,
                 const std::filesystem::path& output,
                 const ProtectOptions& options) const override;

    [[nodiscard]] core::diagnostics::Result<VerifyReport>
    verify_file(const std::filesystem::path& path) const override;
};

class ElfRewriter final : public IBinaryRewriter {
public:
    [[nodiscard]] bool supports(core::binary::BinaryFormat fmt,
                                core::binary::Architecture arch) const noexcept override;

    [[nodiscard]] core::diagnostics::Result<ProtectionReport>
    protect_file(const std::filesystem::path& input,
                 const std::filesystem::path& output,
                 const ProtectOptions& options) const override;

    [[nodiscard]] core::diagnostics::Result<VerifyReport>
    verify_file(const std::filesystem::path& path) const override;
};

class MachORewriter final : public IBinaryRewriter {
public:
    [[nodiscard]] bool supports(core::binary::BinaryFormat fmt,
                                core::binary::Architecture arch) const noexcept override;

    [[nodiscard]] core::diagnostics::Result<ProtectionReport>
    protect_file(const std::filesystem::path& input,
                 const std::filesystem::path& output,
                 const ProtectOptions& options) const override;

    [[nodiscard]] core::diagnostics::Result<VerifyReport>
    verify_file(const std::filesystem::path& path) const override;
};

class ProtectionEngine {
public:
    [[nodiscard]] static core::diagnostics::Result<ProtectionReport>
    protect(const std::filesystem::path& input,
            const std::filesystem::path& output,
            const ProtectOptions& options);

    [[nodiscard]] static core::diagnostics::Result<VerifyReport>
    verify(const std::filesystem::path& path);

    [[nodiscard]] static core::diagnostics::Result<CompatibilityReport>
    check_compatibility(const std::filesystem::path& path,
                        bool allow_external_calls = false);

    [[nodiscard]] static core::diagnostics::Result<std::vector<ExceptionUnwindEntry>>
    analyze_exceptions(const std::filesystem::path& path);
};

} // namespace bytemorph::prot
