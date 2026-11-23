#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace bytemorph::virt {

/// Future contract (v0.2+) for polymorphic bytecode ISA generation.
struct BytecodeSpec {
    std::uint32_t isa_version{1};
    std::uint64_t build_seed{0}; // Enables per-build bytecode diversification
    bool encrypt_handlers{false};
};

struct BytecodeStream {
    BytecodeSpec spec;
    std::vector<std::uint8_t> bytes;
    std::vector<std::uint8_t> opcode_map;
};

} // namespace bytemorph::virt
