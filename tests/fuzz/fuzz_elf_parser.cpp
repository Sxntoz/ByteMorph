#include "bytemorph/formats/elf/elf_parser.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (!data || size > 4 * 1024 * 1024) {
        return 0;
    }
    bytemorph::formats::elf::ElfParser parser;
    std::vector<std::uint8_t> buf(data, data + size);
    auto res = parser.parse(std::move(buf));
    if (res) {
        (void)res.value()->symbols();
        (void)res.value()->segments();
        (void)res.value()->relocations();
    }
    return 0;
}
