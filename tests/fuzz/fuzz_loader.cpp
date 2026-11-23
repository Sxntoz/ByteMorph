#include "bytemorph/core/binary/loader.hpp"
#include "bytemorph/formats/elf/elf_parser.hpp"
#include "bytemorph/formats/macho/macho_parser.hpp"
#include "bytemorph/formats/pe/pe_parser.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (!data || size > 4 * 1024 * 1024) {
        return 0;
    }

    bytemorph::core::binary::BinaryLoader loader;
    loader.register_parser(std::make_unique<bytemorph::formats::pe::PeParser>());
    loader.register_parser(std::make_unique<bytemorph::formats::elf::ElfParser>());
    loader.register_parser(std::make_unique<bytemorph::formats::macho::MachOParser>());

    std::vector<std::uint8_t> buf(data, data + size);
    auto res = loader.load_buffer(std::move(buf));
    if (res) {
        const auto& bin = *res.value();
        (void)bin.info();
        (void)bin.sections();
        (void)bin.segments();
        (void)bin.read_virtual(bin.info().entry_point, 16);
    }
    return 0;
}
