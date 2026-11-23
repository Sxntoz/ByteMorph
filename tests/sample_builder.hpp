#pragma once

#include <cstdint>
#include <cstring>
#include <vector>

namespace bytemorph::tests {

inline void write_u16_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint16_t v) {
    buf[off] = static_cast<std::uint8_t>(v & 0xFF);
    buf[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
}

inline void write_u32_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint32_t v) {
    buf[off] = static_cast<std::uint8_t>(v & 0xFF);
    buf[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
    buf[off + 2] = static_cast<std::uint8_t>((v >> 16) & 0xFF);
    buf[off + 3] = static_cast<std::uint8_t>((v >> 24) & 0xFF);
}

inline void write_u64_le(std::vector<std::uint8_t>& buf, std::size_t off, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        buf[off + i] = static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF);
    }
}

/// Sample x86-64 machine code with call, conditional jump, and ret:
/// +0x00: call +7 (target +0x0C)
/// +0x05: xor eax, eax
/// +0x07: ret
/// +0x08: nop x4
/// +0x0C: cmp rax, 0
/// +0x10: je +3 (target +0x15)
/// +0x12: inc rax
/// +0x15: ret
inline std::vector<std::uint8_t> sample_x86_64_code() {
    return {
        0xE8, 0x07, 0x00, 0x00, 0x00, // call +7
        0x31, 0xC0,                   // xor eax, eax
        0xC3,                         // ret
        0x90, 0x90, 0x90, 0x90,       // nop x4
        0x48, 0x83, 0xF8, 0x00,       // cmp rax, 0
        0x74, 0x03,                   // je +3
        0x48, 0xFF, 0xC0,             // inc rax
        0xC3                          // ret
    };
}

/// Builds a minimal valid ELF64 (x86-64, ET_EXEC) with a .text section at 0x401000.
inline std::vector<std::uint8_t> build_minimal_elf64_x86_64(const std::vector<std::uint8_t>& code) {
    const std::size_t text_off = 0x1000;
    const std::size_t text_span = (std::max)(std::size_t{0x200}, (code.size() + 0x1FF) & ~std::size_t(0x1FF));
    const std::size_t shstrtab_off = text_off + text_span;
    const std::string shstrtab = std::string("\0.text\0.shstrtab\0", 16);
    const std::size_t shdr_off = shstrtab_off + 0x40;
    const std::size_t total_size = shdr_off + 3 * 64;

    std::vector<std::uint8_t> buf(total_size, 0);

    // e_ident
    buf[0] = 0x7F; buf[1] = 'E'; buf[2] = 'L'; buf[3] = 'F';
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EV_CURRENT

    write_u16_le(buf, 16, 2);        // e_type = ET_EXEC
    write_u16_le(buf, 18, 62);       // e_machine = EM_X86_64
    write_u32_le(buf, 20, 1);        // e_version = 1
    write_u64_le(buf, 24, 0x401000); // e_entry
    write_u64_le(buf, 32, 64);       // e_phoff
    write_u64_le(buf, 40, shdr_off); // e_shoff
    write_u16_le(buf, 52, 64);       // e_ehsize
    write_u16_le(buf, 54, 56);       // e_phentsize
    write_u16_le(buf, 56, 1);        // e_phnum
    write_u16_le(buf, 58, 64);       // e_shentsize
    write_u16_le(buf, 60, 3);        // e_shnum
    write_u16_le(buf, 62, 2);        // e_shstrndx

    // Elf64_Phdr at offset 64 (PT_LOAD)
    write_u32_le(buf, 64 + 0, 1);          // p_type = PT_LOAD
    write_u32_le(buf, 64 + 4, 5);          // p_flags = PF_R | PF_X
    write_u64_le(buf, 64 + 8, text_off);   // p_offset
    write_u64_le(buf, 64 + 16, 0x401000);  // p_vaddr
    write_u64_le(buf, 64 + 24, 0x401000);  // p_paddr
    write_u64_le(buf, 64 + 32, code.size()); // p_filesz
    write_u64_le(buf, 64 + 40, code.size()); // p_memsz
    write_u64_le(buf, 64 + 48, 0x1000);    // p_align

    // .text bytes
    std::memcpy(buf.data() + text_off, code.data(), code.size());
    std::memcpy(buf.data() + shstrtab_off, shstrtab.data(), shstrtab.size());

    // Section 1: .text
    const std::size_t s1 = shdr_off + 64;
    write_u32_le(buf, s1 + 0, 1);            // sh_name = ".text"
    write_u32_le(buf, s1 + 4, 1);            // sh_type = SHT_PROGBITS
    write_u64_le(buf, s1 + 8, 0x6);          // sh_flags = SHF_ALLOC | SHF_EXECINSTR
    write_u64_le(buf, s1 + 16, 0x401000);    // sh_addr
    write_u64_le(buf, s1 + 24, text_off);    // sh_offset
    write_u64_le(buf, s1 + 32, code.size()); // sh_size
    write_u64_le(buf, s1 + 48, 16);          // sh_addralign

    // Section 2: .shstrtab
    const std::size_t s2 = shdr_off + 128;
    write_u32_le(buf, s2 + 0, 7);                 // sh_name = ".shstrtab"
    write_u32_le(buf, s2 + 4, 3);                 // sh_type = SHT_STRTAB
    write_u64_le(buf, s2 + 24, shstrtab_off);     // sh_offset
    write_u64_le(buf, s2 + 32, shstrtab.size());  // sh_size
    write_u64_le(buf, s2 + 48, 1);                // sh_addralign

    return buf;
}

/// Builds a minimal valid PE32+ (x86-64) executable with a .text section at RVA 0x1000.
inline std::vector<std::uint8_t> build_minimal_pe64_x86_64(const std::vector<std::uint8_t>& code) {
    const std::size_t raw_text_off = 0x200;
    const std::size_t raw_text_size = (std::max)(std::size_t{0x200}, (code.size() + 0x1FF) & ~std::size_t(0x1FF));
    const std::size_t virt_image_size = 0x1000 + ((code.size() + 0xFFF) & ~std::size_t(0xFFF));
    std::vector<std::uint8_t> buf(raw_text_off + raw_text_size, 0);

    // DOS Header
    buf[0] = 'M';
    buf[1] = 'Z';
    write_u32_le(buf, 0x3C, 0x80); // e_lfanew

    // PE Signature
    const std::size_t pe = 0x80;
    buf[pe] = 'P'; buf[pe + 1] = 'E'; buf[pe + 2] = 0; buf[pe + 3] = 0;

    // COFF File Header (20 bytes at pe + 4)
    const std::size_t coff = pe + 4;
    write_u16_le(buf, coff + 0, 0x8664); // Machine = AMD64
    write_u16_le(buf, coff + 2, 1);      // NumberOfSections = 1
    write_u16_le(buf, coff + 16, 0xF0);  // SizeOfOptionalHeader = 240
    write_u16_le(buf, coff + 18, 0x0022);// Characteristics = EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // Optional Header PE32+ (240 bytes at pe + 24)
    const std::size_t opt = pe + 24;
    write_u16_le(buf, opt + 0, 0x20B);       // Magic = PE32+
    write_u32_le(buf, opt + 4, static_cast<std::uint32_t>(raw_text_size)); // SizeOfCode
    write_u32_le(buf, opt + 16, 0x1000);     // AddressOfEntryPoint
    write_u32_le(buf, opt + 20, 0x1000);     // BaseOfCode
    write_u64_le(buf, opt + 24, 0x140000000ULL); // ImageBase
    write_u32_le(buf, opt + 32, 0x1000);     // SectionAlignment
    write_u32_le(buf, opt + 36, 0x200);      // FileAlignment
    write_u16_le(buf, opt + 40, 6);          // MajorOSVersion
    write_u16_le(buf, opt + 48, 6);          // MajorSubsystemVersion
    write_u32_le(buf, opt + 56, static_cast<std::uint32_t>(virt_image_size)); // SizeOfImage
    write_u32_le(buf, opt + 60, 0x200);      // SizeOfHeaders
    write_u16_le(buf, opt + 68, 3);          // Subsystem = WINDOWS_CUI
    write_u16_le(buf, opt + 70, 0x8160);     // DllCharacteristics (DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE)
    write_u32_le(buf, opt + 108, 16);        // NumberOfRvaAndSizes

    // Section Header (.text) at opt + 240 (0x188)
    const std::size_t sec = opt + 0xF0;
    std::memcpy(buf.data() + sec, ".text\0\0\0", 8);
    write_u32_le(buf, sec + 8, static_cast<std::uint32_t>(code.size())); // VirtualSize
    write_u32_le(buf, sec + 12, 0x1000);                                 // VirtualAddress
    write_u32_le(buf, sec + 16, static_cast<std::uint32_t>(raw_text_size)); // SizeOfRawData
    write_u32_le(buf, sec + 20, static_cast<std::uint32_t>(raw_text_off));  // PointerToRawData
    write_u32_le(buf, sec + 36, 0x60000020);                             // CODE | EXECUTE | READ

    std::memcpy(buf.data() + raw_text_off, code.data(), code.size());
    return buf;
}

/// Sample x86-64 loop code:
/// +0x00: xor ecx, ecx (31 C9)
/// +0x02: inc ecx      (FF C1)  <-- loop header
/// +0x04: cmp ecx, 3   (83 F9 03)
/// +0x07: jl -7        (7C F9)  -> +0x02
/// +0x09: ret          (C3)
inline std::vector<std::uint8_t> sample_x86_64_loop_code() {
    return {
        0x31, 0xC9,       // xor ecx, ecx
        0xFF, 0xC1,       // inc ecx
        0x83, 0xF9, 0x03, // cmp ecx, 3
        0x7C, 0xF9,       // jl +0x02
        0xC3              // ret
    };
}

/// Sample ARM64 (AArch64) little-endian machine code:
/// +0x00: mov x0, #0        (00 00 80 D2)
/// +0x04: cmp x0, #0        (1F 00 00 F1)
/// +0x08: b.eq +0x08        (40 00 00 54) -> +0x10
/// +0x0C: add x0, x0, #1    (00 04 00 91)
/// +0x10: bl +0x08          (02 00 00 94) -> +0x18
/// +0x14: ret               (C0 03 5F D6)
/// +0x18: add x0, x0, #2    (00 08 00 91)
/// +0x1C: ret               (C0 03 5F D6)
inline std::vector<std::uint8_t> sample_arm64_code() {
    return {
        0x00, 0x00, 0x80, 0xD2, // mov x0, #0
        0x1F, 0x00, 0x00, 0xF1, // cmp x0, #0
        0x40, 0x00, 0x00, 0x54, // b.eq #0x10
        0x00, 0x04, 0x00, 0x91, // add x0, x0, #1
        0x02, 0x00, 0x00, 0x94, // bl #0x18
        0xC0, 0x03, 0x5F, 0xD6, // ret
        0x00, 0x08, 0x00, 0x91, // add x0, x0, #2
        0xC0, 0x03, 0x5F, 0xD6  // ret
    };
}

/// Builds a minimal valid ELF64 (AArch64, ET_EXEC) with a .text section at 0x401000.
inline std::vector<std::uint8_t> build_minimal_elf64_arm64(const std::vector<std::uint8_t>& code) {
    auto buf = build_minimal_elf64_x86_64(code);
    write_u16_le(buf, 18, 183); // e_machine = EM_AARCH64
    return buf;
}

/// Builds a minimal valid Mach-O 64-bit binary (x86-64 or ARM64) with __TEXT/__text and LC_MAIN.
inline std::vector<std::uint8_t> build_minimal_macho64(bool arm64, const std::vector<std::uint8_t>& code) {
    // Layout:
    // 0x0000..0x0020: mach_header_64 (32 bytes)
    // 0x0020..0x00B8: LC_SEGMENT_64 __TEXT (72 + 80 = 152 bytes, 1 section __text)
    // 0x00B8..0x00D0: LC_MAIN (24 bytes)
    // 0x1000..      : __text code bytes
    const std::size_t text_off = 0x1000;
    const std::size_t total_size = text_off + ((code.size() + 0xFFF) & ~std::size_t(0xFFF));
    std::vector<std::uint8_t> buf(total_size, 0);

    // mach_header_64
    write_u32_le(buf, 0, 0xFEEDFACF);                         // MH_MAGIC_64
    write_u32_le(buf, 4, arm64 ? 0x0100000Cu : 0x01000007u);  // CPU_TYPE_ARM64 / X86_64
    write_u32_le(buf, 8, arm64 ? 0u : 3u);                    // cpusubtype
    write_u32_le(buf, 12, 2);                                 // MH_EXECUTE
    write_u32_le(buf, 16, 2);                                 // ncmds = 2
    write_u32_le(buf, 20, 152 + 24);                          // sizeofcmds
    write_u32_le(buf, 24, 0x00200085);                        // MH_PIE | MH_DYLDLINK | MH_NOUNDEFS

    // LC_SEGMENT_64 (0x19) at 0x20
    const std::size_t seg = 0x20;
    write_u32_le(buf, seg + 0, 0x19);                         // cmd = LC_SEGMENT_64
    write_u32_le(buf, seg + 4, 152);                          // cmdsize
    std::memcpy(buf.data() + seg + 8, "__TEXT\0\0\0\0\0\0\0\0\0\0", 16);
    write_u64_le(buf, seg + 24, 0x100000000ULL);              // vmaddr
    write_u64_le(buf, seg + 32, 0x2000);                      // vmsize
    write_u64_le(buf, seg + 40, 0);                           // fileoff
    write_u64_le(buf, seg + 48, total_size);                  // filesize
    write_u32_le(buf, seg + 56, 7);                           // maxprot = RWX
    write_u32_le(buf, seg + 60, 5);                           // initprot = RX
    write_u32_le(buf, seg + 64, 1);                           // nsects = 1

    // section_64 (__text) at seg + 72
    const std::size_t sec = seg + 72;
    std::memcpy(buf.data() + sec + 0, "__text\0\0\0\0\0\0\0\0\0\0", 16);
    std::memcpy(buf.data() + sec + 16, "__TEXT\0\0\0\0\0\0\0\0\0\0", 16);
    write_u64_le(buf, sec + 32, 0x100001000ULL);              // addr
    write_u64_le(buf, sec + 40, code.size());                 // size
    write_u32_le(buf, sec + 48, static_cast<std::uint32_t>(text_off)); // offset
    write_u32_le(buf, sec + 52, 4);                           // align
    write_u32_le(buf, sec + 64, 0x80000400u);                 // S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS

    // LC_MAIN (0x80000028) at 0xB8
    const std::size_t main_cmd = 0xB8;
    write_u32_le(buf, main_cmd + 0, 0x80000028u);
    write_u32_le(buf, main_cmd + 4, 24);
    write_u64_le(buf, main_cmd + 8, text_off);                // entryoff

    std::memcpy(buf.data() + text_off, code.data(), code.size());
    return buf;
}

inline void write_u32_be(std::vector<std::uint8_t>& buf, std::size_t off, std::uint32_t v) {
    buf[off] = static_cast<std::uint8_t>((v >> 24) & 0xFF);
    buf[off + 1] = static_cast<std::uint8_t>((v >> 16) & 0xFF);
    buf[off + 2] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
    buf[off + 3] = static_cast<std::uint8_t>(v & 0xFF);
}

/// Builds a minimal Fat/Universal Mach-O containing two slices.
inline std::vector<std::uint8_t> build_minimal_macho_fat(const std::vector<std::uint8_t>& x64_slice,
                                                         const std::vector<std::uint8_t>& arm64_slice) {
    const std::size_t off1 = 0x1000;
    const std::size_t off2 = off1 + ((x64_slice.size() + 0xFFF) & ~std::size_t(0xFFF));
    const std::size_t total = off2 + arm64_slice.size();
    std::vector<std::uint8_t> buf(total, 0);

    // fat_header (big-endian)
    write_u32_be(buf, 0, 0xCAFEBABEu); // FAT_MAGIC
    write_u32_be(buf, 4, 2);           // nfat_arch

    // fat_arch[0] = x86_64
    write_u32_be(buf, 8 + 0, 0x01000007u);
    write_u32_be(buf, 8 + 4, 3);
    write_u32_be(buf, 8 + 8, static_cast<std::uint32_t>(off1));
    write_u32_be(buf, 8 + 12, static_cast<std::uint32_t>(x64_slice.size()));
    write_u32_be(buf, 8 + 16, 12);

    // fat_arch[1] = arm64
    write_u32_be(buf, 28 + 0, 0x0100000Cu);
    write_u32_be(buf, 28 + 4, 0);
    write_u32_be(buf, 28 + 8, static_cast<std::uint32_t>(off2));
    write_u32_be(buf, 28 + 12, static_cast<std::uint32_t>(arm64_slice.size()));
    write_u32_be(buf, 28 + 16, 12);

    std::memcpy(buf.data() + off1, x64_slice.data(), x64_slice.size());
    std::memcpy(buf.data() + off2, arm64_slice.data(), arm64_slice.size());
    return buf;
}

} // namespace bytemorph::tests
