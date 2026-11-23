# Changelog

## [0.5.0] - 2026-11-23

### Adicionado
- `ElfRewriter` funcional para ELF64 x86-64 (System V AMD64 ABI, segmentos `PT_LOAD` W^X `.bmrt`/`.bmvm`, preservação de PIE).
- `MachORewriter` funcional para Mach-O 64-bit (x86-64 e ARM64/AAPCS64, segmentos `__BMRT`/`__BMVM` e integração com `/usr/bin/codesign` no macOS).
- Emissor PIC compartilhado (`native_vm_emitter`) para Win64, System V AMD64 e AArch64.
- Suporte a chamadas externas autorizadas (`VmOpcode::CallExt`) na VM e no `IrToVmTranslator`.
- Testes de integração multiplataforma para Windows PE32+, Linux ELF64 e macOS Mach-O 64-bit.

## [0.4.0] - 2026-11-23
- Reescritor PE32+ x86-64, virtualização seletiva nativa, criptografia autenticada XChaCha20-Poly1305 + BLAKE2b-256.

## [0.3.0] - 2026-11-23
- Engine de ofuscação sobre IR, VM baseada em registradores, tradutor IR → `.bvm`, protótipo AsmJit.

## [0.2.0] - 2026-11-23
- Parser Mach-O 64-bit/Fat, disassembler/lifter ARM64, descoberta avançada de funções, CFG 2.0, fuzz targets.

## [0.1.0] - 2026-11-23
- Fundação multiplataforma C++20/Rust, parsers PE32+/ELF64, disassembler x86-64 e CLI inicial.
