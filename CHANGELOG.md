# Changelog

## [0.6.0] - 2026-11-23

### Adicionado
- **Stack frames e memória 8/16/32/64 bits:** `vm.load` e `vm.store` (`base + disp`) nos interpretadores IR/VM e nos emissores nativos PIC x86-64 (`1360B` frame) e ARM64 (`1376B` frame), com validação de limites e alinhamento de pilha ABI.
- **ELF64 ARM64:** proteção funcional de binários Linux AArch64 em `ElfRewriter`, preservando PIE/ASLR e segmentos `PT_LOAD` W^X, com execução nativa no CI (`ubuntu-24.04-arm`).
- **Controle de fluxo avançado:** chamadas indiretas autorizadas (`authorized_call_targets`), jump tables validadas (`jump_table_targets`), trap `vm.halt (dst=0xFF)`, `vm.div` nativo ARM64/x86-64 e suporte expandido aos lifters x86-64/AArch64 (`push`/`pop`/`leave`/`stp`/`ldp`/`madd`/`cbz`/`cbnz`/RMW).
- **CLI v0.6:** `bytemorph compatibility <in> --format json`, `bytemorph protect --functions auto` e `bytemorph analyze --functions`.
- **Testes:** 6 novos testes `ProtectionV06Test` (44 testes C++ + 3 testes Rust).

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
