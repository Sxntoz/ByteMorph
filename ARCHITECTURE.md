# Arquitetura do ByteMorph (v0.8)

## Camadas

- `core/{diagnostics,binary,analysis,ir}`: detecção, leitura bounds-checked, CFG 2.0, serialização `BMIR` v1 e interpretador de referência com endereçamento `base + disp` e larguras 8/16/32/64 bits.
- `formats/{pe,elf,macho}` e `architectures/{x86_64,aarch64}`: parsers LIEF, disassemblers Zydis/Capstone e lifters IR com suporte a stack frames (`push`/`pop`/`leave`/`stp`/`ldp`), indexação complexa e RMW em memória.
- `obfuscation/`: pipeline determinístico (`SemanticSubstitutionPass`, `ArithmeticBooleanMbaPass`, `ControlFlowObfuscationPass`) e `EquivalenceValidator`.
- `virtualization/`: VM baseada em 32 registradores de 64 bits (`vm.load`/`vm.store` 8/16/32/64-bit, `vm.call`/`vm.ret`, `vm.callext`, `vm.halt` trap `0xFF`), codec `.bvm` (`BMVM` v1), tradutor `IrToVmTranslator` (jump tables e chamadas indiretas autorizadas) e `VmInterpreter`.
- `protection/`:
  - `CryptoAead` (Monocypher 4.0.2: **XChaCha20-Poly1305 AEAD** + **BLAKE2b-256**).
  - `native_vm_emitter`: emissor PIC compartilhado (`emit_shared_pic_x64_vm_runtime` / `emit_shared_pic_arm64_vm_runtime`) para **Win64**, **System V AMD64** e **ARM64 (AAPCS64)**, com planejador multifuncional transacional (`prepare_target_functions`), stack frame virtual isolado e `Load`/`Store` 8/16/32/64 bits.
  - `PeRewriter` (PE32+ x86-64 e ARM64), `ElfRewriter` (ELF64 x86-64 e ARM64), `MachORewriter` (Mach-O 64-bit e Fat/Universal x86-64/ARM64) e `ProtectionEngine::check_compatibility`.
- `rust/bytemorph-verify`: pré-validador seguro (`#![forbid(unsafe_code)]`) e entropia.
