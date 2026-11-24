# Arquitetura do ByteMorph (v0.9)

## Camadas

- `core/{diagnostics,binary,analysis,ir}`: detecção, leitura bounds-checked, CFG 2.0, serialização `BMIR` v1 e interpretador de referência com flags `ZF`/`SF`/`CF`/`OF`, endereçamento `base + disp`, globais `LeaGlobal`, `SelectCc`/`SetCc`/`Adc`/`Sbb`.
- `formats/{pe,elf,macho}` e `architectures/{x86_64,aarch64}`: parsers LIEF, disassemblers Zydis/Capstone e lifters IR com suporte a RIP-relative (`[rip+disp32]`, `[0x...]`), ARM64 `ADRP+ADD`/`ADRP+LDR`/`ADR`, `cmovcc`/`setcc`/`adc`/`sbb`, `csel`/`csinc`/`csinv`/`csneg`/`cset`/`csetm`, stack frames e RMW.
- `obfuscation/`: pipeline determinístico (`SemanticSubstitutionPass`, `ArithmeticBooleanMbaPass`, `ControlFlowObfuscationPass`) e `EquivalenceValidator`.
- `virtualization/`: VM baseada em 32 registradores de 64 bits (`VmOpcode::LeaPic`, `SelectCc`, `SetCc`, `Load`/`Store` 8/16/32/64-bit, `Call`/`Ret`, `CallExt`, `Halt` trap `0xFF`), `thread_local` memory pool no `VmInterpreter`, codec `.bvm` (`BMVM` v1) e `IrToVmTranslator`.
- `protection/`:
  - `CryptoAead` (Monocypher 4.0.2: **XChaCha20-Poly1305 AEAD** + **BLAKE2b-256**).
  - `native_vm_emitter`: emissor PIC compartilhado (`emit_shared_pic_x64_vm_runtime` / `emit_shared_pic_arm64_vm_runtime`) para **Win64**, **System V AMD64** e **ARM64 (AAPCS64)**, com `LeaPic`, `SelectCc`, `SetCc` e flags `ZF`/`SF`/`CF`/`OF` completos.
  - `PeRewriter` (PE32+ x86-64 e ARM64), `ElfRewriter` (ELF64 x86-64 e ARM64), `MachORewriter` (Mach-O 64-bit e Fat/Universal x86-64/ARM64) e Smart Eligibility 3.0 (`evaluate_function_eligibility`).
- `rust/bytemorph-verify`: pré-validador seguro (`#![forbid(unsafe_code)]`) e entropia.
