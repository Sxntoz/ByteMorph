# Arquitetura do ByteMorph (v0.5)

## Camadas

- `core/{diagnostics,binary,analysis,ir}`: detecção, leitura bounds-checked, CFG 2.0, serialização `BMIR` v1 e interpretador de referência.
- `formats/{pe,elf,macho}` e `architectures/{x86_64,aarch64}`: parsers LIEF, disassemblers Zydis/Capstone e lifters IR.
- `obfuscation/`: pipeline determinístico (`SemanticSubstitutionPass`, `ArithmeticBooleanMbaPass`, `ControlFlowObfuscationPass`) e `EquivalenceValidator`.
- `virtualization/`: VM baseada em 32 registradores de 64 bits, codec `.bvm` (`BMVM` v1, incluindo `vm.callext`), tradutor `IrToVmTranslator` e protótipo AsmJit.
- `protection/`:
  - `CryptoAead` (Monocypher 4.0.2: **XChaCha20-Poly1305 AEAD** + **BLAKE2b-256**).
  - `native_vm_emitter`: emissor PIC compartilhado para **Win64**, **System V AMD64** e **ARM64 (AAPCS64)** via AsmJit.
  - `PeRewriter` (PE32+ x86-64), `ElfRewriter` (ELF64 x86-64) e `MachORewriter` (Mach-O 64-bit x86-64/ARM64).
- `rust/bytemorph-verify`: pré-validador seguro (`#![forbid(unsafe_code)]`) e entropia.
