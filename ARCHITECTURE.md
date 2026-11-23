# Arquitetura do ByteMorph (v0.4)

## Camadas

- `core/{diagnostics,binary,analysis,ir}`: detecção, leitura bounds-checked, CFG 2.0, serialização `BMIR` v1 e interpretador de referência.
- `formats/{pe,elf,macho}` e `architectures/{x86_64,aarch64}`: parsers LIEF, disassemblers Zydis/Capstone e lifters IR.
- `obfuscation/`: pipeline determinístico (`SemanticSubstitutionPass`, `ArithmeticBooleanMbaPass`, `ControlFlowObfuscationPass`) e `EquivalenceValidator`.
- `virtualization/`: VM baseada em 32 registradores de 64 bits, codec `.bvm` (`BMVM` v1), tradutor `IrToVmTranslator` e protótipo AsmJit.
- `protection/`:
  - `CryptoAead` (Monocypher 4.0.2: **XChaCha20-Poly1305 AEAD** + **BLAKE2b-256**).
  - `IBinaryRewriter` (`PeRewriter` funcional para PE32+ x86-64; `ElfRewriter` e `MachORewriter` como contratos para v0.5).
  - Runtime nativo PIC x86-64 (`.bmrt` `R-X`) + metadados autenticados `BMP4` v1 (`.bmvm` `R--`).
- `rust/bytemorph-verify`: pré-validador seguro (`#![forbid(unsafe_code)]`) e entropia.
