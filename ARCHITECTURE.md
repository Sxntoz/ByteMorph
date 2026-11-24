# Arquitetura do ByteMorph (v0.12)

## Camadas

- `core/{diagnostics,binary,analysis,ir}`: detecção, leitura bounds-checked, CFG 2.0, serialização `BMIR` v1, otimizador modular `IrOptimizer` (v0.12) e interpretador de referência com flags `ZF`/`SF`/`CF`/`OF`/`PF`, registradores vetoriais `vregs[32]`, globais `LeaGlobal`, condicionais e ponto flutuante IEEE 754 (`VMov`/`FAdd`/`FSub`/`FMul`/`FDiv`/`FCmp`/`FCvt`/`VPAdd`/`VPSub`).
- `formats/{pe,elf,macho}` e `architectures/{x86_64,aarch64}`: parsers LIEF, disassemblers Zydis/Capstone e lifters IR com suporte a RIP-relative, ARM64 `ADRP+ADD`/`ADRP+LDR`, condicionais avançadas e subconjunto SIMD/FP (SSE2 + ARM64 FP32/FP64).
- `obfuscation/`: pipeline determinístico (`SemanticSubstitutionPass`, `ArithmeticBooleanMbaPass`, `ControlFlowObfuscationPass`) e `EquivalenceValidator`.
- `virtualization/`: VM baseada em 32 registradores GPR + 32 registradores vetoriais (`V0..V31`), codec `.bvm` (`BMVM` v1, tabela de 64 opcodes), tradutor `IrToVmTranslator` e `VmInterpreter` com `thread_local` memory pool.
- `protection/`:
  - `CryptoAead` (Monocypher 4.0.2: **XChaCha20-Poly1305 AEAD** + **BLAKE2b-256**), metadados `BMP4` v2 e blobs `BMBC` v2 com nonces exclusivos.
  - `native_vm_emitter`: emissor PIC compartilhado para **Win64**, **System V AMD64** e **ARM64 (AAPCS64)** com verificador/descriptografador AEAD `XChaCha20-Poly1305` em runtime, limpeza do buffer ao sair e execução nativa SIMD/FP.
  - `PeRewriter`, `ElfRewriter`, `MachORewriter`, análise de exceções/unwind (`analyze_exceptions`) e Smart Eligibility 5.0 (`--max-overhead`, métricas de recursão/efeitos colaterais/SIMD).
- `sdk/`: API C/C++ versionada (`bytemorph/protect.h`, `bytemorph/protect.hpp`) e integração CMake (`ByteMorph::SDK`, `bytemorph_protect_target`).
- `rust/bytemorph-verify`: pré-validador seguro (`#![forbid(unsafe_code)]`) e entropia.
