# ByteMorph

**ByteMorph** é um framework open source, modular e multiplataforma de análise binária, ofuscação de IR, virtualização de código e proteção de binários em **C++20** e **Rust**.

> **Status atual (v0.5.0):**  
> - **Análise estática e IR/VM:** multiplataforma (PE32+, ELF64, Mach-O 64-bit / Fat Universal; x86-64 e ARM64).  
> - **Proteção e reescrita de binários (`protect` / `verify`):** funcional para **Windows PE32+ x86-64**, **Linux ELF64 x86-64** (`ET_EXEC` / PIE `ET_DYN`) e **macOS Mach-O 64-bit** (x86-64 e ARM64, com re-assinatura ad-hoc via `/usr/bin/codesign` no macOS).

## Recursos da v0.5

- **Reescrita multiplataforma (`protection/`):**
  - `PeRewriter` (PE32+ x86-64, Win64 ABI).
  - `ElfRewriter` (ELF64 x86-64, System V AMD64 ABI, criação de segmentos `PT_LOAD` respeitando W^X).
  - `MachORewriter` (Mach-O 64-bit x86-64 e ARM64/AAPCS64, segmentos `__BMRT`/`__BMVM`, respeito à política de assinatura do macOS).
- **Chamadas externas na VM (`vm.callext`):** ponte PIC relativa para chamadas autorizadas compatível com Win64 e System V AMD64.
- **Criptografia Autenticada e Integridade (Monocypher 4.0.2):** **XChaCha20-Poly1305 AEAD** + **BLAKE2b-256** (`BMP4` v1).

## Compilação (Windows, Linux e macOS)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel 2
ctest --test-dir build -C Release --output-on-failure
cargo test --workspace
```

## Uso da CLI (v0.5)

```bash
bytemorph protect input_bin --output protected_bin --profile balanced --func bm_target_compute
bytemorph verify protected_bin
bytemorph protection-info protected_bin
bytemorph benchmark-protection
```

## Licença

Distribuído sob a licença **Apache-2.0**. Consulte [LICENSE](LICENSE).
Compatível com LIEF (Apache-2.0), Zydis (MIT), Capstone (BSD-3-Clause), AsmJit (Zlib), Monocypher (CC0/BSD-2-Clause) e GoogleTest (BSD-3-Clause).
