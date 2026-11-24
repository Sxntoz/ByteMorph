# ByteMorph

**ByteMorph** é um framework open source, modular e multiplataforma de análise binária, ofuscação de IR, virtualização de código e proteção de binários em **C++20** e **Rust**.

> **Status atual (v0.7.0):**  
> - **Análise estática e IR/VM:** multiplataforma (PE32+, ELF64, Mach-O 64-bit / Fat Universal; x86-64 e ARM64).  
> - **Proteção e reescrita de binários (`protect` / `verify` / `compatibility`):** funcional com **proteção multifuncional e runtime VM compartilhado** para **Windows PE32+ x86-64** (e cross-protection/verificação estrutural para **PE32+ ARM64**), **Linux ELF64 x86-64 e ARM64/AArch64** (`ET_EXEC` / PIE `ET_DYN`) e **macOS Mach-O 64-bit e Fat/Universal** (x86-64 + ARM64, com re-assinatura ad-hoc via `/usr/bin/codesign` no macOS).

## Recursos da v0.7

- **Proteção Multifuncional & Runtime Compartilhado:**
  - Proteção simultânea de múltiplas funções em uma única operação (`--functions all-eligible`, `--functions 0xRVA1,0xRVA2`, `--functions fn1,fn2`).
  - Um único runtime VM nativo PIC compartilhado (`.bmrt` / `__BMRT`) com stubs compactos por função (~12B x86-64 / 8B ARM64), validação transacional de sobreposições e rollback atômico antes de mutar `.text`.
- **Chamadas Externas e Entre Funções:** resolução segura de alvos autorizados (IAT/PLT/stubs e chamadas entre funções protegidas e não protegidas).
- **PE32+ ARM64 & Mach-O Universal:** suporte a reescrita e verificação estrutural/AEAD para PE32+ ARM64 (cross-protection) e proteção multi-slice para binários Mach-O Fat/Universal.
- **Otimização da VM:** pré-validação estática de bytecode (`validate_program`) fora do loop de despacho do `VmInterpreter`.
- **CLI v0.7:** `--functions all-eligible`, `--functions <lista>`, `protection-info <bin> --functions`, `benchmark-protection --detailed` e `--no-rollback`.
- **Criptografia Autenticada e Integridade (Monocypher 4.0.2):** **XChaCha20-Poly1305 AEAD** + **BLAKE2b-256** (`BMP4` v1).

## Compilação (Windows, Linux e macOS)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel 2
ctest --test-dir build -C Release --output-on-failure
cargo test --workspace
```

## Uso da CLI (v0.7)

```bash
bytemorph compatibility input_bin --format json
bytemorph protect input_bin --output protected_bin --profile balanced --functions all-eligible --allow-ext-calls
bytemorph protect input_bin --output protected_bin --functions fn1,fn2
bytemorph analyze input_bin --functions
bytemorph verify protected_bin
bytemorph protection-info protected_bin --functions
bytemorph benchmark-protection --detailed
```

## Benchmarks Reproduzíveis (Windows x64 Release)

- `bytemorph benchmark-protection --detailed`:
  - `Native Execution (10k iters)`: `0.013 ms`
  - `VM Interpreter (10k iters)`: `2.987 ms`
  - `VM Stack Load/Store (10k iters)`: `3.166 ms`
  - `External Call Bridge (10k)`: `2.405 ms`
  - Shared Runtime Scaling: 2 funcs (`x64=1492B`, `ARM64=1468B`), 5 funcs (`x64=1844B`, `ARM64=1804B`), 10 funcs (`x64=2420B`, `ARM64=2364B`), 20 funcs (`x64=3580B`, `ARM64=3484B`)
  - `PIC Runtime Emission (avg)`: `0.012 ms` (`x86-64=1388B`, `ARM64=1348B`)
  - `VM Working Set RAM (per ctx)`: `33024 bytes` (`native frame=1360B x64 / 1376B ARM64`)
  - `XChaCha20-Poly1305 (1k ops)`: `1.284 ms`
- `bytemorph_bench 50`:
  - `PE32+ x86-64 (4KB .text)`: `103.11 ms` (`2.0623 ms/iter`, `115200 insns`)
  - `ELF64 x86-64 (4KB .text)`: `97.22 ms` (`1.9444 ms/iter`, `102850 insns`)

## Licença

Distribuído sob a licença **Apache-2.0**. Consulte [LICENSE](LICENSE).
Compatível com LIEF (Apache-2.0), Zydis (MIT), Capstone (BSD-3-Clause), AsmJit (Zlib), Monocypher (CC0/BSD-2-Clause) e GoogleTest (BSD-3-Clause).
