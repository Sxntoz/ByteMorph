# ByteMorph

**ByteMorph** é um framework open source, modular e multiplataforma de análise binária, ofuscação de IR, virtualização de código e proteção de binários em **C++20** e **Rust**.

> **Status atual (v0.6.0):**  
> - **Análise estática e IR/VM:** multiplataforma (PE32+, ELF64, Mach-O 64-bit / Fat Universal; x86-64 e ARM64).  
> - **Proteção e reescrita de binários (`protect` / `verify` / `compatibility`):** funcional para **Windows PE32+ x86-64**, **Linux ELF64 x86-64 e ARM64/AArch64** (`ET_EXEC` / PIE `ET_DYN`) e **macOS Mach-O 64-bit** (x86-64 e ARM64, com re-assinatura ad-hoc via `/usr/bin/codesign` no macOS).

## Recursos da v0.6

- **Stack Frames e Memória na VM (`Load`/`Store`):**
  - Suporte a `vm.load` e `vm.store` em **8, 16, 32 e 64 bits** com endereçamento `base + deslocamento` no interpretador IR, `VmInterpreter` e nos emissores nativos PIC x86-64 (`1360B` frame) e ARM64 (`1376B` frame).
  - Preservação de alinhamento de pilha conforme Win64, System V AMD64 e AAPCS64, detecção de acessos inválidos e limites configuráveis (`memory_slots`, `max_steps`, `max_call_depth`).
- **ELF64 ARM64 (`ElfRewriter`):** proteção real de ELF64 AArch64 com runtime nativo PIC, preservação de PIE/ASLR/DEP e segmentos `PT_LOAD` W^X (`.bmrt`/`.bmvm`).
- **Controle de Fluxo Avançado:** chamadas indiretas com alvos autorizados (`authorized_call_targets`), jump tables validadas (`jump_table_targets`), loops aninhados, múltiplos pontos de retorno e recursão limitada.
- **CLI v0.6:** `compatibility <bin> --format json`, `protect --functions auto` e `analyze --functions`.
- **Criptografia Autenticada e Integridade (Monocypher 4.0.2):** **XChaCha20-Poly1305 AEAD** + **BLAKE2b-256** (`BMP4` v1).

## Compilação (Windows, Linux e macOS)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel 2
ctest --test-dir build -C Release --output-on-failure
cargo test --workspace
```

## Uso da CLI (v0.6)

```bash
bytemorph compatibility input_bin --format json
bytemorph protect input_bin --output protected_bin --profile balanced --functions auto
bytemorph analyze input_bin --functions
bytemorph verify protected_bin
bytemorph protection-info protected_bin
bytemorph benchmark-protection
```

## Benchmarks Reproduzíveis (Windows x64 Release)

- `bytemorph benchmark-protection`:
  - `Native Execution (10k iters)`: `0.018 ms`
  - `VM Interpreter (10k iters)`: `2.571 ms`
  - `VM Stack Load/Store (10k iters)`: `2.775 ms`
  - `External Call Bridge (10k)`: `2.590 ms`
  - `PIC Runtime Emission (avg)`: `0.012 ms` (`x86-64=1388B`, `ARM64=1348B`)
  - `VM Working Set RAM (per ctx)`: `33024 bytes` (`native frame=1360B x64 / 1376B ARM64`)
  - `XChaCha20-Poly1305 (1k ops)`: `1.284 ms`
- `bytemorph_bench 50`:
  - `PE32+ x86-64 (4KB .text)`: `103.11 ms` (`2.0623 ms/iter`, `115200 insns`)
  - `ELF64 x86-64 (4KB .text)`: `97.22 ms` (`1.9444 ms/iter`, `102850 insns`)

## Licença

Distribuído sob a licença **Apache-2.0**. Consulte [LICENSE](LICENSE).
Compatível com LIEF (Apache-2.0), Zydis (MIT), Capstone (BSD-3-Clause), AsmJit (Zlib), Monocypher (CC0/BSD-2-Clause) e GoogleTest (BSD-3-Clause).
