# ByteMorph

**ByteMorph** é um framework open source, modular e multiplataforma de análise binária, ofuscação de IR, virtualização de código e proteção de binários em **C++20** e **Rust**.

> **Status atual (v0.9.0):**  
> - **Análise estática e IR/VM:** multiplataforma (PE32+, ELF64, Mach-O 64-bit / Fat Universal; x86-64 e ARM64).  
> - **Proteção e reescrita de binários (`protect` / `verify` / `compatibility`):**
>   - **Validado com execução nativa:** Windows PE32+ x86-64 (incluindo globais RIP-relative/ASLR, `cmovcc`, `setcc`), Linux ELF64 x86-64 e ARM64/AArch64, macOS Mach-O 64-bit ARM64 (e re-assinatura ad-hoc via `/usr/bin/codesign`).
>   - **Cross-protection / verificação estrutural e AEAD (experimental para execução nativa):** Windows PE32+ ARM64 (`0xAA64`, compilador cruzado `MSVC Hostx64\arm64` disponível localmente, sem runner nativo Windows ARM64) e Mach-O Fat/Universal multi-slice.

## Recursos da v0.9

- **Memória Global PIC & ASLR-Safe (`LeaGlobal` → `VmOpcode::LeaPic`):**
  - Suporte a operandos RIP-relative (`[rip + disp32]`, `[0x...]`) no `X86_64Lifter` e fusão `ADRP+ADD` / `ADRP+LDR` / `ADR` no `AArch64Lifter`.
  - Resolução em runtime via `l_entry + (target_va - stub_base_va)` nos runtimes nativos PIC x86-64 e ARM64, preservando ASLR/PIE em `.rdata`, `.data`, `.rodata` e `__DATA`.
- **Condicionais Avançadas e Flags Completas (`CF` + `OF`):**
  - Novos opcodes `SelectCc` (`cmovcc`, `csel`, `csinc`, `csinv`, `csneg`), `SetCc` (`setcc`, `cset`, `csetm`), `Adc` e `Sbb` no IR, tradutor, interpretador e runtimes nativos.
  - Suporte completo a comparações com sinal (`Lt`/`Le`/`Gt`/`Ge` via `SF != OF`) e sem sinal (`Below`/`BelowEq`/`Above`/`AboveEq` via `CF`/`ZF`), além de `Sign`/`Overflow`.
- **VM Memory Pool (`thread_local`):**
  - Buffer reutilizável por thread em `VmInterpreter::execute` (`use_memory_pool = true`) com zeragem limpa antes do uso, eliminando alocações por chamada (`allocations_count = 0` após aquecimento) e mantendo isolamento total entre execuções e threads concorrentes.
  - Redução de **39.5%** no benchmark `Memory Load/Store (10k)` vs v0.8 (`5.016 ms` → `3.033 ms`) e ganho de **43.1%** sobre alocação heap (`0.607 ms` vs `1.066 ms` em 2k iters/sample).
- **Smart Eligibility 3.0 & CLI v0.9:**
  - `evaluate_function_eligibility` aceita referências `LeaGlobal` resolvidas dentro de seções mapeadas do binário e rejeita alvos fora da imagem ou operandos de memória não resolvidos.
  - Novos flags CLI: `analyze <bin> --memory-references` e `benchmark-protection --memory`.

## Compilação (Windows, Linux e macOS)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel 2
ctest --test-dir build -C Release --output-on-failure
cargo test --workspace
```

## Uso da CLI (v0.9)

```bash
bytemorph compatibility input_bin --detailed --format json
bytemorph analyze input_bin --memory-references
bytemorph analyze input_bin --eligibility-report report.json
bytemorph protect input_bin --output protected_bin --profile balanced --functions all-eligible --allow-ext-calls
bytemorph verify protected_bin
bytemorph protection-info protected_bin --format json
bytemorph benchmark-protection --detailed --memory --compare-baseline
```

## Benchmarks Reproduzíveis (Windows x64 Release)

- `bytemorph benchmark-protection --detailed --memory --compare-baseline`:
  - `Native Execution (10k iters)`: `0.018 ms`
  - `VM Interpreter (10k iters)`: `0.720 ms` (multi-sample normalized `0.623 ms`, `-79.2%` vs v0.7 `2.987 ms`)
  - `Memory Load/Store (Pool, 10k)`: `3.033 ms` (`-39.5%` vs v0.8 `5.016 ms`; 2k median `0.607 ms` vs Heap `1.066 ms`, **+43.1%** speedup, `3,297,609 execs/s`)
  - `External Call Bridge (10k)`: `0.620 ms` (multi-sample normalized `0.524 ms`, `-78.2%` vs v0.7 `2.405 ms`)
  - `Loop/Branch (2k sample)`: median `0.226 ms`, `8,837,826 execs/s`
  - Shared Runtime Scaling: 2 funcs (`x64=2092B`, `ARM64=1972B`), 5 funcs (`x64=2444B`, `ARM64=2308B`), 10 funcs (`x64=3020B`, `ARM64=2868B`), 20 funcs (`x64=4180B`, `ARM64=3988B`)
  - `PIC Runtime Emission (avg)`: `0.049 ms` (`x86-64=1996B`, `ARM64=1860B`)
  - `VM Working Set RAM (per ctx)`: `33024 bytes` (`native frame=1360B x64 / 1376B ARM64`)
  - `XChaCha20-Poly1305 (1k ops)`: `1.897 ms`
- `bytemorph_bench 50`:
  - `PE32+ x86-64 (4KB .text)`: `103.11 ms` (`2.0623 ms/iter`, `115200 insns`)
  - `ELF64 x86-64 (4KB .text)`: `97.22 ms` (`1.9444 ms/iter`, `102850 insns`)

## Licença

Distribuído sob a licença **Apache-2.0**. Consulte [LICENSE](LICENSE).
Compatível com LIEF (Apache-2.0), Zydis (MIT), Capstone (BSD-3-Clause), AsmJit (Zlib), Monocypher (CC0/BSD-2-Clause) e GoogleTest (BSD-3-Clause).
