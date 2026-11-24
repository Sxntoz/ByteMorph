# ByteMorph

**ByteMorph** é um framework open source, modular e multiplataforma de análise binária, ofuscação de IR, virtualização de código e proteção de binários em **C++20** e **Rust**.

> **Status atual (v0.8.0):**  
> - **Análise estática e IR/VM:** multiplataforma (PE32+, ELF64, Mach-O 64-bit / Fat Universal; x86-64 e ARM64).  
> - **Proteção e reescrita de binários (`protect` / `verify` / `compatibility`):**
>   - **Validado com execução nativa:** Windows PE32+ x86-64, Linux ELF64 x86-64 e ARM64/AArch64, macOS Mach-O 64-bit ARM64 (e re-assinatura ad-hoc via `/usr/bin/codesign`).
>   - **Cross-protection / verificação estrutural e AEAD (experimental para execução nativa):** Windows PE32+ ARM64 (`0xAA64`, sem runner Windows ARM64 no CI) e Mach-O Fat/Universal multi-slice.

## Recursos da v0.8

- **Seleção Inteligente de Funções (`evaluate_function_eligibility`):**
  - Detecção determinística de thunks IAT/PLT/GOT, jump stubs, trampolins ARM64 `ADRP+BR`, padding/dados misturados, sobreposição de endereços, limites sem retorno, operandos RIP-relative não resolvidos e chamadas indiretas não autorizadas.
  - Classificação por categoria (`eligible`, `iat_plt_thunk`, `crt_entrypoint`, `rip_relative_or_unresolved_mem`, `overlap`, `indirect_control_flow`, etc.), justificativa e estimativa de custo (`estimated_overhead_pct`, `estimated_runtime_bytes`).
- **Otimização da VM (`VmInterpreter`):**
  - Eliminação da alocação/zeragem de 32 KB no heap quando o programa não utiliza `Load`/`Store` e manutenção de `zf`/`sf` em registradores locais.
  - Redução de **~75–84%** no tempo do interpretador em workloads aritméticos e de ponte externa em relação à v0.7.0.
- **IR e Lifters Expandidos:**
  - Suporte em `X86_64Lifter` (`not`, `xchg`) e `AArch64Lifter` (`mvn`, `uxtb`/`uxth`/`uxtw`, `movn`, `negs`, `mneg`), rejeitando instruções desconhecidas como `IrOpcode::Unknown` sem conversão silenciosa para `Nop`.
- **CLI v0.8:**
  - `compatibility <bin> --detailed`
  - `analyze <bin> --eligibility-report report.json`
  - `benchmark-protection --detailed --compare-baseline`
  - `protection-info <bin> --format json`

## Compilação (Windows, Linux e macOS)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel 2
ctest --test-dir build -C Release --output-on-failure
cargo test --workspace
```

## Uso da CLI (v0.8)

```bash
bytemorph compatibility input_bin --detailed --format json
bytemorph analyze input_bin --eligibility-report report.json
bytemorph protect input_bin --output protected_bin --profile balanced --functions all-eligible --allow-ext-calls
bytemorph verify protected_bin
bytemorph protection-info protected_bin --format json
bytemorph benchmark-protection --detailed --compare-baseline
```

## Benchmarks Reproduzíveis (Windows x64 Release)

- `bytemorph benchmark-protection --detailed --compare-baseline`:
  - `Native Execution (10k iters)`: `0.017 ms`
  - `VM Interpreter (10k iters)`: `0.734 ms` (multi-sample normalized `0.463 ms`, `-84.5%` vs v0.7 `2.987 ms`)
  - `External Call Bridge (10k)`: `0.516 ms` (multi-sample normalized `0.412 ms`, `-82.9%` vs v0.7 `2.405 ms`)
  - `VM Stack Load/Store (10k iters)`: `5.016 ms` (2k median `0.662 ms`, p95 `0.992 ms`, `3,021,148 execs/s`)
  - `Loop/Branch (2k sample)`: median `0.159 ms`, p95 `0.278 ms`, `12,562,814 execs/s`
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
