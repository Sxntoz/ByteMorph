# ByteMorph

**ByteMorph** é um framework open source, modular e multiplataforma de análise binária, ofuscação de IR, virtualização de código e proteção de binários em **C++20** e **Rust**.

> **Status atual (v0.14.0):**  
> - **Análise estática e IR/VM:** multiplataforma (PE32+, ELF64, Mach-O 64-bit / Fat Universal; x86-64 e ARM64).  
> - **Proteção e reescrita de binários (`protect` / `verify` / `compatibility` / `test-equivalence` / `report` / `optimize-ir`):**
>   - **Validado com execução nativa e equivalência:** Windows PE32+ x86-64 (aplicações C11/C++20 com 130+ funções, DLLs com `LoadLibraryA`, SDK `.bmprot`, multithreading, alocação dinâmica, structs/globais, `XChaCha20-Poly1305` eager e **Native Lazy PIC**, e SIMD/FP), Linux ELF64 x86-64 e ARM64/AArch64, macOS Mach-O 64-bit ARM64 (e re-assinatura ad-hoc via `/usr/bin/codesign`).
>   - **Cross-protection / verificação estrutural e AEAD (experimental para execução nativa):** Windows PE32+ ARM64 (`0xAA64`, sem runner nativo Windows ARM64 público no CI) e Mach-O Fat/Universal multi-slice.

## Recursos da v0.14

- **Native Lazy VM Runtime (`.bmrt` PIC x86-64 & ARM64):** execução lazy por bloco básico diretamente no runtime nativo PIC (com tabela de descritores por função, chave `CryptoAead::derive_block_key`, blob `BMBC` v2, bitmap de cache na stack, *fast-path* zero-crypto dentro de loops, wipe seguro ao sair e sentinela `0xDEADAEADDEADAEAD` em adulteração).
- **Lazy VM Performance 2.0:** `CryptoAead::open_into` zero-copy, `LazyBytecodeEngine` sem alocações heap em blocos <=4KB + `std::lower_bound`, e `VmBytecodeCache::get_shared`/`put_shared` sem cópia de vetores em cache hit.
- **Call Bridge 2.0 & CLI v0.14:** autorização de alvos em `.didat`/`__la_symbol_ptr`/`.plt*`, `protection-info --blocks --cache`, `benchmark-protection --native-lazy`, e `"native_lazy_runtime"` em `report --format json`.

## Recursos da v0.13

- **Lazy Bytecode Decryption & Derivação por Bloco:** divisão de programas BVM em blocos básicos autenticados individualmente (`XChaCha20-Poly1305` + `BMLB` v1), com subchaves derivadas por `(fn_index, block_id)` via `BLAKE2b-256` keyed (`CryptoAead::derive_block_key`), nonces exclusivos e AAD vinculada ([docs/LAZY_CACHE.md](docs/LAZY_CACHE.md)).
- **Bytecode Cache 2.0 (`VmBytecodeCache`):** cache LRU thread-safe com limites configuráveis (`max_bytes`/`max_entries`), isolamento por `context_id`, contabilização de hits/misses/evictions e limpeza `volatile` ao despejar/invalidar.
- **Dynamic Linking Expandido:** parsing de **Delayed Imports** e **ordinais `#N`** no `PeParser`, relocations `JUMP_SLOT`/`GLOB_DAT` no `ElfParser`, e binding addresses no `MachORewriter`/`MachOParser`.
- **CLI v0.13:** `--bytecode-mode <eager|lazy>`, `protection-info --blocks`, `benchmark-protection --lazy-vs-eager` e `report --format json` com contagem de blocos autenticados e versão `BMP4 v3`.

## Recursos da v0.12

- **VM Performance 4.0:** pré-decodificação `PreparedBvmProgram` com cache `thread_local`, sentinela de fim de fluxo, dispatch *threaded* (GCC/Clang) / jump-table (MSVC) e limpeza seletiva por intervalo sujo no `tls_memory_pool` (**-29.9%** no interpretador `0.760 ms -> 0.533 ms` e **-69.7%** em `Load`/`Store` `2.393 ms -> 0.724 ms`).
- **IR Optimizer 2.0:** pipeline modular (`IrOptimizer` em [docs/IR_OPTIMIZER.md](docs/IR_OPTIMIZER.md)) com *constant folding/propagation*, *copy propagation*, simplificação algébrica, eliminação local de redundância, simplificação de branches/CFG, análise de *liveness* / DCE e coalescência de `VirtualReg`.
- **Native Runtime 3.0:** zeragem rápida `rep stosq` em x86-64 (preservando `rcx`), `stp xzr, xzr` em ARM64 e stack guard probing de 4KB em ARM64.
- **SDK C/C++ & CMake:** API versionada em [docs/SDK.md](docs/SDK.md) (`<bytemorph/protect.hpp>`, `BYTEMORPH_PROTECT_BEGIN` / `BYTEMORPH_PROTECT_END` / `BYTEMORPH_PROTECT_FUNC` e `bytemorph_protect_target()` no CMake) com descoberta automática pós-compilação e suporte a patching de seções `.bmprot`.
- **Compatibilidade Avançada & CLI v0.12:** proteção e execução validada de DLL/SO/DYLIB (`lab_shared_lib`), auditoria criptográfica `BMP4` v2, `optimize-ir --level 0..3`, `protect` com saída padrão e `--functions all-eligible`, e `benchmark-protection --compare-baseline` (`v0.11 -> v0.12`).

## Recursos da v0.11

- **Criptografia e Integridade 2.0:** `CryptoAead::secure_wipe` zerando chaves/buffers sensíveis, validação de unicidade de nonces e índices em `BMP4` v2, e vetores conhecidos RFC 7693 / `XChaCha20-Poly1305`.
- **SIMD e Ponto Flutuante 2.0:** conversões `int ↔ float` e `f32 ↔ f64` (`cvtsi2ss`/`cvtsi2sd`/`cvttss2si`/`cvttsd2si`/`cvtss2sd`/`cvtsd2ss`, `scvtf`/`ucvtf`/`fcvtzs`/`fcvtzu`/`fcvt`), movimentação `GPR ↔ XMM/SIMD`, operações vetoriais (`paddd`/`paddq`/`psubd`/`psubq`, `andps`/`orps`/`add.4s`/`sub.4s`/`and.16b`/`orr.16b`) e preservação de `MXCSR`.
- **Laboratório de Aplicações Reais & Equivalência:** alvos `lab_c_app` (C11 + `lab_c_lib`) e `lab_cpp_app` (C++20, 120+ funções, `std::thread`, `std::vector`, SIMD e `try/catch` EH) validados via `test-equivalence` (código de saída, stdout e arquivo).
- **Exception & Unwind 2.0 + Smart Eligibility 5.0:** inspeção `.pdata`/`.xdata`, `.eh_frame`, `__unwind_info`, rejeição de funclets `.pdata` (`crt_or_eh_funclet`), métricas (`is_recursive`, `has_side_effects`, `simd_ops_count`, `decision_explanation`) e orçamento `--max-overhead`.
- **VM Performance 3.0 & CLI v0.11:** `tls_call_stack`, hot-path dispatch PIC, `test-equivalence`, `report --output`, `benchmark-protection --full`.

## Recursos da v0.10

- **Bytecode Criptografado em Runtime (`--encrypt-bytecode` / `--profile maximum`):**
  - Selagem `XChaCha20-Poly1305` (Monocypher 4.0.2) por função com nonces exclusivos (`BMBC` v2) e metadados `BMP4` v2.
  - Verificação da tag Poly1305 em tempo constante e descriptografia diretamente nos runtimes nativos PIC x86-64 e ARM64 antes da execução, com rejeição segura em adulterações (`0xDEADAEADDEADAEAD`) e limpeza do buffer em pilha ao sair.
  - Consulte [docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md) para a distinção explícita entre integridade, autenticidade e confidencialidade.
- **SIMD e Ponto Flutuante (IEEE 754):**
  - Suporte incremental para `movdqa`/`movdqu`/`movaps`/`movups`/`movss`/`movsd`/`addss`/`addsd`/`subss`/`subsd`/`mulss`/`mulsd`/`divss`/`divsd`/`ucomiss`/`ucomisd`/`xorps` (x86-64) e `fmov`/`fadd`/`fsub`/`fmul`/`fdiv`/`fcmp` (ARM64), preservando `NaN`, `+Inf`/`-Inf`, `-0.0` e registradores callee-saved (`xmm6..xmm15`, `d8..d15`).
  - Consulte [docs/VM_ARCHITECTURE.md](docs/VM_ARCHITECTURE.md).
- **Exceções, Unwind & Smart Eligibility 4.0:**
  - Inspeção de `.pdata`/`.xdata` (`UNW_FLAG_EHANDLER`/`UHANDLER`) no PE e APIs de throw/unwind (`__cxa_throw`, `_Unwind_Resume`, `CxxThrow`) no ELF/Mach-O, rejeitando funções incompatíveis com diagnóstico claro (`exception_unwind_incompatible`).
- **CLI v0.10:**
  - `protect --profile maximum --encrypt-bytecode`
  - `analyze <bin> --simd` e `analyze <bin> --exceptions`
  - `verify <bin> --deep` e `benchmark-protection --crypto`

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

## Uso da CLI (v0.10)

```bash
bytemorph compatibility input_bin --detailed --format json
bytemorph analyze input_bin --simd
bytemorph analyze input_bin --exceptions
bytemorph analyze input_bin --memory-references
bytemorph protect input_bin --output protected_bin --profile maximum --encrypt-bytecode --functions all-eligible
bytemorph verify protected_bin --deep
bytemorph protection-info protected_bin --format json
bytemorph benchmark-protection --detailed --memory --crypto --compare-baseline
```

## Benchmarks Reproduzíveis (Windows x64 Release)

- `bytemorph benchmark-protection --detailed --memory --crypto --compare-baseline`:
  - `Native Execution (10k iters)`: `0.021 ms`
  - `VM Interpreter (10k iters)`: `1.573 ms` (multi-sample normalized `1.247 ms`, `-58.3%` vs v0.7 `2.987 ms`)
  - `Memory Load/Store (Pool, 2k/sample)`: median `1.338 ms` vs `Heap` `2.415 ms` (**+44.6%** speedup, `1,494,768 execs/s`)
  - `SIMD/FP64 (2k/sample)`: median `0.248 ms`, `8,064,516 execs/s`
  - `External Call Bridge (2k/sample)`: median `0.210 ms`, `9,514,748 execs/s`
  - `AEAD Seal+Open (256B, 1k)`: `6.517 ms` (`XChaCha20-Poly1305 1k ops: 3.823 ms`)
  - Shared Runtime Scaling: 2 funcs (`x64=2100B`, `ARM64=1972B`), 5 funcs (`x64=2444B`, `ARM64=2308B`), 10 funcs (`x64=3028B`, `ARM64=2868B`), 20 funcs (`x64=4188B`, `ARM64=3988B`)
  - `PIC Runtime Emission (avg)`: `0.049 ms` (`x86-64=1996B`, `ARM64=1860B`)
  - `VM Working Set RAM (per ctx)`: `33024 bytes` (`native frame=1360B x64 / 1376B ARM64`)
  - `XChaCha20-Poly1305 (1k ops)`: `1.897 ms`
- `bytemorph_bench 50`:
  - `PE32+ x86-64 (4KB .text)`: `103.11 ms` (`2.0623 ms/iter`, `115200 insns`)
  - `ELF64 x86-64 (4KB .text)`: `97.22 ms` (`1.9444 ms/iter`, `102850 insns`)

## Licença

Distribuído sob a licença **Apache-2.0**. Consulte [LICENSE](LICENSE).
Compatível com LIEF (Apache-2.0), Zydis (MIT), Capstone (BSD-3-Clause), AsmJit (Zlib), Monocypher (CC0/BSD-2-Clause) e GoogleTest (BSD-3-Clause).
