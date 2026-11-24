# Roadmap do ByteMorph

## Implementado (v0.1.0 – v0.13.0)

- [x] **v0.1 – v0.2:** Fundação multiplataforma, parsers PE32+/ELF64/Mach-O 64-bit & Fat, disassemblers/lifters x86-64 e ARM64, CFG 2.0, fuzz targets.
- [x] **v0.3:** Engine de ofuscação sobre IR, VM baseada em registradores (`.bvm`), tradutor IR → Bytecode, protótipo AsmJit.
- [x] **v0.4:** `PeRewriter` (PE32+ x86-64), virtualização seletiva nativa, XChaCha20-Poly1305 AEAD + BLAKE2b-256.
- [x] **v0.5:** `ElfRewriter` (ELF64 x86-64, SysV ABI), `MachORewriter` (Mach-O 64-bit x86-64 e ARM64, integração com `/usr/bin/codesign`), suporte a chamadas externas autorizadas (`vm.callext`) e validação multiplataforma em CI.
- [x] **v0.6:** Stack frames e `Load`/`Store` de 8/16/32/64 bits nos runtimes nativos, proteção **ELF64 ARM64**, chamadas indiretas autorizadas, jump tables validadas, loops aninhados/recursão e CLI `compatibility` / `--functions auto`.
- [x] **v0.7:** Proteção multifuncional com runtime VM compartilhado (`--functions all-eligible` / lista de RVAs ou nomes), validação transacional e rollback atômico, chamadas entre funções protegidas/externas, **Mach-O Fat/Universal** multi-slice, **PE32+ ARM64** (cross-protection) e pré-validação no `VmInterpreter`.
- [x] **v0.8:** Seleção inteligente (`evaluate_function_eligibility` filtrando thunks IAT/PLT/GOT, jump stubs, padding, sobreposições e operandos RIP-relative), otimização da VM (-75–84% em interpretador/ponte externa), lifters expandidos (`not`/`xchg`/`mvn`/`uxtb`/`uxth`/`uxtw`/`movn`/`mneg`), suíte de benchmarks multi-amostra (`--compare-baseline`) e relatórios JSON (`--eligibility-report`, `protection-info --format json`).
- [x] **v0.9:** Memória global PIC/ASLR (`LeaGlobal` → `VmOpcode::LeaPic`, `ADRP+ADD`/`ADRP+LDR`), instruções condicionais avançadas (`cmovcc`/`setcc`/`adc`/`sbb`, `csel`/`csinc`/`csinv`/`csneg`/`cset`/`csetm`), flags `CF`/`OF`, **VM Memory Pool** (`thread_local`, -39.5% em `Load`/`Store`), Smart Eligibility 3.0 e CLI `--memory-references` / `--memory`.
- [x] **v0.10:** Bytecode criptografado e autenticado em runtime (`XChaCha20-Poly1305` PIC x86-64/ARM64, `BMBC` v2, `BMP4` v2, `--encrypt-bytecode`), subconjunto SIMD/FP IEEE 754 (SSE2 + ARM64 FP32/FP64), inspeção de exceções/unwind (`.pdata`/`.eh_frame`/`__unwind_info`), Smart Eligibility 4.0 e CLI `--simd` / `--exceptions` / `--deep` / `--crypto`.
- [x] **v0.11:** Criptografia 2.0 (`secure_wipe`, unicidade de nonces em `BMP4` v2, vetores KAT), SIMD/FP 2.0 (conversões `int↔float`/`f32↔f64`, `GPR↔XMM/SIMD`, `padd`/`psub`/`and`/`or` vetorial, `MXCSR`), laboratório real (`lab_c_app` + `lab_cpp_app` 130+ funções / multithread), Exception & Unwind 2.0, Smart Eligibility 5.0 (`--max-overhead`), VM Performance 3.0 (`tls_call_stack` + hot-path dispatch) e CLI `test-equivalence` / `report` / `benchmark-protection --full`.
- [x] **v0.12:** VM Performance 4.0 (`PreparedBvmProgram`, dispatch *threaded*, dirty-range `tls_memory_pool`), IR Optimizer 2.0 (`IrOptimizer`), Native Runtime 3.0 (`rep stosq` x64, `stp` + stack probe 4KB ARM64), SDK C/C++ + CMake (`BYTEMORPH_PROTECT_BEGIN`/`END`, `bytemorph_protect_target`), proteção validada de DLL/SO/DYLIB (`lab_shared_lib`) e CLI `optimize-ir`.
- [x] **v0.13:** Lazy Bytecode Decryption (`BMLB` v1 + `BMP4` v3), derivação de subchaves por bloco (`CryptoAead::derive_block_key`), **Bytecode Cache 2.0** (`VmBytecodeCache` LRU thread-safe com wipe seguro), resolução expandida de imports (Delayed/Ordinal/PLT-GOT/Mach-O) e CLI `--bytecode-mode` / `--blocks` / `--lazy-vs-eager`.

## Planejado (v0.14+)

- [ ] Execução nativa validada em hardware Windows ARM64 e expansão de IAT/PLT/GOT dinâmicos.
- [ ] Descriptografia lazy em runtime e verificação contínua de integridade.
- [ ] Interface gráfica (GUI) integrada via `IProtectionObserver`.
