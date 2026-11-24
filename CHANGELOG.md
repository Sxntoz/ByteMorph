# Changelog

## [0.13.0] - 2026-11-24

### Adicionado
- **Lazy Bytecode Decryption & Derivação por Bloco:**
  - `CryptoAead::derive_block_key` (`BLAKE2b-256` keyed) e `CryptoAead::generate_block_nonce` com separação de domínios (`bm.lazy.block.v1`, `BM_BLK_KDF_v1`, `BM_BLK_NONCE_v1`).
  - `LazyBytecodeEngine` (`seal_function`, `open_block`, `verify_block_aead`, `verify_all_blocks`, `execute_lazy`) com AAD `BMLB` v1 vinculada a `(fn_index, block_id, start_pc, insn_count, plain_bytes)` e formato `BMP4` v3 retrocompatível com v1/v2.
- **Bytecode Cache 2.0:**
  - `VmInterpreter::split_into_basic_blocks`, `VmInterpreter::execute_lazy` e `VmBytecodeCache` (LRU thread-safe, `max_bytes`/`max_entries`, isolamento por `context_id`, métricas de hits/misses/evictions e wipe `volatile` ao despejar/invalidar).
- **Dynamic Linking Compatibility:**
  - Suporte a **Delayed Imports** e **imports por ordinal (`#N`)** no `PeParser`, relocations `JUMP_SLOT`/`GLOB_DAT` no `ElfParser`, e `binding_info()->address()` no `MachOParser`.
- **CLI v0.13 & Documentação:**
  - `--bytecode-mode <eager|lazy>`, `protection-info --blocks`, `benchmark-protection --lazy-vs-eager`, `report --format json` com `encrypted_blocks_count`/`blocks_verified_count`, e [docs/LAZY_CACHE.md](docs/LAZY_CACHE.md).
- **Testes:** 5 novos testes `ProtectionV013Test` (93 testes C++ + 3 testes Rust aprovados).

## [0.12.0] - 2026-11-24

### Adicionado
- **VM Performance 4.0:** `PreparedBvmProgram` (`VmInterpreter::prepare` / `execute_prepared`) com cache `thread_local`, sentinela `Halt` de fim de fluxo, dispatch *threaded* (GCC/Clang) e limpeza seletiva por intervalo sujo no `tls_memory_pool` (**-29.9%** no interpretador `0.760 -> 0.533 ms` e **-69.7%** em `Load`/`Store` `2.393 -> 0.724 ms`).
- **IR Optimizer 2.0:** `core/ir/ir_optimizer.hpp` com passes modulares (constant folding/propagation, copy propagation, simplificação algébrica, eliminação de redundância local, simplificação de branches/CFG, liveness + DCE, coalescência de `VirtualReg`), integrado ao `prepare_target_functions`.
- **Native Runtime 3.0:** zeragem `rep stosq` em x86-64, `stp xzr, xzr` em ARM64 e stack probing 4KB em ARM64; `PeRewriter::protect_file` estendido para aplicar trampolins em qualquer seção executável (incluindo `.bmprot`).
- **SDK C/C++ & CMake:** `sdk/include/bytemorph/protect.h`, `protect.hpp`, `sdk/cmake/ByteMorphSDK.cmake` (`ByteMorph::SDK`, `bytemorph_protect_target`) e descoberta automática de marcadores `.bmprot` / `__bm_sdk_begin_marker`..`__bm_sdk_end_marker`.
- **CLI v0.12 & Documentação:** `optimize-ir <in.ir> [--level 0..3]`, `protect` com saída padrão, `benchmark-protection --compare-baseline` (`v0.11 -> v0.12`), [docs/SDK.md](docs/SDK.md) e [docs/IR_OPTIMIZER.md](docs/IR_OPTIMIZER.md).
- **Testes:** 6 novos testes `ProtectionV012Test` + alvos `lab_sdk_app` e `lab_shared_lib` (88 testes C++ + 3 testes Rust aprovados).

## [0.11.0] - 2026-11-24

### Adicionado
- **Criptografia e Integridade 2.0:**
  - `CryptoAead::secure_wipe` (`crypto_wipe` do Monocypher) aplicado em chaves derivadas (`rt_key`), contextos `BLAKE2b` e buffers de bytecode em texto plano após selagem nos emissores PIC x86-64/ARM64.
  - Validação estrita em `deserialize_metadata` para `BMP4` v2: rejeição de nonces duplicados, índices `fn_index` duplicados ou fora dos limites e `plaintext_size == 0`.
  - Testes com vetores conhecidos RFC 7693 (`BLAKE2b-256`) e KAT/tamper `XChaCha20-Poly1305`.
- **SIMD e Ponto Flutuante 2.0:**
  - Novos opcodes `FCvt`, `VPAdd`, `VPSub` no IR e `VCvtI2F` (`0x2B`)..`VOr` (`0x35`) no `.bvm` (`MaxOpcode = 0x36`), cobrindo `cvtsi2ss`/`cvtsi2sd`/`cvttss2si`/`cvttsd2si`/`cvtss2sd`/`cvtsd2ss`, `movd`, `paddd`/`paddq`/`psubd`/`psubq`, `andps`/`andpd`/`pand`/`orps`/`orpd`/`por` (x86-64) e `scvtf`/`ucvtf`/`fcvtzs`/`fcvtzu`/`fcvt`, `fmov` GPR↔FP, `add`/`sub` `.4s`/`.2d`, `and`/`orr`/`eor` `.16b` (ARM64).
  - Preservação de `MXCSR` (`stmxcsr`/`ldmxcsr`) no runtime PIC x86-64 quando `has_simd` está ativo.
- **Laboratório de Aplicações Reais & Equivalência:**
  - Adicionados `lab_c_lib` + `lab_c_app` (C11, structs, arrays, `calloc`/`free`, globais e saída em arquivo) e `lab_cpp_app` (C++20, 120+ funções, `std::vector`, `std::thread`, SIMD/FP e `try/catch` EH).
- **Exception & Unwind Compatibility 2.0 + Smart Eligibility 5.0:**
  - Inspeção de `.eh_frame` (ELF), `__unwind_info` (Mach-O) e `.pdata`/`.xdata` (PE), além de métricas `is_recursive`, `has_side_effects`, `external_calls_count`, `global_refs_count`, `simd_ops_count`, `decision_explanation` e seleção por orçamento (`--max-overhead`).
- **VM Performance 3.0 & CLI v0.11:**
  - `tls_call_stack` no `VmInterpreter` e reordenação *hot-path* no dispatch PIC nativo.
  - Novos comandos: `test-equivalence`, `report`, `benchmark-protection --full` e `--max-overhead`.
- **Testes:** 7 novos testes `ProtectionV011Test` (82 testes C++ + 3 testes Rust).

## [0.10.0] - 2026-11-24

### Adicionado
- **Bytecode Criptografado em Runtime (`--encrypt-bytecode` / `--profile maximum`):**
  - Blobs `BMBC` v2 autenticados por função com `XChaCha20-Poly1305` (nonces exclusivos) e metadados `BMP4` v2 (`ProtectionMetadata::encrypted_functions`).
  - Verificador/descriptografador PIC `XChaCha20-Poly1305` nativo em x86-64 e ARM64 antes da interpretação, rejeitando adulterações (`0xDEADAEADDEADAEAD`) e zerando buffers em pilha na saída.
- **SIMD e Ponto Flutuante (IEEE 754):**
  - Opcodes `VMov`, `FAdd`, `FSub`, `FMul`, `FDiv`, `FCmp` no IR, `VMovReg..VXor` no `.bvm` (`kOpcodeTableSize = 64`), suporte a SSE2 (`movdqa`/`movdqu`/`movss`/`movsd`/`addss`/`addsd`/`subss`/`subsd`/`mulss`/`mulsd`/`divss`/`divsd`/`ucomiss`/`ucomisd`/`xorps`) e ARM64 FP (`fmov`/`fadd`/`fsub`/`fmul`/`fdiv`/`fcmp`), preservando `NaN`/`Inf`/`-0.0` e registradores callee-saved.
- **Exceções/Unwind & Smart Eligibility 4.0:**
  - `ProtectionEngine::analyze_exceptions` inspeciona `.pdata`/`.xdata` (PE), `.eh_frame` (ELF) e `__unwind_info` (Mach-O), rejeitando funções com handlers SEH/C++ EH ativos (`exception_unwind_incompatible`).
- **CLI v0.10 & Documentação:**
  - `--encrypt-bytecode`, `analyze --simd`, `analyze --exceptions`, `verify --deep`, `benchmark-protection --crypto`, [docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md) e [docs/VM_ARCHITECTURE.md](docs/VM_ARCHITECTURE.md).
- **Testes:** 10 novos testes `ProtectionV010Test` (75 testes C++ + 3 testes Rust aprovados).

## [0.9.0] - 2026-11-24

### Adicionado
- **Memória Global RIP/PC-Relative & ASLR (`LeaGlobal` → `VmOpcode::LeaPic`):**
  - `X86_64Lifter` agora resolve `[rip + disp32]` e endereços absolutos formatados pelo Zydis para `IrOpcode::LeaGlobal`; `AArch64Lifter` funde pares `ADRP+ADD` e `ADRP+LDR` e suporta `ADR`.
  - `VmOpcode::LeaPic` (`0x1A`) calcula em runtime `l_entry + (target_va - stub_base_va)` nos emissores nativos PIC x86-64 e ARM64 e `pic_base_va + imm` no `VmInterpreter`, preservando ASLR/PIE.
- **Condicionais Avançadas & Flags `CF`/`OF`:**
  - `VmOpcode::SelectCc` (`0x1B`), `VmOpcode::SetCc` (`0x1C`), `IrOpcode::Adc` e `IrOpcode::Sbb`, cobrindo `cmovcc`, `setcc`, `adc`, `sbb` (x86-64) e `csel`/`csinc`/`csinv`/`csneg`/`cset`/`csetm` (ARM64).
  - `IrInterpreter`, `VmInterpreter` e runtimes nativos x86-64/ARM64 agora propagam `ZF`, `SF`, `CF` e `OF` para comparações com e sem sinal.
- **VM Memory Pool (`thread_local`):**
  - Buffer reutilizável por thread em `VmInterpreter::execute` (`use_memory_pool = true`) com zeragem antes de cada execução e contagem em `VmExecState::allocations_count`, reduzindo `Memory Load/Store (10k)` de `5.016 ms` (v0.8) para `3.033 ms` (**-39.5%**) e alcançando **43.1%** de ganho sobre alocação heap (`0.607 ms` vs `1.066 ms`).
- **Smart Eligibility 3.0 & CLI v0.9:**
  - `evaluate_function_eligibility` valida referências `LeaGlobal` contra seções mapeadas do binário.
  - Novos flags CLI: `analyze --memory-references` e `benchmark-protection --memory`.
- **Testes:** 11 novos testes `ProtectionV09Test` (65 testes C++ + 3 testes Rust aprovados).

## [0.8.0] - 2026-11-23

### Adicionado
- **Seleção Inteligente de Funções:** `evaluate_function_eligibility` compartilhada entre `check_compatibility` e `prepare_target_functions`, rejeitando thunks IAT/PLT/GOT, jump stubs, trampolins `ADRP+BR`, regiões de padding/dados, funções sobrepostas, fluxos sem retorno, operandos RIP-relative não resolvidos e chamadas indiretas não autorizadas, com categoria e estimativa de custo.
- **Otimização da VM:** alocação lazy de memória em `VmInterpreter::execute` e flags `zf`/`sf` em registradores locais, reduzindo o tempo do interpretador de `2.987 ms` para `0.463 ms` (normalizado multi-amostra) / `0.734 ms` (-75% a -84%).
- **IR e Lifters:** suporte a `not`/`xchg` (`X86_64Lifter`) e `mvn`/`uxtb`/`uxth`/`uxtw`/`movn`/`mneg`/`negs` (`AArch64Lifter`), preservando `IrOpcode::Unknown` para instruções desconhecidas.
- **CLI v0.8 & Benchmarks:** `compatibility --detailed`, `analyze --eligibility-report <path>`, `protection-info --format json` e `benchmark-protection --compare-baseline` (mediana, p95, p99 e throughput).
- **Testes:** 5 novos testes `ProtectionV08Test` (54 testes C++ + 3 testes Rust aprovados).

## [0.7.0] - 2026-11-23

### Adicionado
- **Proteção Multifuncional com Runtime Compartilhado:** `prepare_target_functions`, `emit_shared_pic_x64_vm_runtime` e `emit_shared_pic_arm64_vm_runtime` unificam múltiplas funções em um único runtime PIC (`.bmrt`/`__BMRT`) com stubs compactos por função, detecção de sobreposição e validação transacional antes da escrita.
- **Mach-O Fat/Universal multi-slice:** `MachORewriter` agora reescreve e verifica todas as fatias (x86-64 e ARM64) de binários Universal Mach-O com suporte a `/usr/bin/codesign`.
- **PE32+ ARM64:** `PeRewriter` agora suporta cross-protection e verificação estrutural/AEAD para binários Windows PE32+ ARM64 (`0xAA64`).
- **Otimização do Interpretador VM:** pré-validação estática (`validate_program`) fora do loop quente do `VmInterpreter::execute`.
- **CLI v0.7:** `--functions all-eligible`, `--functions <lista>`, `protection-info <bin> --functions`, `benchmark-protection --detailed` e `--no-rollback`.
- **Testes:** novos testes `ProtectionV07Test` (49 testes C++ no Windows + 3 testes Rust).

## [0.6.0] - 2026-11-23

### Adicionado
- **Stack frames e memória 8/16/32/64 bits:** `vm.load` e `vm.store` (`base + disp`) nos interpretadores IR/VM e nos emissores nativos PIC x86-64 (`1360B` frame) e ARM64 (`1376B` frame), com validação de limites e alinhamento de pilha ABI.
- **ELF64 ARM64:** proteção funcional de binários Linux AArch64 em `ElfRewriter`, preservando PIE/ASLR e segmentos `PT_LOAD` W^X, com execução nativa no CI (`ubuntu-24.04-arm`).
- **Controle de fluxo avançado:** chamadas indiretas autorizadas (`authorized_call_targets`), jump tables validadas (`jump_table_targets`), trap `vm.halt (dst=0xFF)`, `vm.div` nativo ARM64/x86-64 e suporte expandido aos lifters x86-64/AArch64 (`push`/`pop`/`leave`/`stp`/`ldp`/`madd`/`cbz`/`cbnz`/RMW).
- **CLI v0.6:** `bytemorph compatibility <in> --format json`, `bytemorph protect --functions auto` e `bytemorph analyze --functions`.
- **Testes:** 6 novos testes `ProtectionV06Test` (44 testes C++ + 3 testes Rust).

## [0.5.0] - 2026-11-23

### Adicionado
- `ElfRewriter` funcional para ELF64 x86-64 (System V AMD64 ABI, segmentos `PT_LOAD` W^X `.bmrt`/`.bmvm`, preservação de PIE).
- `MachORewriter` funcional para Mach-O 64-bit (x86-64 e ARM64/AAPCS64, segmentos `__BMRT`/`__BMVM` e integração com `/usr/bin/codesign` no macOS).
- Emissor PIC compartilhado (`native_vm_emitter`) para Win64, System V AMD64 e AArch64.
- Suporte a chamadas externas autorizadas (`VmOpcode::CallExt`) na VM e no `IrToVmTranslator`.
- Testes de integração multiplataforma para Windows PE32+, Linux ELF64 e macOS Mach-O 64-bit.

## [0.4.0] - 2026-11-23
- Reescritor PE32+ x86-64, virtualização seletiva nativa, criptografia autenticada XChaCha20-Poly1305 + BLAKE2b-256.

## [0.3.0] - 2026-11-23
- Engine de ofuscação sobre IR, VM baseada em registradores, tradutor IR → `.bvm`, protótipo AsmJit.

## [0.2.0] - 2026-11-23
- Parser Mach-O 64-bit/Fat, disassembler/lifter ARM64, descoberta avançada de funções, CFG 2.0, fuzz targets.

## [0.1.0] - 2026-11-23
- Fundação multiplataforma C++20/Rust, parsers PE32+/ELF64, disassembler x86-64 e CLI inicial.
