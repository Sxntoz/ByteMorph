# Changelog

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
