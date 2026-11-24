# Roadmap do ByteMorph

## Implementado (v0.1.0 – v0.8.0)

- [x] **v0.1 – v0.2:** Fundação multiplataforma, parsers PE32+/ELF64/Mach-O 64-bit & Fat, disassemblers/lifters x86-64 e ARM64, CFG 2.0, fuzz targets.
- [x] **v0.3:** Engine de ofuscação sobre IR, VM baseada em registradores (`.bvm`), tradutor IR → Bytecode, protótipo AsmJit.
- [x] **v0.4:** `PeRewriter` (PE32+ x86-64), virtualização seletiva nativa, XChaCha20-Poly1305 AEAD + BLAKE2b-256.
- [x] **v0.5:** `ElfRewriter` (ELF64 x86-64, SysV ABI), `MachORewriter` (Mach-O 64-bit x86-64 e ARM64, integração com `/usr/bin/codesign`), suporte a chamadas externas autorizadas (`vm.callext`) e validação multiplataforma em CI.
- [x] **v0.6:** Stack frames e `Load`/`Store` de 8/16/32/64 bits nos runtimes nativos, proteção **ELF64 ARM64**, chamadas indiretas autorizadas, jump tables validadas, loops aninhados/recursão e CLI `compatibility` / `--functions auto`.
- [x] **v0.7:** Proteção multifuncional com runtime VM compartilhado (`--functions all-eligible` / lista de RVAs ou nomes), validação transacional e rollback atômico, chamadas entre funções protegidas/externas, **Mach-O Fat/Universal** multi-slice, **PE32+ ARM64** (cross-protection) e pré-validação no `VmInterpreter`.
- [x] **v0.8:** Seleção inteligente (`evaluate_function_eligibility` filtrando thunks IAT/PLT/GOT, jump stubs, padding, sobreposições e operandos RIP-relative), otimização da VM (-75–84% em interpretador/ponte externa), lifters expandidos (`not`/`xchg`/`mvn`/`uxtb`/`uxth`/`uxtw`/`movn`/`mneg`), suíte de benchmarks multi-amostra (`--compare-baseline`) e relatórios JSON (`--eligibility-report`, `protection-info --format json`).

## Planejado (v0.9+)

- [ ] Execução nativa validada em hardware Windows ARM64 e expansão de IAT/PLT/GOT dinâmicos.
- [ ] Descriptografia lazy em runtime e verificação contínua de integridade.
- [ ] Interface gráfica (GUI) integrada via `IProtectionObserver`.
