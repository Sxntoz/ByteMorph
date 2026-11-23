# Roadmap do ByteMorph

## Implementado (v0.1.0 – v0.6.0)

- [x] **v0.1 – v0.2:** Fundação multiplataforma, parsers PE32+/ELF64/Mach-O 64-bit & Fat, disassemblers/lifters x86-64 e ARM64, CFG 2.0, fuzz targets.
- [x] **v0.3:** Engine de ofuscação sobre IR, VM baseada em registradores (`.bvm`), tradutor IR → Bytecode, protótipo AsmJit.
- [x] **v0.4:** `PeRewriter` (PE32+ x86-64), virtualização seletiva nativa, XChaCha20-Poly1305 AEAD + BLAKE2b-256.
- [x] **v0.5:** `ElfRewriter` (ELF64 x86-64, SysV ABI), `MachORewriter` (Mach-O 64-bit x86-64 e ARM64, integração com `/usr/bin/codesign`), suporte a chamadas externas autorizadas (`vm.callext`) e validação multiplataforma em CI.
- [x] **v0.6:** Stack frames e `Load`/`Store` de 8/16/32/64 bits nos runtimes nativos, proteção **ELF64 ARM64**, chamadas indiretas autorizadas, jump tables validadas, loops aninhados/recursão e CLI `compatibility` / `--functions auto`.

## Planejado (v0.7+)

- [ ] Suporte a binários Mach-O Fat/Universal multi-slice e PE32+ ARM64.
- [ ] Resolução automática de chamadas externas via IAT/PLT/GOT dentro da VM.
- [ ] Descriptografia lazy em runtime e verificação contínua de integridade.
- [ ] Interface gráfica (GUI) integrada via `IProtectionObserver`.
