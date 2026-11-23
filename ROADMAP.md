# Roadmap do ByteMorph

## Implementado (v0.1.0 – v0.3.0)

- [x] **v0.1:** Fundação multiplataforma, parsers PE32+ e ELF64 (LIEF), disassembler x86-64 (Zydis), IR própria, CLI inicial e `bytemorph-verify` (Rust).
- [x] **v0.2:** Mach-O 64-bit e Fat/Universal, disassembler/lifter ARM64 (Capstone), `.pdata`/`.eh_frame_hdr`/`LC_FUNCTION_STARTS`, CFG 2.0, `functions`/`cfg`/`inspect --format json`, fuzz targets e benchmark.
- [x] **v0.3:** Engine de ofuscação sobre IR (substituição semântica, MBA, predicados opacos), VM própria baseada em registradores (`.bvm`), tradutor IR → Bytecode, diversificação por `build_seed`, interpretador de referência da IR, protótipo AsmJit x86-64 e comandos CLI v0.3.

## Planejado (v0.4+)

- [ ] Reescrita e empacotamento seguro de binários PE/ELF/Mach-O (virtualização seletiva de funções).
- [ ] Emissor nativo de handlers da VM para x86-64 (AsmJit) e ARM64.
- [ ] Proteção de strings, constantes e recursos.
- [ ] Verificação criptográfica de integridade em runtime.
- [ ] Interface gráfica (GUI) integrada via `IProtectionObserver`.
