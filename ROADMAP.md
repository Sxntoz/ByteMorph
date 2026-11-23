# Roadmap do ByteMorph

## Implementado (v0.1.0 – v0.4.0)

- [x] **v0.1:** Fundação multiplataforma, parsers PE32+/ELF64, disassembler x86-64, IR e CLI inicial.
- [x] **v0.2:** Mach-O 64-bit e Fat/Universal, ARM64 (Capstone), `.pdata`/`.eh_frame_hdr`/`LC_FUNCTION_STARTS`, CFG 2.0, fuzz targets e benchmark.
- [x] **v0.3:** Engine de ofuscação sobre IR, VM baseada em registradores (`.bvm`), tradutor IR → Bytecode, protótipo AsmJit e CLI v0.3.
- [x] **v0.4:** Reescritor modular PE32+ x64 (`PeRewriter`), virtualização seletiva com runtime nativo PIC x86-64 (`.bmrt`), criptografia autenticada XChaCha20-Poly1305 + BLAKE2b-256 (Monocypher) em `.bmvm` (`BMP4` v1), perfis `fast`/`balanced`/`maximum`, CLI `protect`/`verify`/`protection-info`/`benchmark-protection` e validação com executável real de laboratório.

## Planejado (v0.5+)

- [ ] Reescrita e virtualização seletiva para **ELF64** (Linux x64/ARM64) e **Mach-O 64-bit** (macOS, respeitando code signing).
- [ ] Suporte a chamadas externas (IAT/PLT) e exceções/SEH dentro de funções virtualizadas.
- [ ] Descriptografia lazy em runtime com chave derivada por sessão/hardware autorizado.
- [ ] Interface gráfica (GUI) integrada via `IProtectionObserver`.
