# Changelog

## [0.4.0] - 2026-11-23

### Adicionado
- Reescritor modular PE32+ x86-64 (`PeRewriter`) com escrita atômica e validação estrutural pós-proteção.
- Virtualização seletiva de funções nativas com trampoline `jmp rel32` compatível com ASLR e runtime VM PIC x86-64 na seção `.bmrt` (`R-X`).
- Criptografia autenticada **XChaCha20-Poly1305 AEAD** e hashing **BLAKE2b-256** via **Monocypher 4.0.2** na seção `.bmvm` (`BMP4` v1).
- Perfis de proteção (`fast`, `balanced`, `maximum`) e comandos CLI `protect`, `verify`, `protection-info` e `benchmark-protection`.
- Teste de integração ponta a ponta executando binário real de laboratório (`lab_pe_target.exe`) antes e depois da virtualização.
- Correções de CI: upgrade do LIEF para `0.16.4`, runner `macos-latest` e `--parallel 2` para evitar OOM no Ubuntu.

## [0.3.0] - 2026-11-23
- Engine de ofuscação sobre IR, VM baseada em registradores, tradutor IR → `.bvm`, protótipo AsmJit e publicação pública no GitHub.

## [0.2.0] - 2026-11-23
- Parser Mach-O 64-bit e Fat/Universal, disassembler/lifter ARM64, descoberta avançada de funções, CFG 2.0 e fuzz targets.

## [0.1.0] - 2026-11-23
- Fundação multiplataforma C++20/Rust, parsers PE32+/ELF64, disassembler x86-64 e CLI inicial.
