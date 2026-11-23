# ByteMorph

**ByteMorph** é um framework open source, modular e multiplataforma de análise binária, ofuscação de IR, virtualização de código e proteção de binários em **C++20** e **Rust**.

> **Status atual (v0.4.0):**  
> - **Análise estática e IR/VM:** multiplataforma (PE32+, ELF64, Mach-O 64-bit / Fat Universal; x86-64 e ARM64).  
> - **Proteção e reescrita de binários (`protect` / `verify`):** funcional para **Windows PE32+ x86-64** em executáveis de laboratório não assinados; **ELF64** e **Mach-O 64-bit** permanecem como contratos planejados para a v0.5.

## Recursos da v0.4

- **Reescrita modular de binários (`protection/`):**
  - Inserção controlada de seções respeitando W^X: `.bmrt` (`R-X`, runtime VM nativo PIC x86-64 via AsmJit) e `.bmvm` (`R--`, metadados versionados `BMP4` v1 e payload criptografado).
  - Preservação de ASLR (`DYNAMIC_BASE`), DEP/NX (`NX_COMPAT`), `.pdata`, `.reloc`, imports e exports.
  - Recusa modificação silenciosa de binários assinados com Authenticode (exige `--allow-signed-strip`).
- **Virtualização seletiva de funções:**
  - Seleção por nome exportado (`--func`) ou RVA (`--func-rva`), validação de elegibilidade, lifting → ofuscação (`fast` / `balanced` / `maximum`) → tradução para VM → trampoline `jmp rel32` compatível com ASLR e Win64 ABI.
- **Criptografia Autenticada e Integridade (Monocypher 4.0.2):**
  - **XChaCha20-Poly1305 AEAD** para selagem de bytecode e strings/constantes protegidas.
  - **BLAKE2b-256** para verificação de integridade de `.text` e `.bmrt`.

## Compilação (Windows, Linux e macOS)

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel 2
ctest --test-dir build -C Release --output-on-failure
cargo test --workspace
```

## Uso da CLI (v0.4)

```bash
# Análise e IR/VM (v0.1 - v0.3)
bytemorph info <arquivo>
bytemorph analyze <arquivo>
bytemorph disasm <arquivo>
bytemorph functions <arquivo>
bytemorph cfg <arquivo>
bytemorph inspect <arquivo> --format json
bytemorph ir <arquivo> --output saida.ir
bytemorph obfuscate-ir entrada.ir --output saida.ir --seed 0x1234
bytemorph vm-compile entrada.ir --output programa.bvm --seed 0x5678
bytemorph vm-run programa.bvm
bytemorph vm-inspect programa.bvm
bytemorph benchmark-vm

# Proteção de Binários PE32+ x86-64 (v0.4)
bytemorph protect input.exe --output protected.exe --profile balanced --func minha_funcao
bytemorph verify protected.exe
bytemorph protection-info protected.exe
bytemorph benchmark-protection
```

## Licença

Distribuído sob a licença **Apache-2.0**. Consulte [LICENSE](LICENSE).
Compatível com LIEF (Apache-2.0), Zydis (MIT), Capstone (BSD-3-Clause), AsmJit (Zlib), Monocypher (CC0/BSD-2-Clause) e GoogleTest (BSD-3-Clause).
