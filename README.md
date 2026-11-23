# ByteMorph

**ByteMorph** é um framework open source, modular e multiplataforma de análise binária, ofuscação de IR e virtualização de código em **C++20** e **Rust**.

> **Aviso Experimental (v0.3.0):**  
> O ByteMorph ainda é experimental e **não realiza proteção completa de executáveis de terceiros nesta versão**. Os passes de ofuscação e a VM operam sobre módulos `.ir` e programas `.bvm` validados, preservando compatibilidade com os mecanismos de segurança do sistema operacional (ASLR, DEP, CFG, CET).

## Recursos Implementados

- **Análise Binária Multiplataforma (v0.1 – v0.2):**
  - Parsers somente leitura para **PE32/PE32+**, **ELF32/ELF64** e **Mach-O 64-bit / Fat Universal** via **LIEF**.
  - Disassemblers e lifters IR para **x86-64** (**Zydis**) e **ARM64/AArch64** (**Capstone**).
  - Descoberta avançada de funções (`.pdata`, `.eh_frame_hdr`, `LC_FUNCTION_STARTS`) e **CFG 2.0** (loops, blocos inalcançáveis, confiança).
- **Ofuscação & Virtualização (v0.3):**
  - **Engine de ofuscação sobre IR:** substituição semântica, identidades MBA aritméticas/booleanas e predicados opacos em fluxo de controle com seeds determinísticas e orçamento de expansão.
  - **Máquina Virtual própria baseada em registradores:** 32 registradores de 64 bits, formato `.bvm` versionado com diversificação de opcodes por `build_seed`, interpretador seguro com limites de passos/memória/pilha.
  - **Tradutor IR → Bytecode** com resolução de labels e validação diferencial contra o interpretador de referência da IR.
  - **Protótipo AsmJit x86-64 (opcional):** geração de código nativo controlado e comparação de desempenho com a VM interpretada.

## Compilação (Windows, Linux e macOS)

### Pré-requisitos
- **CMake** >= 3.20
- Compilador **C++20** (MSVC 2022/2026 no Windows, GCC 11+ / Clang 14+ no Linux, Apple Clang no macOS)
- **Git** (para `FetchContent`: LIEF, Zydis, Capstone, AsmJit, GoogleTest)
- **Rust / Cargo** (opcional, para `bytemorph-verify`)

### Build e Testes

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel
ctest --test-dir build -C Release --output-on-failure
cargo test --workspace
```

Para desabilitar AsmJit (ex.: hosts não-x86-64 ou builds mínimos): `-DBYTEMORPH_ENABLE_ASMJIT=OFF`.

## Uso da CLI (v0.3)

```bash
# Análise estática (v0.1 - v0.2)
bytemorph info <arquivo>
bytemorph analyze <arquivo>
bytemorph disasm <arquivo>
bytemorph functions <arquivo>
bytemorph cfg <arquivo>
bytemorph inspect <arquivo> --format json

# IR, Ofuscação e Virtualização (v0.3)
bytemorph ir <arquivo> --output saida.ir
bytemorph obfuscate-ir entrada.ir --output saida.ir --seed 0x1234
bytemorph vm-compile entrada.ir --output programa.bvm --seed 0x5678
bytemorph vm-run programa.bvm
bytemorph vm-inspect programa.bvm
bytemorph benchmark-vm
```

Consulte [docs/IR_AND_BYTECODE.md](docs/IR_AND_BYTECODE.md) para detalhes da IR e da VM.

## Licença

Distribuído sob a licença **Apache-2.0**. Consulte [LICENSE](LICENSE).
