# Changelog

## [0.3.0] - 2026-11-23

### Adicionado
- Serialização versionada `.ir` (`BMIR` v1) e interpretador determinístico de referência da IR (`IrInterpreter`).
- Engine de ofuscação sobre IR (`SemanticSubstitutionPass`, `ArithmeticBooleanMbaPass`, `ControlFlowObfuscationPass`, `ObfuscationPipeline`, `EquivalenceValidator`).
- Máquina virtual própria baseada em registradores, formato `.bvm` (`BMVM` v1) com diversificação de opcodes por `build_seed` e interpretador seguro com limites de execução.
- Tradutor `IrToVmTranslator` e protótipo nativo x86-64 via **AsmJit** (`AsmJitPrototype`).
- Comandos CLI v0.3: `ir`, `obfuscate-ir`, `vm-compile`, `vm-run`, `vm-inspect` e `benchmark-vm`.
- Testes diferenciais IR vs IR ofuscada vs VM, testes baseados em propriedades e documentação em `docs/IR_AND_BYTECODE.md`.

## [0.2.0] - 2026-11-23

### Adicionado
- Parser Mach-O 64-bit e Fat/Universal, disassembler/lifter ARM64 (Capstone), `.pdata`/`.eh_frame_hdr`/`LC_FUNCTION_STARTS`, CFG 2.0, fuzz targets e benchmark.

## [0.1.0] - 2026-11-23

### Adicionado
- Fundação multiplataforma C++20/Rust, parsers PE32+/ELF64, disassembler x86-64 e CLI inicial.
