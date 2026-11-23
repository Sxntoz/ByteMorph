# Arquitetura do ByteMorph (v0.3)

## Visão Geral

1. **Cross-protection por design:** O `core/` não possui dependências de APIs específicas de sistema operacional.
2. **Camadas modulares:**
   - `core/diagnostics`, `core/binary`, `core/analysis`: detecção, leitura bounds-checked e CFG 2.0.
   - `core/ir`: IR independente de arquitetura, serializador versionado (`BMIR` v1) e interpretador determinístico de referência.
   - `formats/{pe,elf,macho}` e `architectures/{x86_64,aarch64}`: parsers LIEF, disassemblers Zydis/Capstone e lifters IR.
   - `obfuscation/`: pipeline modular (`SemanticSubstitutionPass`, `ArithmeticBooleanMbaPass`, `ControlFlowObfuscationPass`) e `EquivalenceValidator`.
   - `virtualization/`: VM baseada em 32 registradores de 64 bits, codec `.bvm` (`BMVM` v1) com tabela de opcodes diversificada por `build_seed`, tradutor `IrToVmTranslator` e protótipo nativo `AsmJitPrototype`.
   - `rust/bytemorph-verify`: pré-validador seguro (`#![forbid(unsafe_code)]`) e entropia.
   - `protection/`, `runtime/`: contratos preservados para reescrita segura de binários e verificação de integridade em v0.4+.
