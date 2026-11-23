# Especificação de IR (`.ir`) e Bytecode (`.bvm`) — ByteMorph v0.3

> **Nota:** O ByteMorph encontra-se em estágio experimental (v0.3.0). Os formatos `.ir` e `.bvm` são versionados para evoluções futuras.

## 1. Formato Serializado `.ir` (`BMIR` v1)

| Campo | Tamanho | Descrição |
|---|---|---|
| `Magic` | 4 bytes | `0x52494D42` (`"BMIR"` em little-endian) |
| `Version` | 2 bytes | `1` |
| `Flags` | 2 bytes | Reservado (`0`) |
| `PayloadSize` | 4 bytes | Tamanho exato do payload em bytes |
| `Checksum` | 4 bytes | Hash FNV-1a de 32 bits do payload |
| `Payload` | `PayloadSize` | Módulo, arquitetura, funções, blocos básicos e instruções IR |

## 2. Arquitetura da Máquina Virtual (Baseada em Registradores)

A VM do ByteMorph adota uma arquitetura de **32 registradores de 64 bits** (`R0`–`R31`, sendo `R0` o acumulador/retorno e `R28`–`R31` registradores temporários do tradutor), além de flags `ZF` e `SF`, memória linear limitada (`memory_slots`) e pilha de chamadas limitada (`max_call_depth`).

**Justificativa da escolha (Registradores vs. Pilha):**
- Mapeamento direto para os registradores virtuais e arquiteturais da IR, reduzindo o número de instruções de movimento em comparação a uma VM de pilha pura.
- Menor sobrecarga de despacho no interpretador para expressões aritméticas e booleanas (ex.: MBA).
- Facilita a permutação polimórfica de opcodes por `build_seed`.

## 3. Formato Serializado `.bvm` (`BMVM` v1)

| Campo | Tamanho | Descrição |
|---|---|---|
| `Magic` | 4 bytes | `0x4D564D42` (`"BMVM"` em little-endian) |
| `Version` | 2 bytes | `1` |
| `Flags` | 2 bytes | Reservado (`0`) |
| `BuildSeed` | 8 bytes | Seed usada na permutação determinística da tabela de opcodes |
| `CodeSize` | 4 bytes | Múltiplo de 12 bytes (tamanho fixo por instrução) |
| `Checksum` | 4 bytes | FNV-1a 32 bits de `OpcodeTable + Code` |
| `OpcodeTable` | 32 bytes | Mapeamento lógico → físico dos opcodes |
| `Code` | `CodeSize` | Sequência de instruções (`u8 op, u8 dst, u8 src1, u8 src2, i64 imm`) |
