# ByteMorph IR Optimizer 2.0 (`v0.12.0`)

O `IrOptimizer` (`core/ir/include/bytemorph/core/ir/ir_optimizer.hpp`) executa um pipeline modular de otimização sobre `IrFunction` e `IrModule` antes da ofuscação/tradução para bytecode BVM, preservando semântica de memória, flags (`ZF/SF/CF/OF`), ponto flutuante/SIMD e efeitos colaterais (`Store`, `Call`, `Syscall`, `Div`).

## Passes Modulares

1. **Expression / Algebraic Simplification** (`simplify_expressions`): elimina `Mov x, x`, simplifica identidades (`x + 0`, `x - 0`, `x ^ x`, `x * 1`, `x * 0`, `x & 0`, `x << 0`, `x >> 0`) quando as flags não estão vivas após a instrução.
2. **Constant Propagation & Folding** (`propagate_and_fold_constants`): propaga imediatos por bloco básico e dobra operações aritméticas/lógicas constantes (`Add`, `Sub`, `Mul`, `Div` com divisor não nulo, `And`, `Or`, `Xor`, `Shl`, `Shr`).
3. **Copy Propagation** (`propagate_copies`): substitui usos de cópias `Mov dst, src` dentro do bloco básico.
4. **Local Redundant Instruction Elimination** (`eliminate_redundant_instructions`): elimina expressões puras duplicadas quando os operandos não foram redefinidos e as flags não são observadas.
5. **Branch & CFG Simplification** (`simplify_branches`): dobra `Cmp imm, imm` + `JumpCond` estáticos, remove `Nop`s e elimina blocos básicos inalcançáveis.
6. **Liveness Analysis & DCE** (`compute_liveness`, `eliminate_dead_code`): calcula `live_in`/`live_out` e remove definições mortas de `VirtualReg` sem efeitos colaterais.
7. **Virtual Register Coalescing** (`coalesce_virtual_registers`): compacta registradores virtuais (`v0, v1, ...`).

## Uso via CLI

```bash
bytemorph optimize-ir input.ir --level 3 -o output.ir
```
