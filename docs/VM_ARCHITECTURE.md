# Arquitetura da VM do ByteMorph (v0.10)

## Modelo de Registradores e Memória

- **32 Registradores GPR de 64 bits (`R0..R31`):** `R28..R31` reservados como scratch pelo `IrToVmTranslator`.
- **32 Registradores SIMD/FP de 128 bits (`V0..V31`):** mapeados para `xmm0..xmm15` (x86-64) e `v0..v31`/`d0..d31`/`s0..s31` (ARM64), preservando `xmm6..xmm15` (Win64) e `d8..d15` (AAPCS64).
- **Flags:** `ZF` (bit 0), `SF` (bit 1), `CF` (bit 2), `OF` (bit 3) e `PF` (paridade / `unordered` IEEE 754).
- **VM Memory Pool (`thread_local`):** no `VmInterpreter`, a memória virtual é reutilizada por thread (`use_memory_pool = true`) com zeragem prévia, mantendo isolamento total entre execuções e threads concorrentes.

## Conjunto de Instruções (`.bvm` / `VmOpcode`)

- **Controle e GPR:** `Nop`, `MovReg`, `MovImm`, `Load`, `Store`, `Add`, `Sub`, `Mul`, `Div`, `And`, `Or`, `Xor`, `Shl`, `Shr`, `Cmp`, `Jmp`, `Jeq`, `Jne`, `Jlt`, `Jle`, `Jgt`, `Jge`, `Call`, `Ret`, `Halt` (`dst=0xFF` trap), `CallExt`, `LeaPic` (`0x1A`), `SelectCc` (`0x1B`), `SetCc` (`0x1C`).
- **SIMD e Ponto Flutuante (IEEE 754):** `VMovReg` (`0x1D`), `VAddF32`/`F64` (`0x1E`/`0x1F`), `VSubF32`/`F64` (`0x20`/`0x21`), `VMulF32`/`F64` (`0x22`/`0x23`), `VDivF32`/`F64` (`0x24`/`0x25`), `VCmpF32`/`F64` (`0x26`/`0x27`), `VLoad` (`0x28`), `VStore` (`0x29`), `VXor` (`0x2A`).
