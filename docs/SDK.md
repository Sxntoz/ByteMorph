# ByteMorph C/C++ SDK (`v0.12.0`)

O SDK nativo do ByteMorph permite marcar funções específicas diretamente em código C/C++ para virtualização pós-compilação, com suporte a MSVC, GCC e Clang em Windows, Linux e macOS.

## Headers e API Versionada

- C11 / C++20: `#include <bytemorph/protect.h>`
- C++20: `#include <bytemorph/protect.hpp>`
- Versão: `BYTEMORPH_SDK_VERSION_STRING` (`"0.12.0"`), `bytemorph::sdk::version()`
- Perfis: `fast` (`BYTEMORPH_PROFILE_FAST`), `balanced` (`BYTEMORPH_PROFILE_BALANCED`), `maximum` (`BYTEMORPH_PROFILE_MAXIMUM`)

## Marcadores

```cpp
#include <bytemorph/protect.hpp>

BYTEMORPH_PROTECT_BEGIN
int calculate_license(int value) {
    return value * 42;
}
BYTEMORPH_PROTECT_END

BYTEMORPH_PROTECT_FUNC
uint64_t mix_token(uint64_t a, uint64_t b) {
    return (a * 1315423911ULL) ^ b;
}
```

### Como funciona

- **MSVC**: `BYTEMORPH_PROTECT_BEGIN` / `BYTEMORPH_PROTECT_END` emitem `#pragma code_seg(push, ".bmprot")` e `#pragma code_seg(pop)`, isolando o código compilado na seção `.bmprot`.
- **GCC / Clang**: `BYTEMORPH_PROTECT_FUNC` posiciona a função na seção `.bmprot` (`__TEXT,__bmprot` no macOS) e `BYTEMORPH_PROTECT_BEGIN` / `BYTEMORPH_PROTECT_END` emitem marcadores de intervalo `__bm_sdk_begin_marker` / `__bm_sdk_end_marker`.
- **Descoberta automática**: Ao executar `bytemorph protect app.exe --functions auto` (ou sem `--func`), o `ProtectionEngine` identifica automaticamente as funções marcadas na seção `.bmprot` / intervalos de marcadores.

## Integração CMake

Inclua `sdk/cmake/ByteMorphSDK.cmake` (ou linke `ByteMorph::SDK`):

```cmake
target_link_libraries(my_app PRIVATE ByteMorph::SDK)
bytemorph_protect_target(my_app
    PROFILE balanced
    ENCRYPT_BYTECODE
    REPORT "${CMAKE_CURRENT_BINARY_DIR}/my_app_report.json"
)
```
