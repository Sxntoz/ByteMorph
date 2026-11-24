# Criptografia do ByteMorph (v0.11)

## Algoritmos Consolidados

O **ByteMorph** não inventa algoritmos criptográficos. Toda a camada criptográfica utiliza **Monocypher 4.0.2**:

- **AEAD:** `XChaCha20-Poly1305` (chave de 256 bits, nonce de 192 bits, tag Poly1305 de 128 bits, conforme RFC 8439 / XChaCha20-Poly1305).
- **Hash criptográfico & KDF:** `BLAKE2b-256` (para integridade de `.text` / `.bmrt`, derivação de chaves por domínio e geração determinística de nonces exclusivos por função).

## Fluxo em Runtime (`--encrypt-bytecode` / `--profile maximum`)

1. **Armazenamento autenticado:** o bytecode de cada função virtualizada em `.bmrt` / `__BMRT` é selado individualmente como um blob `BMBC` v2 (`magic + version + fn_index + plain_len`, `nonce[24]`, `mac[16]`, `ciphertext`).
2. **Nonces exclusivos:** cada função recebe um nonce derivado de `seed ^ (0x9E3779B97F4A7C15 * (fn_index + 1))` e contador exclusivo.
3. **Metadados públicos vs. material secreto:** os metadados `BMP4` v2 (`.bmvm`) armazenam apenas os nonces públicos, MACs e hashes `BLAKE2b-256` do AAD (`aad_hash`) para auditoria via `verify --deep`; a chave derivada permanece separada no runtime.
4. **Verificação e descriptografia em runtime:** os emissores PIC nativos (`x86-64` e `ARM64`) validam a tag Poly1305 em tempo constante **antes** de interpretar qualquer instrução da VM. Em caso de adulteração, a execução é interrompida (`0xDEADAEADDEADAEAD`) e o buffer é zerado.
5. **Limpeza de buffers:** após `Ret`/`Halt` (ou falha de tag), o buffer temporário em pilha contendo o bytecode descriptografado é sobrescrito com zeros (`0x00`). No host, `CryptoAead::secure_wipe` zera `rt_key`, contextos `BLAKE2b` e buffers `plain_bytes` após selagem.
6. **Validação estrita de metadados (`BMP4` v2):** `deserialize_metadata` rejeita nonces duplicados entre funções, `fn_index` duplicados/inválidos e registros com `plaintext_size == 0`.

## Modelo de Ameaça e Limitações Explícitas

- **Proteção contra corrupção e autenticidade (AEAD):** a tag Poly1305 detecta alterações acidentais ou maliciosas no cabeçalho `BMBC`, nonce ou ciphertext antes da execução na VM.
- **Confidencialidade em repouso vs. controle do processo:** **uma chave distribuída dentro do próprio executável não oferece sigilo absoluto contra um atacante com controle total do processo** (depuração, dump de memória ou engenharia reversa do runtime). A criptografia em runtime dificulta inspeção estática direta do bytecode em disco, mas não substitui isolamento por hardware (enclaves/DRM externo).
- **`verify --deep`:** executa validação estática adicional (W^X nas seções `.bmrt`/`.bmvm`, unicidade de nonces, `BMP4` v2 e AEAD). Não garante ausência de adulteração dinâmica em memória durante a execução.
