# ByteMorph Lazy Bytecode Decryption & Bytecode Cache 2.0 (`v0.13.0`)

A v0.13.0 introduz o modo experimental `--bytecode-mode lazy`, dividindo funções virtualizadas em blocos básicos autenticados individualmente com **XChaCha20-Poly1305** e subchaves derivadas por `(fn_index, block_id)`.

## Arquitetura Criptográfica por Bloco

1. **Divisão em Blocos Básicos (`VmInterpreter::split_into_basic_blocks`)**: cada alvo de branch/call e cada instrução após `Jmp`/`Jcc`/`Call`/`Ret`/`Halt` inicia um novo bloco (`BvmBasicBlock`).
2. **Derivação de Subchaves (`CryptoAead::derive_block_key`)**: usa `BLAKE2b-256` em modo keyed (`crypto_blake2b_keyed_init`) com a chave mestre, domínio (`"bm.lazy.block.v1"`), `fn_index` e `block_id`.
3. **Nonces Exclusivos (`CryptoAead::generate_block_nonce`)**: gera nonces de 192 bits via `BLAKE2b` sobre `(seed, fn_index, block_id)`.
4. **AAD Vinculada ao Bloco (`LazyBytecodeEngine::build_block_aad`)**: autentica `magic ("BMLB")`, `version=1`, `fn_index`, `block_id`, `start_pc`, `insn_count` e `plain_bytes`, impedindo substituição ou reordenação de blocos.
5. **Modelo de Ameaça**: assim como na v0.10–v0.12, chaves distribuídas no executável garantem integridade/autenticidade contra adulteração (*anti-tamper*) e separação de domínios entre blocos, mas não confidencialidade absoluta contra um adversário com controle total do processo.

## Bytecode Cache 2.0 (`VmBytecodeCache`)

- **Isolamento por Contexto:** entradas indexadas por `(context_id, block_start_pc)`, evitando compartilhamento acidental entre funções/execuções.
- **LRU com Limites Configuráveis:** `max_bytes` (padrão `64 KiB`) e `max_entries` (padrão `128` blocos), com mutex para segurança multithread e compatibilidade com recursão/loops.
- **Limpeza Segura:** buffers de instruções despejados por LRU, invalidação (`invalidate_context` / `invalidate_all`) ou destruição são zerados via escrita `volatile`.
- **Fallback Controlado:** `--bytecode-mode eager` permanece disponível como padrão estável de menor latência.
