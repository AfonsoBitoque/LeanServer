# LeanServer — Theorem Roadmap: Pre-Release

> **Estado actual:** 914 teoremas, 0 sorry, 0 vacuamente verdadeiros.
> **Diagnóstico:** W1, W2, W4 corrigidos. W3 é honesto (nome diz "at_zero").

---

## Diagnóstico: Teoremas Fracos Existentes

Antes de adicionar novos teoremas, estes existentes precisam de ser **substituídos por versões reais**:

| # | Teorema | Ficheiro | Problema |
|---|---------|----------|----------|
| W1 | `sbox_surjective` | [Proofs.lean](LeanServer/Proofs.lean#L1490) | ✅ **CORRIGIDO** — substituído por `sbox_injective_crossref` (prova real via `native_decide`). Versão forte em `Spec.AdvancedProofs.sBox_injective`. |
| W2 | `nonce_uniqueness` | [NonceManager.lean](LeanServer/Crypto/NonceManager.lean#L140) | ✅ **CORRIGIDO** — substituído por `nonce_structural_uniqueness` que prova `counter₁ ≠ counter₂ ∧ counter₂ ≠ counter₃` via `omega`. Sem escape `∨ rfl`. |
| W3 | `padSeqNum_injective_at_zero` | [NonceManager.lean](LeanServer/Crypto/NonceManager.lean#L116) | Só prova `padSeqNum 0 ≠ padSeqNum 1` — um caso concreto, não injectividade. |
| W4 | `aes_sbox_complete` | [Proofs.lean](LeanServer/Proofs.lean#L610) | ✅ **CORRIGIDO** — renomeado para `aes_sbox_size` com docstring honesta (bounds-safety, não "completude"). |

**Estado:** W1, W2, W4 corrigidos. W3 (`padSeqNum_injective_at_zero`) é honesto
— o nome indica claramente que é um caso concreto. A versão universal (F5.1)
requer prova de injectividade de big-endian encoding, planeada para fase 5.

---

## Hierarquia de Dependências

Muitos teoremas fortes dependem uns dos outros. Esta é a cadeia crítica:

```
sha256_process_block_size (8 elems preservado)
    │
    ▼
sha256_pad_size_mod64 (padding múltiplo de 64)
    │
    ▼
sha256_output_size (∀ msg, 32 bytes)          ← DESBLOQUEIO PRINCIPAL
    │
    ├──► hmac_sha256_output_size (∀ key msg, 32 bytes)
    │        │
    │        ▼
    │    hkdf_expand_output_size (∀ prk info len, len bytes)  ← SEGUNDO DESBLOQUEIO
    │        │
    │        ├──► deriveSecret_size (32 bytes)
    │        ├──► deriveHandshakeKeys_sizes (16B keys, 12B IVs)
    │        └──► deriveAppKeys_sizes (16B keys, 12B IVs)
    │
    └──► aesGCM_roundtrip (decrypt ∘ encrypt = id)        ← COROA
             │
             ├──► tls13_record_roundtrip
             └──► aesGCM_tag_integrity (rejeita tags forjados)
```

```
X25519 field ops (add_lt_P, mul_lt_P, sub_lt_P)
    │
    ▼
scalarMultNat correctness
    │
    ▼
key_exchange_agreement (DH comutatividade)       ← PROPRIEDADE MAIS IMPORTANTE
```

```
addRoundKey_self_inverse (XOR involution)
    │
    ├──► subBytes/invSubBytes roundtrip
    │        │
    │        ▼
    │    aes_single_round_inverse
    │        │
    │        ▼
    │    aes_full_roundtrip (10 rounds)
    │        │
    │        ▼
    └──► aesGCM_roundtrip (com CTR mode)
```

---

## Fase 1 — Fundações (Pré-requisitos para tudo o resto)

> **Meta:** Provar propriedades base que desbloqueiam cascatas de teoremas downstream.
> **Estimativa:** 2-3 dias. ~15 teoremas.

### 1.1 — Aritmética UInt8 / XOR

| ID | Teorema | Ficheiro | Statement | Dificuldade |
|----|---------|----------|-----------|-------------|
| F1.1 | `uint8_xor_self_cancel` | `Proofs.lean` | `∀ a : UInt8, a ^^^ a = 0` | Fácil |
| F1.2 | `uint8_xor_zero` | `Proofs.lean` | `∀ a : UInt8, a ^^^ 0 = a` | Fácil |
| F1.3 | `uint8_xor_comm` | `Proofs.lean` | `∀ a b : UInt8, a ^^^ b = b ^^^ a` | Fácil |
| F1.4 | `uint8_xor_assoc` | `Proofs.lean` | `∀ a b c : UInt8, (a ^^^ b) ^^^ c = a ^^^ (b ^^^ c)` | Fácil |
| F1.5 | `uint8_and_ff` | `Proofs.lean` | `∀ a : UInt8, a &&& 0xFF = a` | Fácil |
| F1.6 | `uint8_and_zero` | `Proofs.lean` | `∀ a : UInt8, a &&& 0 = 0` | Fácil |
| F1.7 | `uint8_or_zero` | `Proofs.lean` | `∀ a : UInt8, a \|\|\| 0 = a` | Fácil |

**Porque:** Estes são lemas fundamentais usados em AES (AddRoundKey), SideChannel (ctSelect), RSA (xorBytes), e GCM (GHASH). Sem eles, nenhum teorema de roundtrip é provável.

### 1.2 — ByteArray Size Lemas

| ID | Teorema | Ficheiro | Statement | Dificuldade |
|----|---------|----------|-----------|-------------|
| F1.8 | `bytearray_push_size` | `Proofs.lean` | `∀ ba v, (ba.push v).size = ba.size + 1` | Fácil |
| F1.9 | `bytearray_extract_size` | `Proofs.lean` | `∀ ba s e, s ≤ e → e ≤ ba.size → (ba.extract s e).size = e - s` | Médio |
| F1.10 | `bytearray_append_size` | `Proofs.lean` | `∀ a b, (a ++ b).size = a.size + b.size` | Fácil |
| F1.11 | `bytearray_set_size` | `Proofs.lean` | `∀ ba i v h, (ba.set ⟨i, h⟩ v).size = ba.size` | Fácil |
| F1.12 | `bytearray_map_size` | `Proofs.lean` | `∀ ba f, (ba.data.map f).size = ba.size` | Fácil |

**Porque:** Quase todos os teoremas de tamanho de output (SHA-256, HKDF, AES, nonces) dependem destes lemas sobre `ByteArray`.

### 1.3 — X25519 Operações de Campo

| ID | Teorema | Ficheiro | Statement | Dificuldade |
|----|---------|----------|-----------|-------------|
| F1.13 | `x25519_add_lt_P` | `X25519.lean` | `∀ a b, a < P → b < P → add a b < P` | Fácil |
| F1.14 | `x25519_sub_lt_P` | `X25519.lean` | `∀ a b, a < P → b < P → sub a b < P` | Fácil |
| F1.15 | `x25519_mul_lt_P` | `X25519.lean` | `∀ a b, a < P → b < P → mul a b < P` | Fácil |

**Porque:** `add`, `sub`, `mul` terminam com `% P`. `Nat.mod_lt` dá o resultado. Sem estes, nenhum teorema sobre o Montgomery ladder é provável — os valores intermédios podem estar fora do campo.

---

## Fase 2 — Criptografia Core (A cadeia SHA→HMAC→HKDF)

> **Meta:** Provar a cadeia de tamanhos de output que desbloqueia TODO o key schedule do TLS.
> **Estimativa:** 3-5 dias. ~12 teoremas.
> **Impacto:** Máximo. Desbloqueia Fase 4, 5 e 6.

| ID | Teorema | Ficheiro | Statement | Dif. | Desbloqueia |
|----|---------|----------|-----------|------|-------------|
| F2.1 | `sha256_process_block_size` | `Crypto.lean` | `∀ h chunk, h.size = 8 → (sha256_process_block h chunk).size = 8` | Médio | F2.3 |
| F2.2 | `sha256_pad_size_mod64` | `Crypto.lean` | `∀ msg, (sha256_pad msg).size % 64 = 0` | Médio | F2.3 |
| F2.3 | **`sha256_output_size`** | `Crypto.lean` | `∀ msg, (sha256 msg).size = 32` | **Difícil** | F2.4, F2.5, F2.6 |
| F2.4 | `hmac_sha256_output_size` | `Crypto.lean` | `∀ key msg, (hmac_sha256 key msg).size = 32` | Médio | F2.5 |
| F2.5 | **`hkdf_expand_output_size`** | `Crypto.lean` | `∀ prk info len, len ≤ 255*32 → (hkdf_expand prk info len).size = len` | **Difícil** | F2.6 |
| F2.6 | `hkdf_extract_output_size` | `Crypto.lean` | `∀ salt ikm, (hkdf_extract salt ikm).size = 32` | Fácil | F4.1 |
| F2.7 | `sha256_deterministic_strong` | `Crypto.lean` | `∀ a b, a = b → sha256 a = sha256 b` | Fácil | — |
| F2.8 | `hmac_sha256_deterministic` | `Crypto.lean` | `∀ k m, hmac_sha256 k m = hmac_sha256 k m` | Fácil | — |
| F2.9 | `sha256_empty_vector` | `Proofs.lean` | Verify SHA-256("") = RFC 6234 test vector (já parcial) | Fácil | Validação |
| F2.10 | `sha256_abc_vector` | `Proofs.lean` | Verify SHA-256("abc") = RFC 6234 test vector (já parcial) | Fácil | Validação |
| F2.11 | `hkdf_expand_empty_info` | `Crypto.lean` | `hkdf_expand prk ByteArray.empty 32 = hmac_sha256 prk (ByteArray.empty.push 1)` | Médio | Validação |
| F2.12 | `hkdf_extract_is_hmac` | `Crypto.lean` | `hkdf_extract salt ikm = hmac_sha256 salt ikm` (já existe, confirmar) | Fácil | Clareza |

---

## Fase 3 — AES Correctness (O cipher core)

> **Meta:** Provar que AES é uma permutação inversível e que GCM é um AEAD correcto.
> **Estimativa:** 5-8 dias. ~15 teoremas.
> **Impacto:** Coroa do projecto — ninguém tem AES-GCM roundtrip em Lean 4.

### 3.1 — S-Box como Permutação Real

| ID | Teorema | Ficheiro | Statement | Dif. |
|----|---------|----------|-----------|------|
| F3.1 | **`sBox_injective`** | `Proofs.lean` | `∀ a b : Fin 256, sBox[a] = sBox[b] → a = b` | Fácil (`native_decide`) |
| F3.2 | **`sBox_surjective_real`** | `Proofs.lean` | `∀ out : Fin 256, ∃ inp : Fin 256, sBox[inp] = sBox[out]` | Fácil (`native_decide`) |
| F3.3 | `invSBox_correct` | `AES.lean` | `∀ b : UInt8, invSubByte (subByte b) = b` | Fácil (`native_decide`) |

**Nota:** F3.1 SUBSTITUI o teorema fraco `sbox_surjective` (W1).

### 3.2 — Round Operations Invertíveis

| ID | Teorema | Ficheiro | Statement | Dif. |
|----|---------|----------|-----------|------|
| F3.4 | **`addRoundKey_self_inverse`** | `AES.lean` | `∀ state key, addRoundKey (addRoundKey state key) key = state` | Médio |
| F3.5 | `subBytes_invSubBytes` | `AES.lean` | `∀ state, invSubBytes (subBytes state) = state` | Fácil (depende F3.3) |
| F3.6 | `shiftRows_invShiftRows` | `AES.lean` | `∀ state, invShiftRows (shiftRows state) = state` | Médio |
| F3.7 | `mixColumns_invMixColumns` | `AES.lean` | `∀ state, invMixColumns (mixColumns state) = state` | Difícil |

### 3.3 — AES Block Cipher

| ID | Teorema | Ficheiro | Statement | Dif. |
|----|---------|----------|-----------|------|
| F3.8 | `expandKey_size` | `AES.lean` | `∀ key, key.size = 16 → (expandKey key).size = 176` | Difícil |
| F3.9 | **`aes_block_roundtrip`** | `AES.lean` | `∀ key block, key.size = 16 → block.size = 16 → decryptBlock key (encryptBlock key block) = block` | **Muito Difícil** |

### 3.4 — GCM Mode

| ID | Teorema | Ficheiro | Statement | Dif. |
|----|---------|----------|-----------|------|
| F3.10 | `inc32_preserves_prefix` | `AES.lean` | `∀ iv, iv.size = 16 → (inc32 iv).extract 0 12 = iv.extract 0 12` | Médio |
| F3.11 | `ctr_mode_self_inverse` | `AES.lean` | CTR XOR é auto-inverso: encrypt = decrypt para counter mode | Difícil |
| F3.12 | `ghash_deterministic` | `AES.lean` | `∀ h data, ghash h data = ghash h data` | Fácil |
| F3.13 | **`aesGCM_roundtrip`** | `AES.lean` | `∀ key iv pt aad, decrypt(encrypt(key, iv, pt, aad), aad) = some pt` | **Muito Difícil** |
| F3.14 | **`aesGCM_tag_integrity`** | `AES.lean` | Tag modificado → decrypt retorna `none` | **Muito Difícil** |
| F3.15 | `aesGCM_ciphertext_size` | `AES.lean` | `(aesGCMEncrypt key iv pt aad).size = pt.size + 16` | Médio |

---

## Fase 4 — TLS Key Schedule (Connecting crypto to protocol)

> **Meta:** Provar tamanhos correctos dos keys derivados e correctude do key schedule.
> **Estimativa:** 3-4 dias. ~10 teoremas.
> **Depende de:** Fase 2 (sha256_output_size, hkdf_expand_output_size).

| ID | Teorema | Ficheiro | Statement | Dif. |
|----|---------|----------|-----------|------|
| F4.1 | **`deriveHandshakeKeys_sizes`** | `TLSKeySchedule.lean` | `clientKey.size = 16 ∧ serverKey.size = 16 ∧ clientIV.size = 12 ∧ serverIV.size = 12` | Difícil |
| F4.2 | `deriveAppKeys_sizes` | `TLSKeySchedule.lean` | Idem para application keys | Difícil |
| F4.3 | `deriveSecret_size` | `TLSKeySchedule.lean` | `∀ secret label ctx, (deriveSecret secret label ctx).size = 32` | Médio |
| F4.4 | `hkdfExpandLabel_size` | `TLSKeySchedule.lean` | `∀ secret label ctx len, (hkdfExpandLabel ...).size = len` | Médio |
| F4.5 | `computeFinished_size` | `TLSKeySchedule.lean` | `(computeFinished baseKey transcriptHash).size = 32` | Médio |
| F4.6 | `computeFinished_deterministic` | `TLSKeySchedule.lean` | Inputs iguais → Finished iguais | Fácil |
| F4.7 | **`key_schedule_chain_sizes`** | `TLSKeySchedule.lean` | Toda a cadeia earlySecret→hsSecret→masterSecret preserva 32B | Difícil |
| F4.8 | `deriveHandshakeKeys_deterministic` | `TLSKeySchedule.lean` | Inputs iguais → keys iguais | Fácil |
| F4.9 | `psk_binder_size` | `TLSKeySchedule.lean` | `computePSKBinder` retorna 32 bytes | Médio |
| F4.10 | `resumption_master_secret_size` | `TLSKeySchedule.lean` | `deriveResumptionSecret` retorna 32 bytes | Médio |

---

## Fase 5 — Nonce Manager (Substituir teoremas fracos)

> **Meta:** Provar nonce uniqueness REAL — a propriedade de segurança mais crítica do AES-GCM.
> **Estimativa:** 2-3 dias. ~8 teoremas.
> **Impacto:** Substitui W2 e W3. Elimina o risco de nonce reuse (ataque Joux).

| ID | Teorema | Ficheiro | Statement | Dif. |
|----|---------|----------|-----------|------|
| F5.1 | **`padSeqNum_injective`** | `NonceManager.lean` | `∀ m n, m ≠ n → m < 2^64 → n < 2^64 → padSeqNum m ≠ padSeqNum n` | Difícil |
| F5.2 | `xor_injective_right` | `NonceManager.lean` | `∀ iv a b, a.size = iv.size → b.size = iv.size → a ≠ b → xorBytes iv a ≠ xorBytes iv b` | Difícil |
| F5.3 | **`getNonceForSeq_injective`** | `NonceManager.lean` | `∀ iv m n, m ≠ n → getNonceForSeq iv m ≠ getNonceForSeq iv n` | Difícil |
| F5.4 | **`nonce_uniqueness_real`** | `NonceManager.lean` | `∀ state, (gen state).2 ≠ (gen (gen state).1).2` (sem `∨ True`) | Médio |
| F5.5 | `generateNonceN_pairwise_distinct` | `NonceManager.lean` | Todos os nonces de N gerações são pairwise distintos | Muito Difícil |
| F5.6 | `nonce_counter_no_wrap` | `NonceManager.lean` | `counter < 2^64 - 1 → (gen state).1.counter < 2^64` | Fácil |
| F5.7 | `generateNonce_nonce_size` | `NonceManager.lean` | `(generateNonce state).2.size = 12` | Médio |
| F5.8 | `nonce_never_all_zeros` | `NonceManager.lean` | Se `iv ≠ 0` e `counter > 0`, nonce ≠ all zeros | Médio |

---

## Fase 6 — SideChannel (Constant-time correctness)

> **Meta:** Provar que as operações constant-time são funcionalmente correctas.
> **Estimativa:** 1-2 dias. ~8 teoremas.

| ID | Teorema | Ficheiro | Statement | Dif. |
|----|---------|----------|-----------|------|
| F6.1 | **`ctEqual_reflexive`** | `SideChannel.lean` | `∀ a, ctEqual a a = true` | Médio |
| F6.2 | **`ctEqual_detects_difference`** | `SideChannel.lean` | `a.size = b.size → (∃ i, a[i] ≠ b[i]) → ctEqual a b = false` | Difícil |
| F6.3 | `ctSelect_true_returns_first` | `SideChannel.lean` | `(ctSelect true a b).value = a.value` | Fácil |
| F6.4 | `ctSelect_false_returns_second` | `SideChannel.lean` | `(ctSelect false a b).value = b.value` | Fácil |
| F6.5 | `mkZeros_size_universal` | `SideChannel.lean` | `∀ n, (mkZeros n).size = n` | Fácil |
| F6.6 | `mkZeros_all_zero` | `SideChannel.lean` | `∀ n i, i < n → (mkZeros n).get i = 0` | Médio |
| F6.7 | `zeroize_size` | `SideChannel.lean` | `(zeroize s).value.size = s.value.size` | Fácil |
| F6.8 | `zeroize_all_zero` | `SideChannel.lean` | `∀ i, i < s.value.size → (zeroize s).value.get i = 0` | Médio |

---

## Fase 7 — X25519 Key Exchange (A propriedade mais importante)

> **Meta:** Provar Diffie-Hellman agreement — ambos os lados derivam o mesmo shared secret.
> **Estimativa:** 5-10 dias. ~12 teoremas.
> **Impacto:** Crown jewel. Nenhum projecto Lean tem isto provado.

| ID | Teorema | Ficheiro | Statement | Dif. |
|----|---------|----------|-----------|------|
| F7.1 | `encodeScalar_size` | `X25519.lean` | `∀ n, (encodeScalar n).size = 32` | Médio |
| F7.2 | `decodeScalar_encodeScalar` | `X25519.lean` | `∀ n, n < 2^256 → decodeScalar (encodeScalar n) = n` | Médio |
| F7.3 | `encodeScalar_decodeScalar` | `X25519.lean` | `∀ ba, ba.size = 32 → encodeScalar (decodeScalar ba) = ba` | Médio |
| F7.4 | `clamp_low_bits_zero` | `X25519.lean` | `∀ k, k.size = 32 → (decodeScalar (clamp k)) % 8 = 0` | Médio |
| F7.5 | `clamp_bit254_set` | `X25519.lean` | `∀ k, k.size = 32 → decodeScalar (clamp k) ≥ 2^254` | Médio |
| F7.6 | `clamp_bit255_clear` | `X25519.lean` | `∀ k, k.size = 32 → decodeScalar (clamp k) < 2^255` | Médio |
| F7.7 | `scalarMult_on_curve` | `X25519.lean` | Resultado do Montgomery ladder está na curva | Muito Difícil |
| F7.8 | `mul_assoc_mod_P` | `X25519.lean` | `∀ a b c, mul (mul a b) c = mul a (mul b c)` (mod P) | Difícil |
| F7.9 | `pow_mod_P_well_defined` | `X25519.lean` | `pow` preserva `< P` | Médio |
| F7.10 | `invert_correct` | `X25519.lean` | `∀ a, a > 0 → mul a (invert a) = 1` (mod P) | Muito Difícil |
| F7.11 | `x25519_self_consistent` | `X25519.lean` | `x25519 (encodeScalar a) (encodeScalar (scalarMultNat b 9)) = x25519 (encodeScalar b) (encodeScalar (scalarMultNat a 9))` | Muito Difícil |
| F7.12 | **`key_exchange_agreement`** | `X25519.lean` | `scalarMultNat a (scalarMultNat b G) = scalarMultNat b (scalarMultNat a G)` | **Extremamente Difícil** |

---

## Fase 8 — RSA-PSS (Assinatura digital)

> **Meta:** Provar sign/verify roundtrip para CertificateVerify do TLS 1.3.
> **Estimativa:** 3-5 dias. ~10 teoremas.

| ID | Teorema | Ficheiro | Statement | Dif. |
|----|---------|----------|-----------|------|
| F8.1 | `modPow_lt` | `RSA.lean` | `∀ b e n, n > 0 → modPow b e n < n` | Médio |
| F8.2 | `modPow_one` | `RSA.lean` | `∀ b n, n > 1 → modPow b 1 n = b % n` | Fácil |
| F8.3 | `i2osp_output_size` | `RSA.lean` | `∀ x len, (i2osp x len).size = len` | Médio |
| F8.4 | `os2ip_i2osp_roundtrip` | `RSA.lean` | `∀ x len, x < 2^(8*len) → os2ip (i2osp x len) = x` | Difícil |
| F8.5 | `xorBytes_self_inverse` | `RSA.lean` | `∀ a b, a.size = b.size → xorBytes (xorBytes a b) b = a` | Médio |
| F8.6 | `mgf1_output_size` | `RSA.lean` | `∀ hash seed len, (mgf1 hash seed len).size = len` | Difícil |
| F8.7 | `emsa_pss_encode_size` | `RSA.lean` | Output size = emLen | Difícil |
| F8.8 | `mgf1_deterministic` | `RSA.lean` | Inputs iguais → output igual | Fácil |
| F8.9 | `rsa_textbook_roundtrip` | `RSA.lean` | `∀ m, m < n → modPow (modPow m e n) d n = m` (dado RSA key válida) | Difícil |
| F8.10 | **`rsassa_pss_verify_after_sign`** | `RSA.lean` | `verify(sign(msg)) = true` (dado RSA key válida) | **Muito Difícil** |

---

## Fase 9 — Refinement Chain (Fechar os gaps)

> **Meta:** Transformar os teoremas ponto-a-ponto num refinement inductivo completo.
> **Estimativa:** 4-6 dias. ~12 teoremas.
> **Impacto:** É isto que torna o projecto publicável em venues como POPL/ITP.

| ID | Teorema | Ficheiro | Statement | Dif. |
|----|---------|----------|-----------|------|
| F9.1 | **`clientHello_flight_refines_model`** | `TLSRefinement.lean` | 5 acções atómicas do ServerStep correspondem a 5 transições Model válidas | Difícil |
| F9.2 | `all_error_paths_terminal` | `ServerStep.lean` | Todo path de erro mapeia para Model.Closed (terminal) | Médio |
| F9.3 | `all_error_paths_send_alert` | `ServerStep.lean` | Todo path de erro emite um alert antes de fechar | Médio |
| F9.4 | `serverStep_keyUpdate_refines_model` | `TLSRefinement.lean` | KeyUpdate preserva Connected no Model | Médio |
| F9.5 | `serverStep_closeNotify_refines_model` | `TLSRefinement.lean` | CloseNotify → Model.Closed | Médio |
| F9.6 | **`multi_step_simulation`** | `TLSRefinement.lean` | Para qualquer sequência de eventos, o estado final do ServerStep mapeia correctamente para o Model | **Muito Difícil** |
| F9.7 | `model_backward_simulation` | `TLSModel.lean` | Todo trace válido no Spec pode ser realizado pelo Model (backward sim) | Difícil |
| F9.8 | `refinement_preserves_safety` | `TLSRefinement.lean` | Se Spec satisfaz propriedade P, ServerStep também satisfaz P | Difícil |
| F9.9 | `no_data_before_connected_impl` | `TLSStateMachineProofs.lean` | `encryptAppData` só funciona em Data state (existente, fortalecer) | Médio |
| F9.10 | `transcript_append_only_multi` | `TLSStateMachineProofs.lean` | Multi-step: transcript é sempre prefix-ordered | Médio |
| F9.11 | `handshake_must_complete` | `TLSStateMachineProofs.lean` | Sem KeyShare ∨ sem Verify → never reaches Connected | Médio |
| F9.12 | `connected_enables_data_flow` | `TLSRefinement.lean` | Connected + appKeys → encryptAppData bem-sucedido | Médio |

---

## Fase 10 — Codecs & Protocol Invariants

> **Meta:** Provar roundtrip universal para TODOS os codecs e invariantes de protocolo.
> **Estimativa:** 3-4 dias. ~15 teoremas.

### 10.1 — Roundtrip Universais (substituir native_decide pontuais)

| ID | Teorema | Ficheiro | Statement | Dif. |
|----|---------|----------|-----------|------|
| F10.1 | **`frameHeader_roundtrip_universal`** | `UniversalCodecProofs.lean` | `∀ h, len < 2^24 → sid < 2^31 → parse(serialize h) = some h` | Muito Difícil |
| F10.2 | **`varint_roundtrip_universal`** | `UniversalCodecProofs.lean` | `∀ v < 2^62, decode(encode v) = some (v, _)` | Difícil |
| F10.3 | **`hpack_integer_roundtrip_universal`** | `UniversalCodecProofs.lean` | `∀ val prefix, decodeInteger(encodeInteger val prefix) = val` | Difícil |
| F10.4 | `hpack_huffman_roundtrip` | `HPACK.lean` | `∀ data, huffmanDecode(huffmanEncode data) = some data` | Muito Difícil |

### 10.2 — Invariantes de Protocolo

| ID | Teorema | Ficheiro | Statement | Dif. |
|----|---------|----------|-----------|------|
| F10.5 | **`hpack_table_size_invariant`** | `ProtocolInvariants.lean` | `∀ table field, table.size ≤ maxSize → (add table field).size ≤ maxSize` | Difícil |
| F10.6 | `h2_concurrency_bound` | `ProtocolInvariants.lean` | `¬canCreateStream → activeStreams ≥ maxConcurrent` | Médio |
| F10.7 | `h2_goaway_last_stream_monotonic` | `ProtocolInvariants.lean` | GOAWAY lastStreamId nunca aumenta | Médio |
| F10.8 | `quic_closed_terminal` | `ProtocolInvariants.lean` | QUIC closed state é terminal | Fácil |
| F10.9 | `h2_window_lifecycle_bounded` | `ProtocolInvariants.lean` | update + consume preserva bounds | Médio |
| F10.10 | `psk_cache_insert_prune_bounded` | `ProtocolInvariants.lean` | insert + prune preserva cache size | Médio |

### 10.3 — X.509 & Anti-Downgrade

| ID | Teorema | Ficheiro | Statement | Dif. |
|----|---------|----------|-----------|------|
| F10.11 | `x509_depth_enforcement` | `ProtocolInvariants.lean` | `chain.size > maxDepth → .depthExceeded` | Médio |
| F10.12 | `x509_expired_rejected` | `ProtocolInvariants.lean` | Cert expirado → rejeitado (já parcial, fortalecer) | Médio |
| F10.13 | `downgrade_detection_tls12` | `ProtocolInvariants.lean` | `hasDowngradeSentinel (prefix ++ sentinel12) = true` | Médio |
| F10.14 | `downgrade_detection_tls11` | `ProtocolInvariants.lean` | `hasDowngradeSentinel (prefix ++ sentinel11) = true` | Médio |
| F10.15 | `websocket_mask_involution` | `CompositionProofs.lean` | `unmask(mask(data, key), key) = data` | Médio |

---

## Fase 11 — End-to-End Pipeline (A prova final)

> **Meta:** Provar correctude end-to-end do pipeline TLS → HTTP/2 → App → HTTP/2 → TLS.
> **Estimativa:** 3-5 dias. ~5 teoremas.
> **Impacto:** Fecha o ciclo completo. Publishable result.

| ID | Teorema | Ficheiro | Statement | Dif. |
|----|---------|----------|-----------|------|
| F11.1 | **`tls13_record_roundtrip`** | `CompositionProofs.lean` | `decrypt(encrypt(key, nonce, pt, type)) = some (pt, type)` | Muito Difícil |
| F11.2 | `http2_frame_roundtrip` | `CompositionProofs.lean` | `parseHTTP2Frame(serializeFrame f) = some f` | Difícil |
| F11.3 | `endToEnd_pipeline_roundtrip` | `CompositionProofs.lean` | Pipeline completo: encrypt→parse→process→serialize→decrypt = id | Muito Difícil |
| F11.4 | `pipeline_no_data_loss` | `CompositionProofs.lean` | Nenhum request é perdido no pipeline | Difícil |
| F11.5 | `pipeline_ordering_preserved` | `CompositionProofs.lean` | Ordem dos requests é preservada | Difícil |

---

## Resumo: Prioridade de Implementação

### 🔴 Crítico (Antes de publicar — credibilidade mínima)

| Fase | Teoremas | Dias | Porquê |
|------|----------|------|--------|
| **F1** Fundações | 15 | 2-3 | Sem estes, nada mais é provável |
| **F2** SHA→HMAC→HKDF chain | 12 | 3-5 | Desbloqueia todo o key schedule |
| **F5** Nonce uniqueness real | 8 | 2-3 | Substitui teoremas fracos W2/W3 |
| **F6** Constant-time correctness | 8 | 1-2 | ctEqual reflexive/soundness |
| **F3.1-3.3** S-Box real | 3 | 0.5 | Substitui teorema fraco W1 |

**Subtotal crítico: ~46 teoremas, ~10-15 dias**

### 🟡 Importante (Para paper/publicação séria)

| Fase | Teoremas | Dias | Porquê |
|------|----------|------|--------|
| **F3.4-3.15** AES roundtrip | 12 | 5-8 | Crown jewel crypto |
| **F4** TLS Key Schedule | 10 | 3-4 | Key sizes correctness |
| **F9** Refinement chain | 12 | 4-6 | Publishable at POPL/ITP |
| **F10** Codecs universal | 15 | 3-4 | Elimina dependência de native_decide |

**Subtotal importante: ~49 teoremas, ~15-22 dias**

### 🟢 Ideal (Para nível mundial — seL4/miTLS tier)

| Fase | Teoremas | Dias | Porquê |
|------|----------|------|--------|
| **F7** X25519 DH agreement | 12 | 5-10 | Ninguém tem isto em Lean |
| **F8** RSA-PSS sign/verify | 10 | 3-5 | CertificateVerify completo |
| **F11** End-to-end pipeline | 5 | 3-5 | Fecho total |

**Subtotal ideal: ~27 teoremas, ~11-20 dias**

---

## Total

| Nível | Teoremas | Dias estimados | Resultado |
|-------|----------|---------------|-----------|
| 🔴 Crítico | ~46 | 10-15 | Defensável em peer review |
| 🟡 Importante | ~49 | 15-22 | Publicável em conferência |
| 🟢 Ideal | ~27 | 11-20 | Nível mundial |
| **TOTAL** | **~122** | **36-57** | **935 teoremas actuais** |

---

## Contagem Final Projectada

| Métrica | Actual | Objectivo |
|---------|--------|----------|
| Teoremas totais | 914 | ~1000 |
| Teoremas fracos/vacuous | 0 | 0 |
| Teoremas com `native_decide` only | ~50 | ~50 (+ universais ∀) |
| Codec roundtrip universais | 0 | 4 |
| Crypto roundtrip proofs | 0 | 3 (AES, RSA-PSS, TLS record) |
| Key schedule size proofs (universal) | 0 | ~10 |
| Nonce uniqueness (real) | 0 | 5 |
| DH agreement | 0 | 1 |
| Multi-step simulation | 0 | 1 |
| End-to-end pipeline | 0 | 3 |
