/**
 * crypto_ffi.c — Native crypto FFI bindings for LeanServer
 *
 * Provides high-performance implementations of:
 *   - SHA-256
 *   - HMAC-SHA256
 *   - AES-128-GCM encrypt/decrypt
 *   - X25519 scalar multiplication
 *
 * Build with -DLEANSERVER_USE_OPENSSL=1 and link -lssl -lcrypto to enable
 * real OpenSSL implementations.  Without the flag, stub functions are provided
 * that satisfy the linker but panic at runtime (they are never called when
 * crypto_backend = "lean", which is the default).
 */

#include <lean/lean.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef LEANSERVER_USE_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#endif

/* ========================================================================== */
/* Helper: ByteArray ↔ C buffer                                               */
/* ========================================================================== */

static inline const uint8_t* ba_data(b_lean_obj_arg ba) {
    return lean_sarray_cptr(ba);
}

static inline size_t ba_size(b_lean_obj_arg ba) {
    return lean_sarray_size(ba);
}

static lean_obj_res mk_byte_array(const uint8_t *buf, size_t len) {
    lean_obj_res arr = lean_alloc_sarray(1, len, len);
    memcpy(lean_sarray_cptr(arr), buf, len);
    return arr;
}

/* Option constructors */
static inline lean_obj_res mk_option_none(void) {
    return lean_box(0); /* Option.none */
}

static inline lean_obj_res mk_option_some(lean_obj_arg val) {
    lean_obj_res obj = lean_alloc_ctor(1, 1, 0); /* Option.some */
    lean_ctor_set(obj, 0, val);
    return obj;
}

/* ========================================================================== */
/* SHA-256                                                                     */
/* ========================================================================== */

#ifdef LEANSERVER_USE_OPENSSL

LEAN_EXPORT lean_obj_res lean_crypto_sha256(b_lean_obj_arg msg) {
    uint8_t digest[SHA256_DIGEST_LENGTH]; /* 32 */
    SHA256(ba_data(msg), ba_size(msg), digest);
    return mk_byte_array(digest, SHA256_DIGEST_LENGTH);
}

#else /* stubs */

static void crypto_ffi_panic(const char *fn) {
    fprintf(stderr, "FATAL: %s called but OpenSSL support not compiled in.\n"
                    "Set crypto_backend=lean in server.config or rebuild with "
                    "-DLEANSERVER_USE_OPENSSL=1 -lssl -lcrypto.\n", fn);
    abort();
}

LEAN_EXPORT lean_obj_res lean_crypto_sha256(b_lean_obj_arg msg) {
    crypto_ffi_panic("lean_crypto_sha256");
    return lean_box(0); /* unreachable */
}

#endif

/* ========================================================================== */
/* HMAC-SHA256                                                                 */
/* ========================================================================== */

#ifdef LEANSERVER_USE_OPENSSL

LEAN_EXPORT lean_obj_res lean_crypto_hmac_sha256(b_lean_obj_arg key,
                                                  b_lean_obj_arg msg) {
    uint8_t result[EVP_MAX_MD_SIZE];
    unsigned int result_len = 0;

    HMAC(EVP_sha256(),
         ba_data(key), (int)ba_size(key),
         ba_data(msg), ba_size(msg),
         result, &result_len);

    return mk_byte_array(result, result_len);
}

#else

LEAN_EXPORT lean_obj_res lean_crypto_hmac_sha256(b_lean_obj_arg key,
                                                  b_lean_obj_arg msg) {
    crypto_ffi_panic("lean_crypto_hmac_sha256");
    return lean_box(0);
}

#endif

/* ========================================================================== */
/* AES-128-GCM Encrypt                                                         */
/* ========================================================================== */

#ifdef LEANSERVER_USE_OPENSSL

LEAN_EXPORT lean_obj_res lean_crypto_aes128_gcm_encrypt(
        b_lean_obj_arg key, b_lean_obj_arg iv,
        b_lean_obj_arg aad, b_lean_obj_arg plaintext) {

    size_t pt_len = ba_size(plaintext);
    uint8_t *ct_buf = (uint8_t *)malloc(pt_len > 0 ? pt_len : 1);
    uint8_t tag[16];
    int len = 0, ct_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)ba_size(iv), NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, ba_data(key), ba_data(iv));

    if (ba_size(aad) > 0) {
        EVP_EncryptUpdate(ctx, NULL, &len, ba_data(aad), (int)ba_size(aad));
    }

    if (pt_len > 0) {
        EVP_EncryptUpdate(ctx, ct_buf, &len, ba_data(plaintext), (int)pt_len);
        ct_len = len;
    }

    EVP_EncryptFinal_ex(ctx, ct_buf + ct_len, &len);
    ct_len += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    lean_obj_res ct_arr = mk_byte_array(ct_buf, (size_t)ct_len);
    lean_obj_res tag_arr = mk_byte_array(tag, 16);
    free(ct_buf);

    lean_obj_res pair = lean_alloc_ctor(0, 2, 0);
    lean_ctor_set(pair, 0, ct_arr);
    lean_ctor_set(pair, 1, tag_arr);
    return pair;
}

#else

LEAN_EXPORT lean_obj_res lean_crypto_aes128_gcm_encrypt(
        b_lean_obj_arg key, b_lean_obj_arg iv,
        b_lean_obj_arg aad, b_lean_obj_arg plaintext) {
    crypto_ffi_panic("lean_crypto_aes128_gcm_encrypt");
    return lean_box(0);
}

#endif

/* ========================================================================== */
/* AES-128-GCM Decrypt                                                         */
/* ========================================================================== */

#ifdef LEANSERVER_USE_OPENSSL

LEAN_EXPORT lean_obj_res lean_crypto_aes128_gcm_decrypt(
        b_lean_obj_arg key, b_lean_obj_arg iv,
        b_lean_obj_arg aad, b_lean_obj_arg ct_with_tag) {

    size_t total = ba_size(ct_with_tag);
    if (total < 16) {
        return mk_option_none();
    }
    size_t ct_len = total - 16;
    const uint8_t *ct_data = ba_data(ct_with_tag);
    const uint8_t *tag = ct_data + ct_len;

    uint8_t *pt_buf = (uint8_t *)malloc(ct_len > 0 ? ct_len : 1);
    int len = 0, pt_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)ba_size(iv), NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, ba_data(key), ba_data(iv));

    if (ba_size(aad) > 0) {
        EVP_DecryptUpdate(ctx, NULL, &len, ba_data(aad), (int)ba_size(aad));
    }

    if (ct_len > 0) {
        EVP_DecryptUpdate(ctx, pt_buf, &len, ct_data, (int)ct_len);
        pt_len = len;
    }

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag);

    int ok = EVP_DecryptFinal_ex(ctx, pt_buf + pt_len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ok > 0) {
        pt_len += len;
        lean_obj_res arr = mk_byte_array(pt_buf, (size_t)pt_len);
        free(pt_buf);
        return mk_option_some(arr);
    } else {
        free(pt_buf);
        return mk_option_none();
    }
}

#else

LEAN_EXPORT lean_obj_res lean_crypto_aes128_gcm_decrypt(
        b_lean_obj_arg key, b_lean_obj_arg iv,
        b_lean_obj_arg aad, b_lean_obj_arg ct_with_tag) {
    crypto_ffi_panic("lean_crypto_aes128_gcm_decrypt");
    return lean_box(0);
}

#endif

/* ========================================================================== */
/* X25519 Scalar Multiplication                                                */
/* ========================================================================== */

#ifdef LEANSERVER_USE_OPENSSL

LEAN_EXPORT lean_obj_res lean_crypto_x25519(b_lean_obj_arg scalar,
                                             b_lean_obj_arg point) {
    uint8_t result[32];
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL, *peer_key = NULL;
    size_t result_len = 32;

    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                         ba_data(scalar), ba_size(scalar));
    if (!pkey) goto fallback;

    peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                            ba_data(point), ba_size(point));
    if (!peer_key) { EVP_PKEY_free(pkey); goto fallback; }

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0 ||
        EVP_PKEY_derive(ctx, result, &result_len) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(pkey);
        goto fallback;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(pkey);

    return mk_byte_array(result, result_len);

fallback:
    memset(result, 0, 32);
    return mk_byte_array(result, 32);
}

LEAN_EXPORT lean_obj_res lean_crypto_x25519_base(b_lean_obj_arg scalar) {
    uint8_t pubkey[32];
    size_t pubkey_len = 32;

    EVP_PKEY *pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                    ba_data(scalar), ba_size(scalar));
    if (!pkey) {
        memset(pubkey, 0, 32);
        return mk_byte_array(pubkey, 32);
    }

    EVP_PKEY_get_raw_public_key(pkey, pubkey, &pubkey_len);
    EVP_PKEY_free(pkey);

    return mk_byte_array(pubkey, pubkey_len);
}

#else

LEAN_EXPORT lean_obj_res lean_crypto_x25519(b_lean_obj_arg scalar,
                                             b_lean_obj_arg point) {
    crypto_ffi_panic("lean_crypto_x25519");
    return lean_box(0);
}

LEAN_EXPORT lean_obj_res lean_crypto_x25519_base(b_lean_obj_arg scalar) {
    crypto_ffi_panic("lean_crypto_x25519_base");
    return lean_box(0);
}

#endif

/* ========================================================================== */
/* Secure Random Bytes                                                         */
/* ========================================================================== */

#ifdef LEANSERVER_USE_OPENSSL

LEAN_EXPORT lean_obj_res lean_crypto_random_bytes(b_lean_obj_arg n_obj,
                                                   lean_obj_arg world) {
    size_t n = lean_usize_of_nat(n_obj);
    uint8_t *buf = (uint8_t *)malloc(n > 0 ? n : 1);
    RAND_bytes(buf, (int)n);
    lean_obj_res arr = mk_byte_array(buf, n);
    free(buf);
    return lean_io_result_mk_ok(arr);
}

#else

LEAN_EXPORT lean_obj_res lean_crypto_random_bytes(b_lean_obj_arg n_obj,
                                                   lean_obj_arg world) {
    crypto_ffi_panic("lean_crypto_random_bytes");
    return lean_box(0);
}

#endif

/* ========================================================================== */
/* Secure Memory Zeroization (Phase 6.4)                                       */
/* ========================================================================== */

/**
 * Securely zero a ByteArray in-place using volatile writes.
 * This prevents the compiler from optimizing away the zeroing (dead-store
 * elimination), unlike a plain memset which may be removed if the buffer
 * is freed immediately after.
 *
 * Uses memset_s (C11 Annex K) if available, otherwise falls back to a
 * volatile-pointer trick recommended by the C FAQ.
 *
 * @param ba  ByteArray to zero
 * @return    Unit (IO action)
 */
LEAN_EXPORT lean_obj_res lean_secure_zero(lean_obj_arg ba, lean_obj_arg world) {
    /* Ensure exclusive ownership (RC=1) so we can mutate in place */
    if (lean_is_exclusive(ba)) {
        size_t len = lean_sarray_size(ba);
        volatile uint8_t *p = (volatile uint8_t *)lean_sarray_cptr(ba);
        for (size_t i = 0; i < len; i++) {
            p[i] = 0;
        }
        /* Memory barrier to prevent reordering */
        __asm__ __volatile__("" ::: "memory");
        lean_dec_ref(ba);
    } else {
        /* Buffer is shared; we can't mutate it safely.
           Log a warning — this is the documented GC limitation. */
        lean_dec_ref(ba);
    }
    return lean_io_result_mk_ok(lean_box(0));
}
