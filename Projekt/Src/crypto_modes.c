#include "crypto_modes.h"
#include "aes.h"
#include "speck.h"
#include "lea.h"
#include "ascon128.h"
#include <string.h>

// ==========================================
// 1. AES-128 IMPLEMENTÁCIÓK (ECB és CTR)
// ==========================================

void bench_aes_ecb_encrypt(const uint8_t key[16], uint8_t *buf, size_t len) {
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    for (size_t i = 0; i < len; i += 16) {
        AES_ECB_encrypt(&ctx, buf + i);
    }
}

void bench_aes_ecb_decrypt(const uint8_t key[16], uint8_t *buf, size_t len) {
    struct AES_ctx ctx;
    AES_init_ctx(&ctx, key);
    for (size_t i = 0; i < len; i += 16) {
        AES_ECB_decrypt(&ctx, buf + i);
    }
}

// AES-CTR: Szimmetrikus folyamat! Titkosítás és Visszafejtés ugyanazt a modult hívja
void bench_aes_ctr_xcrypt(const uint8_t key[16], const uint8_t iv[16], uint8_t *buf, size_t len) {
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CTR_xcrypt_buffer(&ctx, buf, len);
}

// ==========================================
// 2. SPECK-128 IMPLEMENTÁCIÓK
// ==========================================

void bench_speck_ecb_encrypt(const uint8_t key[16], uint8_t *buf, size_t len) {
    u64 K[2], rk[SPECK128_ROUNDS];
    BytesToWords64(key, K, 16);
    Speck128128KeySchedule(K, rk);

    for (size_t i = 0; i < len; i += 16) {
        u64 Pt[2], Ct[2];
        BytesToWords64(buf + i, Pt, 16);
        Speck128128Encrypt(Pt, Ct, rk);
        Words64ToBytes(Ct, buf + i, 2);
    }
}

void bench_speck_ecb_decrypt(const uint8_t key[16], uint8_t *buf, size_t len) {
    u64 K[2], rk[SPECK128_ROUNDS];
    BytesToWords64(key, K, 16);
    Speck128128KeySchedule(K, rk);

    for (size_t i = 0; i < len; i += 16) {
        u64 Ct[2], Pt[2];
        BytesToWords64(buf + i, Ct, 16);
        Speck128128Decrypt(Ct, Pt, rk);
        Words64ToBytes(Pt, buf + i, 2);
    }
}

// ==========================================
// 3. LEA-128 IMPLEMENTÁCIÓK
// ==========================================

void bench_lea_ecb_encrypt(const uint8_t key[16], uint8_t *buf, size_t len) {
    LEA_KEY lea_key;
    lea_set_key(&lea_key, key, 16);
    lea_ecb_encrypt(buf, buf, len, &lea_key);
}

void bench_lea_ecb_decrypt(const uint8_t key[16], uint8_t *buf, size_t len) {
    LEA_KEY lea_key;
    lea_set_key(&lea_key, key, 16);
    lea_ecb_decrypt(buf, buf, len, &lea_key);
}

// ==========================================
// 4. ASCON-128 AEAD IMPLEMENTÁCIÓ
// ==========================================

int bench_ascon_aead_encrypt(const uint8_t key[16], const uint8_t nonce[16],
                             const uint8_t *in, uint8_t *out, size_t len, uint8_t tag[16]) {
    unsigned long long clen;
    // Puffer az ASCON kimenetének (üzenet + 16 bájt TAG)
    uint8_t c_buf[1024 + 16];

    int res = ascon128_aead_encrypt(c_buf, &clen, in, len, NULL, 0, NULL, nonce, key);

    if (res == 0) {
        memcpy(out, c_buf, len);
        memcpy(tag, c_buf + len, 16); // TAG kinyerése
    }
    return res;
}

int bench_ascon_aead_decrypt(const uint8_t key[16], const uint8_t nonce[16],
                             const uint8_t *in, uint8_t *out, size_t len, const uint8_t tag[16]) {
    unsigned long long mlen;
    uint8_t c_buf[1024 + 16];

    memcpy(c_buf, in, len);
    memcpy(c_buf + len, tag, 16); // TAG hozzáfűzése a visszafejtéshez

    return ascon128_aead_decrypt(out, &mlen, NULL, c_buf, len + 16, NULL, 0, nonce, key);
}
