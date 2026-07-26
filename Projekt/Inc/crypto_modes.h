#ifndef CRYPTO_MODES_H
#define CRYPTO_MODES_H

#include <stdint.h>
#include <stddef.h>

// Standardizált paraméterek mind a 4 algoritmushoz
#define BENCH_KEY_SIZE   16  // 128 bit
#define BENCH_NONCE_SIZE 16  // 128 bit IV / Nonce

// --- AES Wrappers ---
void bench_aes_ecb_encrypt(const uint8_t key[16], uint8_t *buf, size_t len);
void bench_aes_ecb_decrypt(const uint8_t key[16], uint8_t *buf, size_t len);
void bench_aes_ctr_xcrypt(const uint8_t key[16], const uint8_t iv[16], uint8_t *buf, size_t len);

// --- SPECK-128 Wrappers ---
void bench_speck_ecb_encrypt(const uint8_t key[16], uint8_t *buf, size_t len);
void bench_speck_ecb_decrypt(const uint8_t key[16], uint8_t *buf, size_t len);

// --- LEA-128 Wrappers ---
void bench_lea_ecb_encrypt(const uint8_t key[16], uint8_t *buf, size_t len);
void bench_lea_ecb_decrypt(const uint8_t key[16], uint8_t *buf, size_t len);

// --- ASCON-128 AEAD Wrapper ---
int bench_ascon_aead_encrypt(const uint8_t key[16], const uint8_t nonce[16],
                             const uint8_t *in, uint8_t *out, size_t len, uint8_t tag[16]);
int bench_ascon_aead_decrypt(const uint8_t key[16], const uint8_t nonce[16],
                             const uint8_t *in, uint8_t *out, size_t len, const uint8_t tag[16]);

#endif // CRYPTO_MODES_H
