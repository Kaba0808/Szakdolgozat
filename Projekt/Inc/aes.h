#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>
#include <stddef.h>

// --- ÜZEMMÓDOK ÉS KULCSMÉRET FIX BEÁLLÍTÁSA ---
#define ECB 1
#define CBC 1
#define CTR 1
#define AES128 1

#define AES_BLOCKLEN 16 // Blokkméret bájtban (AES esetén mindig 16 bájt)
#define AES_KEYLEN 16   // Kulcsméret bájtban (128 bit = 16 bájt)
#define AES_keyExpSize 176 // Kiterjesztett kulcs mérete

struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
  uint8_t Iv[AES_BLOCKLEN];
};

// --- INICIALIZÁLÓ FÜGGVÉNYEK ---
void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);

// --- ECB ÜZEMMÓD ---
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf);

// --- CBC ÜZEMMÓD ---
void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

// --- CTR (COUNTER) ÜZEMMÓD ---
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length);

#endif // _AES_H_
