#ifndef SPECK_H
#define SPECK_H

/*
 * Speck128/128 Reference Implementation
 * Source: NSA SIMON and SPECK Implementation Guide v1.1
 * Authors: Ray Beaulieu, Douglas Shors, Jason Smith,
 *          Stefan Treatman-Clark, Bryan Weeks, Louis Wingers
 * URL: https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf
 * Date: January 15, 2019
 *
 * A szakdolgozati benchmarkhoz a 6. fejezetbol (SPECK128 Reference Code)
 * szarmazo tiszta C, platformfuggetlen implementacio.
 */

#include <stdint.h>

#define u8  uint8_t
#define u32 uint32_t
#define u64 uint64_t

/* Bit rotations (Section 1 of Implementation Guide) */
#define ROTL64(x,r) (((x)<<(r)) | ((x)>>(64-(r))))
#define ROTR64(x,r) (((x)>>(r)) | ((x)<<(64-(r))))

/* Round function macros (Section 6 of Implementation Guide) */
#define ER64(x,y,k) (x=ROTR64(x,8), x+=y, x^=(k), y=ROTL64(y,3), y^=x)
#define DR64(x,y,k) (y^=x, y=ROTR64(y,3), x^=(k), x-=y, x=ROTL64(x,8))

/* Speck128/128: 128-bit block, 128-bit key, 32 rounds */
#define SPECK128_ROUNDS     32
#define SPECK128_BLOCK_SIZE 16
#define SPECK128_KEY_SIZE   16

/* Low-level word-based API */
void Speck128128KeySchedule(const u64 K[2], u64 rk[SPECK128_ROUNDS]);
void Speck128128Encrypt(const u64 Pt[2], u64 Ct[2], const u64 rk[SPECK128_ROUNDS]);
void Speck128128Decrypt(const u64 Ct[2], u64 Pt[2], const u64 rk[SPECK128_ROUNDS]);

/* Byte konverzios fuggvenyek (Section 1) */
void Words64ToBytes(const u64 words[], u8 bytes[], int numwords);
void BytesToWords64(const u8 bytes[], u64 words[], int numbytes);

/* High-level byte-tomb API */
void speck128_encrypt(const u8 key[16], const u8 plaintext[16], u8 ciphertext[16]);
void speck128_decrypt(const u8 key[16], const u8 ciphertext[16], u8 plaintext[16]);

#endif /* SPECK_H */
