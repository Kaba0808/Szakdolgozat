/*
 * Speck128/128 Reference Implementation
 * Source: NSA SIMON and SPECK Implementation Guide v1.1
 * Section 6: "SPECK128 Reference Code"
 * URL: https://nsacyber.github.io/simon-speck/implementations/ImplementationGuide1.1.pdf
 *
 * Test vectors (Section 16, SPECK128/128 Test Vectors):
 *   pt: 20 6d 61 64 65 20 69 74 20 65 71 75 69 76 61 6c
 *   k:  00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
 *   ct: 18 0d 57 5c df fe 60 78 65 32 78 79 51 98 5d a6
 */

#include "speck.h"

/* --- Byte <-> Word konverzio (Section 1, little-endian) --- */

void Words64ToBytes(const u64 words[], u8 bytes[], int numwords)
{
    int i, j = 0;
    for (i = 0; i < numwords; i++) {
        bytes[j]   = (u8)words[i];
        bytes[j+1] = (u8)(words[i] >> 8);
        bytes[j+2] = (u8)(words[i] >> 16);
        bytes[j+3] = (u8)(words[i] >> 24);
        bytes[j+4] = (u8)(words[i] >> 32);
        bytes[j+5] = (u8)(words[i] >> 40);
        bytes[j+6] = (u8)(words[i] >> 48);
        bytes[j+7] = (u8)(words[i] >> 56);
        j += 8;
    }
}

void BytesToWords64(const u8 bytes[], u64 words[], int numbytes)
{
    int i, j = 0;
    for (i = 0; i < numbytes / 8; i++) {
        words[i] = (u64)bytes[j]
                 | ((u64)bytes[j+1] << 8)
                 | ((u64)bytes[j+2] << 16)
                 | ((u64)bytes[j+3] << 24)
                 | ((u64)bytes[j+4] << 32)
                 | ((u64)bytes[j+5] << 40)
                 | ((u64)bytes[j+6] << 48)
                 | ((u64)bytes[j+7] << 56);
        j += 8;
    }
}

/* --- Key Schedule (Section 6) --- */
/*
 * Speck128/128: K = (K[1], K[0])
 * 32 round key, rk[i] generalaasa:
 *   rk[0] = K[0]
 *   for i = 0..30: ER64(K[1], K[0], i) -> rk[i+1]
 */
void Speck128128KeySchedule(const u64 K[2], u64 rk[SPECK128_ROUNDS])
{
    u64 i, B = K[1], A = K[0];
    for (i = 0; i < 31; ) {
        rk[i] = A;
        ER64(B, A, i++);
    }
    rk[i] = A;
}

/* --- Titkositas (Section 6) --- */
void Speck128128Encrypt(const u64 Pt[2], u64 Ct[2], const u64 rk[SPECK128_ROUNDS])
{
    u64 i;
    Ct[0] = Pt[0]; Ct[1] = Pt[1];
    for (i = 0; i < 32; ) ER64(Ct[1], Ct[0], rk[i++]);
}

/* --- Visszafejtes (Section 6) --- */
void Speck128128Decrypt(const u64 Ct[2], u64 Pt[2], const u64 rk[SPECK128_ROUNDS])
{
    int i;
    Pt[0] = Ct[0]; Pt[1] = Ct[1];
    for (i = 31; i >= 0; ) DR64(Pt[1], Pt[0], rk[i--]);
}

/* --- High-level API (byte tomb) --- */
void speck128_encrypt(const u8 key[16], const u8 plaintext[16], u8 ciphertext[16])
{
    u64 K[2], Pt[2], Ct[2];
    u64 rk[SPECK128_ROUNDS];

    BytesToWords64(key, K, 16);
    BytesToWords64(plaintext, Pt, 16);
    Speck128128KeySchedule(K, rk);
    Speck128128Encrypt(Pt, Ct, rk);
    Words64ToBytes(Ct, ciphertext, 2);
}

void speck128_decrypt(const u8 key[16], const u8 ciphertext[16], u8 plaintext[16])
{
    u64 K[2], Ct[2], Pt[2];
    u64 rk[SPECK128_ROUNDS];

    BytesToWords64(key, K, 16);
    BytesToWords64(ciphertext, Ct, 16);
    Speck128128KeySchedule(K, rk);
    Speck128128Decrypt(Ct, Pt, rk);
    Words64ToBytes(Pt, plaintext, 2);
}
