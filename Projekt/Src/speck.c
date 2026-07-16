/**
  ******************************************************************************
  * @file           : speck.c
  * @brief          : Speck128/128 - standardized and memory-aligned for STM32
  ******************************************************************************
  */
#include "speck.h"
#include <stdint.h>
#include <string.h>

void Words64ToBytes(const uint64_t words[], uint8_t bytes[], int numwords)
{
    memcpy(bytes, words, numwords * 8);
}

void BytesToWords64(const uint8_t bytes[], uint64_t words[], int numbytes)
{
    memcpy(words, bytes, numbytes);
}

void Speck128128KeySchedule(const uint64_t K[2], uint64_t rk[SPECK128_ROUNDS])
{
    uint64_t i;
    uint64_t B = K[1];
    uint64_t A = K[0];
    for (i = 0; i < 31; ) {
        rk[i] = A;
        ER64(B, A, i++);
    }
    rk[i] = A;
}

void Speck128128Encrypt(const uint64_t Pt[2], uint64_t Ct[2], const uint64_t rk[SPECK128_ROUNDS])
{
    uint64_t i;
    Ct[0] = Pt[0];
    Ct[1] = Pt[1];
    for (i = 0; i < 32; ) {
        ER64(Ct[1], Ct[0], rk[i++]);
    }
}

void Speck128128Decrypt(const uint64_t Ct[2], uint64_t Pt[2], const uint64_t rk[SPECK128_ROUNDS])
{
    int i;
    Pt[0] = Ct[0];
    Pt[1] = Ct[1];
    for (i = 31; i >= 0; ) {
        DR64(Pt[1], Pt[0], rk[i--]);
    }
}

void speck128_encrypt_block(const uint8_t plaintext[16], uint8_t ciphertext[16], const uint64_t rk[SPECK128_ROUNDS])
{
    uint64_t Pt[2], Ct[2];
    memcpy(Pt, plaintext, 16);
    Speck128128Encrypt(Pt, Ct, rk);
    memcpy(ciphertext, Ct, 16);
}

void speck128_decrypt_block(const uint8_t ciphertext[16], uint8_t plaintext[16], const uint64_t rk[SPECK128_ROUNDS])
{
    uint64_t Ct[2], Pt[2];
    memcpy(Ct, ciphertext, 16);
    Speck128128Decrypt(Ct, Pt, rk);
    memcpy(plaintext, Pt, 16);
}
