/**
  ******************************************************************************
  * @file           : ascon128.c
  * @brief          : ASCON-128 AEAD titkositas es visszafejtes
  *
  * A hivatalos Ascon v1.2 referencia-implementacio (ascon-c, crypto_aead/
  * ascon128v12/ref) alapjan, a hibakereso kiirasok nelkul. Helyesseg: a
  * tervezok LWC_AEAD_KAT_128_128.txt fajljanak mind az 1089 tesztvektora.
  ******************************************************************************
  */
#include "ascon128.h"
#include <stdint.h>

/* Inicializalas: S = IV || K || N, p^12, majd S ^= 0^192 || K */
static void ascon_init(ascon_state_t *s, uint64_t K0, uint64_t K1,
                       const uint8_t *npub) {
    s->x[0] = ASCON_128_IV;
    s->x[1] = K0;
    s->x[2] = K1;
    s->x[3] = LOADBYTES(npub, 8);
    s->x[4] = LOADBYTES(npub + 8, 8);
    P12(s);
    s->x[3] ^= K0;
    s->x[4] ^= K1;
}

/* Kapcsolodo adat feldolgozasa, majd tartomany-elvalasztas.
 * Ures AD eseten a specifikacio szerint nincs feldolgozas (1.4.1. szakasz). */
static void ascon_absorb_ad(ascon_state_t *s, const uint8_t *ad,
                            unsigned long long adlen) {
    if (adlen > 0) {
        while (adlen >= ASCON_128_RATE) {
            s->x[0] ^= LOADBYTES(ad, 8);
            P6(s);
            ad += ASCON_128_RATE;
            adlen -= ASCON_128_RATE;
        }
        s->x[0] ^= LOADBYTES(ad, (int)adlen);
        s->x[0] ^= PAD((int)adlen);
        P6(s);
    }
    s->x[4] ^= 1u;   /* domain separation */
}

/* Veglegesites: S ^= 0^64 || K || 0^128, p^12, cimke = S[192..319] ^ K */
static void ascon_finalize(ascon_state_t *s, uint64_t K0, uint64_t K1) {
    s->x[1] ^= K0;
    s->x[2] ^= K1;
    P12(s);
    s->x[3] ^= K0;
    s->x[4] ^= K1;
}

int ascon128_aead_encrypt(uint8_t *c, unsigned long long *clen,
                          const uint8_t *m, unsigned long long mlen,
                          const uint8_t *ad, unsigned long long adlen,
                          const uint8_t *nsec, const uint8_t *npub,
                          const uint8_t *k) {
    const uint64_t K0 = LOADBYTES(k, 8);
    const uint64_t K1 = LOADBYTES(k + 8, 8);
    ascon_state_t s;

    (void)nsec;
    *clen = mlen + ASCON128_ABYTES;

    ascon_init(&s, K0, K1, npub);
    ascon_absorb_ad(&s, ad, adlen);

    /* Teljes nyiltszoveg-blokkok: C_i = S_r ^ P_i, majd p^6 */
    while (mlen >= ASCON_128_RATE) {
        s.x[0] ^= LOADBYTES(m, 8);
        STOREBYTES(c, s.x[0], 8);
        P6(&s);
        m += ASCON_128_RATE;
        c += ASCON_128_RATE;
        mlen -= ASCON_128_RATE;
    }
    /* Utolso (reszleges vagy ures) blokk kiegeszitessel, permutacio nelkul */
    s.x[0] ^= LOADBYTES(m, (int)mlen);
    STOREBYTES(c, s.x[0], (int)mlen);
    s.x[0] ^= PAD((int)mlen);
    c += mlen;

    ascon_finalize(&s, K0, K1);

    /* 128 bites hitelesito cimke */
    STOREBYTES(c, s.x[3], 8);
    STOREBYTES(c + 8, s.x[4], 8);
    return 0;
}

int ascon128_aead_decrypt(uint8_t *m, unsigned long long *mlen,
                          uint8_t *nsec, const uint8_t *c,
                          unsigned long long clen, const uint8_t *ad,
                          unsigned long long adlen, const uint8_t *npub,
                          const uint8_t *k) {
    const uint64_t K0 = LOADBYTES(k, 8);
    const uint64_t K1 = LOADBYTES(k + 8, 8);
    unsigned long long remaining;
    const uint8_t *tag;
    uint8_t t[ASCON128_ABYTES];
    ascon_state_t s;
    uint8_t diff = 0;

    (void)nsec;
    if (clen < ASCON128_ABYTES) {
        return -1;
    }
    *mlen = clen - ASCON128_ABYTES;
    remaining = *mlen;
    tag = c + *mlen;

    ascon_init(&s, K0, K1, npub);
    ascon_absorb_ad(&s, ad, adlen);

    /* Teljes blokkok: P_i = S_r ^ C_i, majd S_r = C_i es p^6 */
    while (remaining >= ASCON_128_RATE) {
        uint64_t c0 = LOADBYTES(c, 8);
        STOREBYTES(m, s.x[0] ^ c0, 8);
        s.x[0] = c0;
        P6(&s);
        m += ASCON_128_RATE;
        c += ASCON_128_RATE;
        remaining -= ASCON_128_RATE;
    }
    /* Utolso blokk */
    {
        uint64_t c0 = LOADBYTES(c, (int)remaining);
        STOREBYTES(m, s.x[0] ^ c0, (int)remaining);
        s.x[0] = CLEARBYTES(s.x[0], (int)remaining);
        s.x[0] |= c0;
        s.x[0] ^= PAD((int)remaining);
    }

    ascon_finalize(&s, K0, K1);

    /* Cimke-ellenorzes konstans idoben (nincs korai kilepes) */
    STOREBYTES(t, s.x[3], 8);
    STOREBYTES(t + 8, s.x[4], 8);
    for (int i = 0; i < ASCON128_ABYTES; ++i) {
        diff |= (uint8_t)(t[i] ^ tag[i]);
    }
    return (diff == 0) ? 0 : -1;
}
