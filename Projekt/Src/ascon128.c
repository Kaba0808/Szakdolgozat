/**
  ******************************************************************************
  * @file           : ascon128.c
  * @brief          : ASCON-128 AEAD - standardized types for ARM Cortex-M4
  ******************************************************************************
  */
#include "ascon128.h"
#include <stdint.h>
#include <string.h>

int ascon128_aead_encrypt(uint8_t *c, unsigned long long *clen,
                          const uint8_t *m, unsigned long long mlen,
                          const uint8_t *ad, unsigned long long adlen,
                          const uint8_t *nsec, const uint8_t *npub,
                          const uint8_t *k) {
    const uint64_t K0 = LOADBYTES(k, 8);
    const uint64_t K1 = LOADBYTES(k + 8, 8);
    const uint64_t N0 = LOADBYTES(npub, 8);
    const uint64_t N1 = LOADBYTES(npub + 8, 8);
    ascon_state_t s;

    (void)nsec;

    *clen = mlen + ASCON128_ABYTES;

    s.x[0] = ASCON_128_IV;
    s.x[1] = K0;
    s.x[2] = K1;
    s.x[3] = N0;
    s.x[4] = N1;
    P12(&s);
    s.x[3] ^= K0;
    s.x[4] ^= K1;

    while (adlen >= ASCON_128_RATE) {
        s.x[0] ^= LOADBYTES(ad, 8);
        P6(&s);
        ad += ASCON_128_RATE;
        adlen -= ASCON_128_RATE;
    }
    s.x[0] ^= LOADBYTES(ad, (int)adlen);
    s.x[0] ^= PAD((int)adlen);
    P6(&s);
    s.x[4] ^= DSEP();

    while (mlen >= ASCON_128_RATE) {
        s.x[0] ^= LOADBYTES(m, 8);
        STOREBYTES(c, s.x[0], 8);
        P6(&s);
        m += ASCON_128_RATE;
        c += ASCON_128_RATE;
        mlen -= ASCON_128_RATE;
    }

    s.x[0] ^= LOADBYTES(m, (int)mlen);
    STOREBYTES(c, s.x[0], (int)mlen);
    s.x[0] ^= PAD((int)mlen);
    c += mlen;

    s.x[1] ^= K0;
    s.x[2] ^= K1;
    P12(&s);
    s.x[3] ^= K0;
    s.x[4] ^= K1;

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
    const uint64_t N0 = LOADBYTES(npub, 8);
    const uint64_t N1 = LOADBYTES(npub + 8, 8);
    const uint8_t *tag;
    unsigned long long remaining;
    ascon_state_t s;
    int i;
    int diff = 0;
    uint8_t t[ASCON128_ABYTES];

    (void)nsec;

    if (clen < ASCON128_ABYTES) {
        return -1;
    }

    *mlen = clen - ASCON128_ABYTES;
    tag = c + *mlen;
    remaining = *mlen;

    s.x[0] = ASCON_128_IV;
    s.x[1] = K0;
    s.x[2] = K1;
    s.x[3] = N0;
    s.x[4] = N1;
    P12(&s);
    s.x[3] ^= K0;
    s.x[4] ^= K1;

    while (adlen >= ASCON_128_RATE) {
        s.x[0] ^= LOADBYTES(ad, 8);
        P6(&s);
        ad += ASCON_128_RATE;
        adlen -= ASCON_128_RATE;
    }
    s.x[0] ^= LOADBYTES(ad, (int)adlen);
    s.x[0] ^= PAD((int)adlen);
    P6(&s);
    s.x[4] ^= DSEP();

    while (remaining >= ASCON_128_RATE) {
        uint64_t c0 = LOADBYTES(c, 8);
        STOREBYTES(m, s.x[0] ^ c0, 8);
        s.x[0] = c0;
        P6(&s);
        m += ASCON_128_RATE;
        c += ASCON_128_RATE;
        remaining -= ASCON_128_RATE;
    }

    {
        uint64_t c0 = LOADBYTES(c, (int)remaining);
        STOREBYTES(m, s.x[0] ^ c0, (int)remaining);
        s.x[0] = CLEARBYTES(s.x[0], (int)remaining);
        s.x[0] |= c0;
        s.x[0] ^= PAD((int)remaining);
    }

    s.x[1] ^= K0;
    s.x[2] ^= K1;
    P12(&s);
    s.x[3] ^= K0;
    s.x[4] ^= K1;

    STOREBYTES(t, s.x[3], 8);
    STOREBYTES(t + 8, s.x[4], 8);

    for (i = 0; i < ASCON128_ABYTES; ++i) {
        diff |= (int)(t[i] ^ tag[i]);
    }

    return diff == 0 ? 0 : -1;
}
