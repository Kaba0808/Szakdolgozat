#ifndef ASCON128_H_
#define ASCON128_H_

#include <stdint.h>

#define ASCON128_KEYBYTES 16
#define ASCON128_NSECBYTES 0
#define ASCON128_NPUBBYTES 16
#define ASCON128_ABYTES 16

#define ASCON_AEAD_VARIANT 1u
#define ASCON_TAG_SIZE 16u
#define ASCON_128_RATE 8u
#define ASCON_PA_ROUNDS 12u
#define ASCON_128_PB_ROUNDS 6u

#define ASCON_128_IV \
    (((uint64_t)(ASCON_AEAD_VARIANT) << 0) | \
     ((uint64_t)(ASCON_PA_ROUNDS) << 16) | \
     ((uint64_t)(ASCON_128_PB_ROUNDS) << 20) | \
     ((uint64_t)(ASCON_TAG_SIZE * 8u) << 24) | \
     ((uint64_t)(ASCON_128_RATE) << 40))

typedef struct {
    uint64_t x[5];
} ascon_state_t;

#define GETBYTE(x, i) ((uint8_t)((uint64_t)(x) >> (8 * (i))))
#define SETBYTE(b, i) ((uint64_t)(b) << (8 * (i)))
#define PAD(i) SETBYTE(0x01u, (i))
#define DSEP() SETBYTE(0x80u, 7)

static inline uint64_t LOADBYTES(const uint8_t *bytes, int n) {
    int i;
    uint64_t x = 0;
    for (i = 0; i < n; ++i) {
        x |= SETBYTE(bytes[i], i);
    }
    return x;
}

static inline void STOREBYTES(uint8_t *bytes, uint64_t x, int n) {
    int i;
    for (i = 0; i < n; ++i) {
        bytes[i] = GETBYTE(x, i);
    }
}

static inline uint64_t CLEARBYTES(uint64_t x, int n) {
    int i;
    for (i = 0; i < n; ++i) {
        x &= ~SETBYTE(0xffu, i);
    }
    return x;
}

static inline uint64_t ROR64(uint64_t x, int n) {
    return (x >> n) | (x << ((-n) & 63));
}

static inline void ROUND(ascon_state_t *s, uint8_t c) {
    ascon_state_t t;

    s->x[2] ^= c;

    s->x[0] ^= s->x[4];
    s->x[4] ^= s->x[3];
    s->x[2] ^= s->x[1];

    t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
    t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
    t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
    t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
    t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);

    t.x[1] ^= t.x[0];
    t.x[0] ^= t.x[4];
    t.x[3] ^= t.x[2];
    t.x[2] = ~t.x[2];

    s->x[0] = t.x[0] ^ ROR64(t.x[0], 19) ^ ROR64(t.x[0], 28);
    s->x[1] = t.x[1] ^ ROR64(t.x[1], 61) ^ ROR64(t.x[1], 39);
    s->x[2] = t.x[2] ^ ROR64(t.x[2], 1) ^ ROR64(t.x[2], 6);
    s->x[3] = t.x[3] ^ ROR64(t.x[3], 10) ^ ROR64(t.x[3], 17);
    s->x[4] = t.x[4] ^ ROR64(t.x[4], 7) ^ ROR64(t.x[4], 41);
}

static inline void P12(ascon_state_t *s) {
    ROUND(s, 0xf0);
    ROUND(s, 0xe1);
    ROUND(s, 0xd2);
    ROUND(s, 0xc3);
    ROUND(s, 0xb4);
    ROUND(s, 0xa5);
    ROUND(s, 0x96);
    ROUND(s, 0x87);
    ROUND(s, 0x78);
    ROUND(s, 0x69);
    ROUND(s, 0x5a);
    ROUND(s, 0x4b);
}

static inline void P6(ascon_state_t *s) {
    ROUND(s, 0x96);
    ROUND(s, 0x87);
    ROUND(s, 0x78);
    ROUND(s, 0x69);
    ROUND(s, 0x5a);
    ROUND(s, 0x4b);
}

int ascon128_aead_encrypt(unsigned char *c, unsigned long long *clen,
                          const unsigned char *m, unsigned long long mlen,
                          const unsigned char *ad, unsigned long long adlen,
                          const unsigned char *nsec, const unsigned char *npub,
                          const unsigned char *k);

int ascon128_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                          unsigned char *nsec, const unsigned char *c,
                          unsigned long long clen, const unsigned char *ad,
                          unsigned long long adlen, const unsigned char *npub,
                          const unsigned char *k);

#endif
