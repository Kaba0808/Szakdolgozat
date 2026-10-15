/**
  ******************************************************************************
  * @file           : ascon128.h
  * @brief          : ASCON-128 AEAD (Ascon v1.2 specifikacio szerint)
  *
  * Parameterek (Dobraunig et al., Ascon v1.2, 1. tablazat):
  *   kulcs 128 bit, nonce 128 bit, cimke 128 bit,
  *   rate r = 64 bit (8 bajt), a = 12 kor, b = 6 kor.
  *
  * Bajtsorrend: a specifikacio szerint big-endian, vagyis a bemenet elso
  * bajtja a 64 bites allapotszo legfelso bajtjaba kerul.
  ******************************************************************************
  */
#ifndef ASCON128_H_
#define ASCON128_H_

#include <stdint.h>

/* --- API meretek (bajt) --- */
#define ASCON128_KEYBYTES   16
#define ASCON128_NSECBYTES  0
#define ASCON128_NPUBBYTES  16
#define ASCON128_ABYTES     16   /* hitelesito cimke merete */

/* --- Algoritmus-parameterek --- */
#define ASCON_128_RATE       8u  /* r = 64 bit */
#define ASCON_PA_ROUNDS      12u /* a: inicializalas es veglegesites */
#define ASCON_128_PB_ROUNDS  6u  /* b: adatfeldolgozas */

/* Kezdoertek: k || r || a || b || 0*  = 0x80400c0600000000 */
#define ASCON_128_IV                                  \
    (((uint64_t)(ASCON128_KEYBYTES * 8u) << 56) |     \
     ((uint64_t)(ASCON_128_RATE * 8u)    << 48) |     \
     ((uint64_t)(ASCON_PA_ROUNDS)        << 40) |     \
     ((uint64_t)(ASCON_128_PB_ROUNDS)    << 32))

/* 320 bites belso allapot: ot 64 bites szo */
typedef struct {
    uint64_t x[5];
} ascon_state_t;

/* --- Bajt <-> szo konverzio (big-endian) --- */
#define GETBYTE(x, i) ((uint8_t)((uint64_t)(x) >> (56 - 8 * (i))))
#define SETBYTE(b, i) ((uint64_t)(b) << (56 - 8 * (i)))
#define PAD(i)        SETBYTE(0x80u, (i))   /* 1 || 0* kiegeszites */

static inline uint64_t LOADBYTES(const uint8_t *bytes, int n) {
    uint64_t x = 0;
    for (int i = 0; i < n; ++i) {
        x |= SETBYTE(bytes[i], i);
    }
    return x;
}

static inline void STOREBYTES(uint8_t *bytes, uint64_t x, int n) {
    for (int i = 0; i < n; ++i) {
        bytes[i] = GETBYTE(x, i);
    }
}

static inline uint64_t CLEARBYTES(uint64_t x, int n) {
    for (int i = 0; i < n; ++i) {
        x &= ~SETBYTE(0xffu, i);
    }
    return x;
}

static inline uint64_t ROR64(uint64_t x, int n) {
    return (x >> n) | (x << ((-n) & 63));
}

/* --- Az ASCON-permutacio egy kore --- */
static inline void ROUND(ascon_state_t *s, uint8_t c) {
    ascon_state_t t;

    /* 1. korkonstans hozzaadasa */
    s->x[2] ^= c;

    /* 2. helyettesito reteg: 5 bites S-box, bitsliced alakban */
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

    /* 3. linearis diffuzios reteg */
    s->x[0] = t.x[0] ^ ROR64(t.x[0], 19) ^ ROR64(t.x[0], 28);
    s->x[1] = t.x[1] ^ ROR64(t.x[1], 61) ^ ROR64(t.x[1], 39);
    s->x[2] = t.x[2] ^ ROR64(t.x[2], 1)  ^ ROR64(t.x[2], 6);
    s->x[3] = t.x[3] ^ ROR64(t.x[3], 10) ^ ROR64(t.x[3], 17);
    s->x[4] = t.x[4] ^ ROR64(t.x[4], 7)  ^ ROR64(t.x[4], 41);
}

/* p^a: 12 kor (inicializalas, veglegesites) */
static inline void P12(ascon_state_t *s) {
    ROUND(s, 0xf0); ROUND(s, 0xe1); ROUND(s, 0xd2); ROUND(s, 0xc3);
    ROUND(s, 0xb4); ROUND(s, 0xa5); ROUND(s, 0x96); ROUND(s, 0x87);
    ROUND(s, 0x78); ROUND(s, 0x69); ROUND(s, 0x5a); ROUND(s, 0x4b);
}

/* p^b: 6 kor (adatfeldolgozas) */
static inline void P6(ascon_state_t *s) {
    ROUND(s, 0x96); ROUND(s, 0x87); ROUND(s, 0x78);
    ROUND(s, 0x69); ROUND(s, 0x5a); ROUND(s, 0x4b);
}

/* --- Nyilvanos API (a NIST LWC / SUPERCOP feluletet koveti) ---
 * encrypt: c = titkositott szoveg || 16 bajtos cimke, *clen = mlen + 16
 * decrypt: 0 = hiteles uzenet, -1 = hibas cimke (ilyenkor m nem hasznalhato)
 */
int ascon128_aead_encrypt(uint8_t *c, unsigned long long *clen,
                          const uint8_t *m, unsigned long long mlen,
                          const uint8_t *ad, unsigned long long adlen,
                          const uint8_t *nsec, const uint8_t *npub,
                          const uint8_t *k);

int ascon128_aead_decrypt(uint8_t *m, unsigned long long *mlen,
                          uint8_t *nsec, const uint8_t *c,
                          unsigned long long clen, const uint8_t *ad,
                          unsigned long long adlen, const uint8_t *npub,
                          const uint8_t *k);

#endif /* ASCON128_H_ */
