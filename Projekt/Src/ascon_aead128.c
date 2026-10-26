/*
 * ascon_aead128.c - Ascon-AEAD128 (NIST SP 800-232)
 *
 * Forras: a tervezok hivatalos C-implementacioja, ascon-c,
 *   https://github.com/ascon/ascon-c
 *   crypto_aead/asconaead128/bi32 (32 bites, sebessegre optimalizalt,
 *   bit-interleaved, tiszta C), commit 446347f21b209f3921c65ece70027c366cbe1693
 *   (2026-01-28). Szerzok: Christoph Dobraunig, Martin Schlaffer.
 * Licenc: CC0 1.0 Universal (public domain).
 *
 * A projekt egy .c/.h parjahoz a fenti konyvtar fajljait valtoztatas nelkul,
 * fuggosegi sorrendben egymas utan masoltuk (a fajlhatarokat megjegyzes jeloli).
 * Egyetlen modositas: a helyi #include "..." sorok elmaradtak, mert a
 * tartalmuk ebben a fajlban mar szerepel; az api.h es a crypto_aead.h
 * tartalma az ascon_aead128.h-ba kerult. A konfiguracio (config.h) az
 * eredeti alapbeallitas. A printstate.c (csak hibakereseshez) nincs benne.
 */
#include "ascon_aead128.h"

/* ===================== config.h ===================== */
#ifndef CONFIG_H_
#define CONFIG_H_

/* inline the ascon mode */
#ifndef ASCON_INLINE_MODE
#define ASCON_INLINE_MODE 1
#endif

/* inline all permutations */
#ifndef ASCON_INLINE_PERM
#define ASCON_INLINE_PERM 0
#endif

/* unroll permutation loops */
#ifndef ASCON_UNROLL_LOOPS
#define ASCON_UNROLL_LOOPS 1
#endif

/* inline bitinterleaving */
#ifndef ASCON_INLINE_BI
#define ASCON_INLINE_BI 1
#endif

/* extern bitinterleaving */
#ifndef ASCON_EXTERN_BI
#define ASCON_EXTERN_BI 0
#endif

#endif /* CONFIG_H_ */

/* ===================== forceinline.h ===================== */
#ifndef FORCEINLINE_H_
#define FORCEINLINE_H_

/* define forceinline macro */
#ifdef _MSC_VER
#define forceinline __forceinline
#elif defined(__GNUC__)
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define forceinline inline __attribute__((__always_inline__))
#else
#define forceinline static inline
#endif
#elif defined(__CLANG__)
#if __has_attribute(__always_inline__)
#define forceinline inline __attribute__((__always_inline__))
#else
#define forceinline inline
#endif
#else
#define forceinline inline
#endif

#endif /* FORCEINLINE_H_ */

/* ===================== lendian.h ===================== */
#ifndef ENDIAN_H_
#define ENDIAN_H_

#if (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__) || \
    defined(_MSC_VER)

/* macros for little endian machines */
#ifdef PRAGMA_ENDIAN
#pragma message("Use macros for little endian machines")
#endif
#define U64LE(x) (x)
#define U32LE(x) (x)
#define U16LE(x) (x)

#elif (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

/* macros for big endian machines */
#ifdef PRAGMA_ENDIAN
#pragma message("Use macros for big endian machines")
#endif
#define U64LE(x)                           \
  (((0x00000000000000FFULL & (x)) << 56) | \
   ((0x000000000000FF00ULL & (x)) << 40) | \
   ((0x0000000000FF0000ULL & (x)) << 24) | \
   ((0x00000000FF000000ULL & (x)) << 8) |  \
   ((0x000000FF00000000ULL & (x)) >> 8) |  \
   ((0x0000FF0000000000ULL & (x)) >> 24) | \
   ((0x00FF000000000000ULL & (x)) >> 40) | \
   ((0xFF00000000000000ULL & (x)) >> 56))
#define U32LE(x)                                            \
  (((0x000000FF & (x)) << 24) | ((0x0000FF00 & (x)) << 8) | \
   ((0x00FF0000 & (x)) >> 8) | ((0xFF000000 & (x)) >> 24))
#define U16LE(x) (((0x00FF & (x)) << 8) | ((0xFF00 & (x)) >> 8))

#else
#error "Ascon byte order macros not defined in lendian.h"
#endif

#endif /* ENDIAN_H_ */

/* ===================== interleave.h ===================== */
#ifndef INTERLEAVE_H_
#define INTERLEAVE_H_

#include <stdint.h>


#if ASCON_INLINE_BI

#define TOBI deinterleave32
#define FROMBI interleave32

#else

uint64_t TOBI(uint64_t in);
uint64_t FROMBI(uint64_t in);

#endif

extern const uint32_t B[3];

forceinline uint32_t deinterleave16(uint32_t x) {
  uint32_t t;
  t = (x ^ (x >> 1)) & B[0], x ^= t ^ (t << 1);
  t = (x ^ (x >> 2)) & B[1], x ^= t ^ (t << 2);
  t = (x ^ (x >> 4)) & B[2], x ^= t ^ (t << 4);
  t = (x ^ (x >> 8)) & 0xff00, x ^= t ^ (t << 8);
  return x;
}

forceinline uint32_t interleave16(uint32_t x) {
  uint32_t t;
  t = (x ^ (x >> 8)) & 0xff00, x ^= t ^ (t << 8);
  t = (x ^ (x >> 4)) & B[2], x ^= t ^ (t << 4);
  t = (x ^ (x >> 2)) & B[1], x ^= t ^ (t << 2);
  t = (x ^ (x >> 1)) & B[0], x ^= t ^ (t << 1);
  return x;
}

/* credit to Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002 */
forceinline uint64_t deinterleave32(uint64_t in) {
  in = U64LE(in);
  uint32_t hi = in >> 32;
  uint32_t lo = in;
  uint32_t t0, t1, e, o;
  t0 = deinterleave16(lo);
  t1 = deinterleave16(hi);
  e = (t1 << 16) | (t0 & 0x0000FFFF);
  o = (t1 & 0xFFFF0000) | (t0 >> 16);
  return (uint64_t)o << 32 | e;
}

/* credit to Henry S. Warren, Hacker's Delight, Addison-Wesley, 2002 */
forceinline uint64_t interleave32(uint64_t in) {
  uint32_t e = in;
  uint32_t o = in >> 32;
  uint32_t t0, t1, lo, hi;
  t0 = (o << 16) | (e & 0x0000FFFF);
  t1 = (o & 0xFFFF0000) | (e >> 16);
  lo = interleave16(t0);
  hi = interleave16(t1);
  return U64LE((uint64_t)hi << 32 | lo);
}

#endif /* INTERLEAVE_H_ */

/* ===================== interleave.c ===================== */

#if !ASCON_EXTERN_BI

const uint32_t B[3] = {0x22222222, 0x0c0c0c0c, 0x00f000f0};

#if !ASCON_INLINE_BI

uint64_t TOBI(uint64_t in) { return deinterleave32(in); }

uint64_t FROMBI(uint64_t in) { return interleave32(in); }

#endif

#endif

/* ===================== constants.h ===================== */
#ifndef CONSTANTS_H_
#define CONSTANTS_H_

#include <stdint.h>

#define ASCON_80PQ_VARIANT 0
#define ASCON_AEAD_VARIANT 1
#define ASCON_HASH_VARIANT 2
#define ASCON_XOF_VARIANT 3
#define ASCON_CXOF_VARIANT 4
#define ASCON_MAC_VARIANT 5
#define ASCON_PRF_VARIANT 6
#define ASCON_PRFS_VARIANT 7

#define ASCON_TAG_SIZE 16
#define ASCON_HASH_SIZE 32

#define ASCON_128_RATE 8
#define ASCON_128A_RATE 16
#define ASCON_HASH_RATE 8
#define ASCON_PRF_IN_RATE 32
#define ASCON_PRFA_IN_RATE 40
#define ASCON_PRF_OUT_RATE 16

#define ASCON_PA_ROUNDS 12
#define ASCON_128_PB_ROUNDS 6
#define ASCON_128A_PB_ROUNDS 8
#define ASCON_HASH_PB_ROUNDS 12
#define ASCON_HASHA_PB_ROUNDS 8
#define ASCON_PRF_PB_ROUNDS 12
#define ASCON_PRFA_PB_ROUNDS 8

#define ASCON_128_IV 0x0020860000000a01ull
#define ASCON_128A_IV 0x00008a0000400201ull
#define ASCON_80PQ_IV 0x0000862000000a00ull

#define ASCON_HASH_IV 0x00200a0100010a00ull
#define ASCON_HASHA_IV 0x00200a0100010200ull
#define ASCON_XOF_IV 0x00200a0100000a01ull
#define ASCON_XOFA_IV 0x00200a0100000201ull
#define ASCON_CXOF_IV 0x00200a0000000a02ull
#define ASCON_CXOFA_IV 0x00200a0000000202ull

#define ASCON_MAC_IV 0x00408a0004000a03ull
#define ASCON_MACA_IV 0x00608a0004000203ull
#define ASCON_PRF_IV 0x00400a0104000a02ull
#define ASCON_PRFA_IV 0x00600a0104000202ull
#define ASCON_PRFS_IV 0x0000820100000203ull

#define ASCON_HASH_IV0 0xb308e49856e696e1ull
#define ASCON_HASH_IV1 0x39c35509990657dcull
#define ASCON_HASH_IV2 0xf46674e32b5a9644ull
#define ASCON_HASH_IV3 0x678c872d6fe2f8b5ull
#define ASCON_HASH_IV4 0x321218964ea92b7bull

#define ASCON_HASHA_IV0 0xdfc87ee88f6dfe3bull
#define ASCON_HASHA_IV1 0xa5343eaff69bf029ull
#define ASCON_HASHA_IV2 0xaff8d129e063315cull
#define ASCON_HASHA_IV3 0xab080f50d3262646ull
#define ASCON_HASHA_IV4 0xbaa07b54827da001ull

#define ASCON_XOF_IV0 0xb9b5a81fc0ae36b9ull
#define ASCON_XOF_IV1 0xa6d933e6aeabf6d9ull
#define ASCON_XOF_IV2 0xd0b98214bc3f00e5ull
#define ASCON_XOF_IV3 0x3cf1072a288d99caull
#define ASCON_XOF_IV4 0xc044b73b8ef2db1eull

#define ASCON_XOFA_IV0 0xd0301a61d22c7d19ull
#define ASCON_XOFA_IV1 0x84ddf0a7aee92112ull
#define ASCON_XOFA_IV2 0xf2db820c7e587838ull
#define ASCON_XOFA_IV3 0xa991ae5fd830ad8bull
#define ASCON_XOFA_IV4 0x25f0ccd7d1c1e4b3ull

#define RC0 0x0000000c0000000cull
#define RC1 0x0000000c00000009ull
#define RC2 0x000000090000000cull
#define RC3 0x0000000900000009ull
#define RC4 0x0000000c00000006ull
#define RC5 0x0000000c00000003ull
#define RC6 0x0000000900000006ull
#define RC7 0x0000000900000003ull
#define RC8 0x000000060000000cull
#define RC9 0x0000000600000009ull
#define RCa 0x000000030000000cull
#define RCb 0x0000000300000009ull

#define RC(i) ((uint64_t)constants[i + 1] << 32 | constants[i])

#define START(n) (24 - 2 * (n))
#define INC 2
#define END 24

extern const uint8_t constants[];

#endif /* CONSTANTS_H_ */

/* ===================== constants.c ===================== */

#if !ASCON_UNROLL_LOOPS

const uint8_t constants[] = {0xc, 0xc, 0x9, 0xc, 0xc, 0x9, 0x9, 0x9,
                             0x6, 0xc, 0x3, 0xc, 0x6, 0x9, 0x3, 0x9,
                             0xc, 0x6, 0x9, 0x6, 0xc, 0x3, 0x9, 0x3};

#endif

/* ===================== ascon.h ===================== */
#ifndef ASCON_H_
#define ASCON_H_

#include <stdint.h>


typedef union {
  uint64_t x[5];
  uint32_t w[5][2];
  uint8_t b[5][8];
} ascon_state_t;

#ifdef ASCON_AEAD_RATE

#define ASCON_KEYWORDS (CRYPTO_KEYBYTES + 7) / 8

typedef union {
  uint64_t x[ASCON_KEYWORDS];
  uint32_t w[ASCON_KEYWORDS][2];
  uint8_t b[ASCON_KEYWORDS][8];
} ascon_key_t;

#if !ASCON_INLINE_MODE

void ascon_loadkey(ascon_key_t* key, const uint8_t* k);
void ascon_initaead(ascon_state_t* s, const ascon_key_t* key,
                    const uint8_t* npub);
void ascon_adata(ascon_state_t* s, const uint8_t* ad, uint64_t adlen);
void ascon_encrypt(ascon_state_t* s, uint8_t* c, const uint8_t* m,
                   uint64_t mlen);
void ascon_decrypt(ascon_state_t* s, uint8_t* m, const uint8_t* c,
                   uint64_t clen);
void ascon_final(ascon_state_t* s, const ascon_key_t* k);

#endif

int ascon_aead_encrypt(uint8_t* t, uint8_t* c, const uint8_t* m, uint64_t mlen,
                       const uint8_t* ad, uint64_t adlen, const uint8_t* npub,
                       const uint8_t* k);
int ascon_aead_decrypt(uint8_t* m, const uint8_t* t, const uint8_t* c,
                       uint64_t clen, const uint8_t* ad, uint64_t adlen,
                       const uint8_t* npub, const uint8_t* k);

#endif

#ifdef ASCON_HASH_BYTES

#if !ASCON_INLINE_MODE

void ascon_inithash(ascon_state_t* s);
void ascon_absorb(ascon_state_t* s, const uint8_t* in, uint64_t inlen);
void ascon_squeeze(ascon_state_t* s, uint8_t* out, uint64_t outlen);

#endif

int ascon_xof(uint8_t* out, uint64_t outlen, const uint8_t* in, uint64_t inlen);

#endif

#endif /* ASCON_H_ */

/* ===================== printstate.h ===================== */
#ifndef PRINTSTATE_H_
#define PRINTSTATE_H_

#ifdef ASCON_PRINT_STATE


void print(const char* text);
void printbytes(const char* text, const uint8_t* b, uint64_t len);
void printword(const char* text, const uint64_t x);
void printstate(const char* text, const ascon_state_t* s);

#else

#define print(text) \
  do {              \
  } while (0)

#define printbytes(text, b, l) \
  do {                         \
  } while (0)

#define printword(text, w) \
  do {                     \
  } while (0)

#define printstate(text, s) \
  do {                      \
  } while (0)

#endif

#endif /* PRINTSTATE_H_ */

/* ===================== word.h ===================== */
#ifndef WORD_H_
#define WORD_H_

#include <stdint.h>
#include <string.h>


#if ASCON_EXTERN_BI
#define U64TOWORD(x) U64LE(x)
#define WORDTOU64(x) U64LE(x)
#else
#define U64TOWORD(x) TOBI(x)
#define WORDTOU64(x) FROMBI(x)
#endif

#define LOAD(b, n) LOADBYTES(b, n)
#define STORE(b, w, n) STOREBYTES(b, w, n)

typedef union {
  uint64_t x;
  uint32_t w[2];
  uint8_t b[8];
} word_t;

forceinline uint32_t ROR32(uint32_t x, int n) {
  return x >> n | x << (-n & 31);
}

forceinline uint64_t ROR(uint64_t x, int n) {
  word_t b, a = {.x = x};
  b.w[0] = (n % 2) ? ROR32(a.w[1], (n - 1) / 2) : ROR32(a.w[0], n / 2);
  b.w[1] = (n % 2) ? ROR32(a.w[0], (n + 1) / 2) : ROR32(a.w[1], n / 2);
  return b.x;
}

forceinline uint64_t KEYROT(uint64_t hi2lo, uint64_t lo2hi) {
  word_t w, a = {.x = lo2hi}, b = {.x = hi2lo};
  w.w[0] = a.w[0] << 16 | b.w[0] >> 16;
  w.w[1] = a.w[1] << 16 | b.w[1] >> 16;
  return w.x;
}

forceinline int NOTZERO(uint64_t a, uint64_t b) {
  uint64_t result = a | b;
  result |= result >> 32;
  result |= result >> 16;
  result |= result >> 8;
  return ((((int)(result & 0xff) - 1) >> 8) & 1) - 1;
}

#if ASCON_EXTERN_BI

forceinline uint64_t PAD(int i) { return 0x01ull << (8 * i); }

forceinline uint64_t DSEP() { return 0x80ull << 56; }

forceinline uint64_t PRFS_MLEN(uint64_t len) { return len << 51; }

forceinline uint64_t CLEAR(uint64_t w, int n) {
  /* undefined for n == 0 */
  uint64_t mask = ~0ull << (8 * n);
  return w & mask;
}

#else

forceinline uint64_t PAD(int i) { return (uint32_t)0x01 << (4 * i); }

forceinline uint64_t DSEP() { return 0x80ull << 56; }

forceinline uint64_t PRFS_MLEN(uint64_t len) {
  return ((len & 0x01) << 57) | /* 0000x */
         ((len & 0x02) << 25) | /* 000x0 */
         ((len & 0x04) << 56) | /* 00x00 */
         ((len & 0x08) << 24) | /* 0x000 */
         ((len & 0x10) << 55);  /* x0000 */
}

forceinline uint64_t CLEAR(uint64_t w, int n) {
  /* undefined for n == 0 */
  uint32_t mask = 0xffffffffull << (4 * n);
  return w & ((uint64_t)mask << 32 | mask);
}

#endif

forceinline uint64_t MASK(int n) {
  /* undefined for n == 0 */
  return ~0ull << (64 - 8 * n);
}

forceinline uint64_t LOADBYTES(const uint8_t* bytes, int n) {
  uint64_t x = 0;
  memcpy(&x, bytes, n);
  return U64TOWORD(x);
}

forceinline void STOREBYTES(uint8_t* bytes, uint64_t w, int n) {
  uint64_t x = WORDTOU64(w);
  memcpy(bytes, &x, n);
}

#endif /* WORD_H_ */

/* ===================== round.h ===================== */
#ifndef ROUND_H_
#define ROUND_H_


forceinline void ROUND(ascon_state_t* s, uint64_t C) {
  ascon_state_t t;
  /* round constant */
  s->x[2] ^= C;
  /* s-box layer */
  s->x[0] ^= s->x[4];
  s->x[4] ^= s->x[3];
  s->x[2] ^= s->x[1];
  t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
  t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
  t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);
  t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
  t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
  t.x[1] ^= t.x[0];
  t.x[3] ^= t.x[2];
  t.x[0] ^= t.x[4];
  /* linear layer */
  s->x[2] = t.x[2] ^ ROR(t.x[2], 6 - 1);
  s->x[3] = t.x[3] ^ ROR(t.x[3], 17 - 10);
  s->x[4] = t.x[4] ^ ROR(t.x[4], 41 - 7);
  s->x[0] = t.x[0] ^ ROR(t.x[0], 28 - 19);
  s->x[1] = t.x[1] ^ ROR(t.x[1], 61 - 39);
  s->x[2] = t.x[2] ^ ROR(s->x[2], 1);
  s->x[3] = t.x[3] ^ ROR(s->x[3], 10);
  s->x[4] = t.x[4] ^ ROR(s->x[4], 7);
  s->x[0] = t.x[0] ^ ROR(s->x[0], 19);
  s->x[1] = t.x[1] ^ ROR(s->x[1], 39);
  s->x[2] = ~s->x[2];
  printstate(" round output", s);
}

forceinline void PROUNDS(ascon_state_t* s, int nr) {
  int i = START(nr);
  do {
    ROUND(s, RC(i));
    i += INC;
  } while (i != END);
}

#endif /* ROUND_H_ */

/* ===================== permutations.h ===================== */
#ifndef PERMUTATIONS_H_
#define PERMUTATIONS_H_

#include <stdint.h>


forceinline void P12ROUNDS(ascon_state_t* s) {
  ROUND(s, RC0);
  ROUND(s, RC1);
  ROUND(s, RC2);
  ROUND(s, RC3);
  ROUND(s, RC4);
  ROUND(s, RC5);
  ROUND(s, RC6);
  ROUND(s, RC7);
  ROUND(s, RC8);
  ROUND(s, RC9);
  ROUND(s, RCa);
  ROUND(s, RCb);
}

forceinline void P8ROUNDS(ascon_state_t* s) {
  ROUND(s, RC4);
  ROUND(s, RC5);
  ROUND(s, RC6);
  ROUND(s, RC7);
  ROUND(s, RC8);
  ROUND(s, RC9);
  ROUND(s, RCa);
  ROUND(s, RCb);
}

forceinline void P6ROUNDS(ascon_state_t* s) {
  ROUND(s, RC6);
  ROUND(s, RC7);
  ROUND(s, RC8);
  ROUND(s, RC9);
  ROUND(s, RCa);
  ROUND(s, RCb);
}

#if ASCON_INLINE_PERM && ASCON_UNROLL_LOOPS

forceinline void P(ascon_state_t* s, int nr) {
  if (nr == 12) P12ROUNDS(s);
  if (nr == 8) P8ROUNDS(s);
  if (nr == 6) P6ROUNDS(s);
}

#elif !ASCON_INLINE_PERM && ASCON_UNROLL_LOOPS

void P12(ascon_state_t* s);
void P8(ascon_state_t* s);
void P6(ascon_state_t* s);

forceinline void P(ascon_state_t* s, int nr) {
  if (nr == 12) P12(s);
#if ((defined(ASCON_AEAD_RATE) && ASCON_AEAD_RATE == 16) ||    \
     (defined(ASCON_HASH_ROUNDS) && ASCON_HASH_ROUNDS == 8) || \
     (defined(ASCON_PRF_ROUNDS) && ASCON_PRF_ROUNDS == 8))
  if (nr == 8) P8(s);
#endif
#if (defined(ASCON_AEAD_RATE) && ASCON_AEAD_RATE == 8)
  if (nr == 6) P6(s);
#endif
}

#elif ASCON_INLINE_PERM && !ASCON_UNROLL_LOOPS

forceinline void P(ascon_state_t* s, int nr) { PROUNDS(s, nr); }

#else /* !ASCON_INLINE_PERM && !ASCON_UNROLL_LOOPS */

void P(ascon_state_t* s, int nr);

#endif

#endif /* PERMUTATIONS_H_ */

/* ===================== permutations.c ===================== */

#if !ASCON_INLINE_PERM && ASCON_UNROLL_LOOPS

void P12(ascon_state_t* s) { P12ROUNDS(s); }

#endif

#if ((defined(ASCON_AEAD_RATE) && ASCON_AEAD_RATE == 16) ||    \
     (defined(ASCON_HASH_ROUNDS) && ASCON_HASH_ROUNDS == 8) || \
     (defined(ASCON_PRF_ROUNDS) && ASCON_PRF_ROUNDS == 8)) &&  \
    !ASCON_INLINE_PERM && ASCON_UNROLL_LOOPS

void P8(ascon_state_t* s) { P8ROUNDS(s); }

#endif

#if (defined(ASCON_AEAD_RATE) && ASCON_AEAD_RATE == 8) && \
    !ASCON_INLINE_PERM && ASCON_UNROLL_LOOPS

void P6(ascon_state_t* s) { P6ROUNDS(s); }

#endif

#if !ASCON_INLINE_PERM && !ASCON_UNROLL_LOOPS

void P(ascon_state_t* s, int nr) { PROUNDS(s, nr); }

#endif

/* ===================== aead.c ===================== */

#if !ASCON_INLINE_MODE
#undef forceinline
#define forceinline
#endif

#ifdef ASCON_AEAD_RATE

forceinline void ascon_loadkey(ascon_key_t* key, const uint8_t* k) {
#if CRYPTO_KEYBYTES == 16
  key->x[0] = LOAD(k, 8);
  key->x[1] = LOAD(k + 8, 8);
#else /* CRYPTO_KEYBYTES == 20 */
  key->x[0] = KEYROT(0, LOADBYTES(k, 4));
  key->x[1] = LOADBYTES(k + 4, 8);
  key->x[2] = LOADBYTES(k + 12, 8);
#endif
}

forceinline void ascon_initaead(ascon_state_t* s, const ascon_key_t* key,
                                const uint8_t* npub) {
#if CRYPTO_KEYBYTES == 16
  if (ASCON_AEAD_RATE == 8) s->x[0] = ASCON_128_IV;
  if (ASCON_AEAD_RATE == 16) s->x[0] = ASCON_128A_IV;
  s->x[1] = key->x[0];
  s->x[2] = key->x[1];
#else /* CRYPTO_KEYBYTES == 20 */
  s->x[0] = key->x[0] | ASCON_80PQ_IV;
  s->x[1] = key->x[1];
  s->x[2] = key->x[2];
#endif
  s->x[3] = LOAD(npub, 8);
  s->x[4] = LOAD(npub + 8, 8);
  printstate("init 1st key xor", s);
  P(s, 12);
#if CRYPTO_KEYBYTES == 16
  s->x[3] ^= key->x[0];
  s->x[4] ^= key->x[1];
#else /* CRYPTO_KEYBYTES == 20 */
  s->x[2] ^= key->x[0];
  s->x[3] ^= key->x[1];
  s->x[4] ^= key->x[2];
#endif
  printstate("init 2nd key xor", s);
}

forceinline void ascon_adata(ascon_state_t* s, const uint8_t* ad,
                             uint64_t adlen) {
  const int nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;
  if (adlen) {
    /* full associated data blocks */
    while (adlen >= ASCON_AEAD_RATE) {
      s->x[0] ^= LOAD(ad, 8);
      if (ASCON_AEAD_RATE == 16) s->x[1] ^= LOAD(ad + 8, 8);
      printstate("absorb adata", s);
      P(s, nr);
      ad += ASCON_AEAD_RATE;
      adlen -= ASCON_AEAD_RATE;
    }
    /* final associated data block */
    uint64_t* px = &s->x[0];
    if (ASCON_AEAD_RATE == 16 && adlen >= 8) {
      s->x[0] ^= LOAD(ad, 8);
      px = &s->x[1];
      ad += 8;
      adlen -= 8;
    }
    *px ^= PAD(adlen);
    if (adlen) *px ^= LOADBYTES(ad, adlen);
    printstate("pad adata", s);
    P(s, nr);
  }
  /* domain separation */
  s->x[4] ^= DSEP();
  printstate("domain separation", s);
}

forceinline void ascon_encrypt(ascon_state_t* s, uint8_t* c, const uint8_t* m,
                               uint64_t mlen) {
  const int nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;
  /* full plaintext blocks */
  while (mlen >= ASCON_AEAD_RATE) {
    s->x[0] ^= LOAD(m, 8);
    STORE(c, s->x[0], 8);
    if (ASCON_AEAD_RATE == 16) {
      s->x[1] ^= LOAD(m + 8, 8);
      STORE(c + 8, s->x[1], 8);
    }
    printstate("absorb plaintext", s);
    P(s, nr);
    m += ASCON_AEAD_RATE;
    c += ASCON_AEAD_RATE;
    mlen -= ASCON_AEAD_RATE;
  }
  /* final plaintext block */
  uint64_t* px = &s->x[0];
  if (ASCON_AEAD_RATE == 16 && mlen >= 8) {
    s->x[0] ^= LOAD(m, 8);
    STORE(c, s->x[0], 8);
    px = &s->x[1];
    m += 8;
    c += 8;
    mlen -= 8;
  }
  *px ^= PAD(mlen);
  if (mlen) {
    *px ^= LOADBYTES(m, mlen);
    STOREBYTES(c, *px, mlen);
  }
  printstate("pad plaintext", s);
}

forceinline void ascon_decrypt(ascon_state_t* s, uint8_t* m, const uint8_t* c,
                               uint64_t clen) {
  const int nr = (ASCON_AEAD_RATE == 8) ? 6 : 8;
  /* full ciphertext blocks */
  while (clen >= ASCON_AEAD_RATE) {
    uint64_t cx = LOAD(c, 8);
    s->x[0] ^= cx;
    STORE(m, s->x[0], 8);
    s->x[0] = cx;
    if (ASCON_AEAD_RATE == 16) {
      cx = LOAD(c + 8, 8);
      s->x[1] ^= cx;
      STORE(m + 8, s->x[1], 8);
      s->x[1] = cx;
    }
    printstate("insert ciphertext", s);
    P(s, nr);
    m += ASCON_AEAD_RATE;
    c += ASCON_AEAD_RATE;
    clen -= ASCON_AEAD_RATE;
  }
  /* final ciphertext block */
  uint64_t* px = &s->x[0];
  if (ASCON_AEAD_RATE == 16 && clen >= 8) {
    uint64_t cx = LOAD(c, 8);
    s->x[0] ^= cx;
    STORE(m, s->x[0], 8);
    s->x[0] = cx;
    px = &s->x[1];
    m += 8;
    c += 8;
    clen -= 8;
  }
  *px ^= PAD(clen);
  if (clen) {
    uint64_t cx = LOADBYTES(c, clen);
    *px ^= cx;
    STOREBYTES(m, *px, clen);
    *px = CLEAR(*px, clen);
    *px ^= cx;
  }
  printstate("pad ciphertext", s);
}

forceinline void ascon_final(ascon_state_t* s, const ascon_key_t* key) {
#if CRYPTO_KEYBYTES == 16
  if (ASCON_AEAD_RATE == 8) {
    s->x[1] ^= key->x[0];
    s->x[2] ^= key->x[1];
  } else {
    s->x[2] ^= key->x[0];
    s->x[3] ^= key->x[1];
  }
#else /* CRYPTO_KEYBYTES == 20 */
  s->x[1] ^= KEYROT(key->x[0], key->x[1]);
  s->x[2] ^= KEYROT(key->x[1], key->x[2]);
  s->x[3] ^= KEYROT(key->x[2], 0);
#endif
  printstate("final 1st key xor", s);
  P(s, 12);
#if CRYPTO_KEYBYTES == 16
  s->x[3] ^= key->x[0];
  s->x[4] ^= key->x[1];
#else /* CRYPTO_KEYBYTES == 20 */
  s->x[3] ^= key->x[1];
  s->x[4] ^= key->x[2];
#endif
  printstate("final 2nd key xor", s);
}

forceinline void ascon_gettag(ascon_state_t* s, uint8_t* t) {
  STOREBYTES(t, s->x[3], 8);
  STOREBYTES(t + 8, s->x[4], 8);
}

forceinline int ascon_verify(ascon_state_t* s, const uint8_t* t) {
  /* verify should be constant time, check compiler output */
  s->x[3] ^= LOADBYTES(t, 8);
  s->x[4] ^= LOADBYTES(t + 8, 8);
  return NOTZERO(s->x[3], s->x[4]);
}

int ascon_aead_encrypt(uint8_t* t, uint8_t* c, const uint8_t* m, uint64_t mlen,
                       const uint8_t* ad, uint64_t adlen, const uint8_t* npub,
                       const uint8_t* k) {
  ascon_state_t s;
  ascon_key_t key;
  ascon_loadkey(&key, k);
  ascon_initaead(&s, &key, npub);
  ascon_adata(&s, ad, adlen);
  ascon_encrypt(&s, c, m, mlen);
  ascon_final(&s, &key);
  ascon_gettag(&s, t);
  return 0;
}

int ascon_aead_decrypt(uint8_t* m, const uint8_t* t, const uint8_t* c,
                       uint64_t clen, const uint8_t* ad, uint64_t adlen,
                       const uint8_t* npub, const uint8_t* k) {
  ascon_state_t s;
  ascon_key_t key;
  ascon_loadkey(&key, k);
  ascon_initaead(&s, &key, npub);
  ascon_adata(&s, ad, adlen);
  ascon_decrypt(&s, m, c, clen);
  ascon_final(&s, &key);
  return ascon_verify(&s, t);
}

int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;
  /* set ciphertext size */
  *clen = mlen + CRYPTO_ABYTES;
  uint8_t* t = (uint8_t*)c + mlen;
  print("encrypt\n");
  printbytes("k", k, CRYPTO_KEYBYTES);
  printbytes("n", npub, CRYPTO_NPUBBYTES);
  printbytes("a", ad, adlen);
  printbytes("m", m, mlen);
  /* ascon encryption */
  int result = ascon_aead_encrypt(t, c, m, mlen, ad, adlen, npub, k);
  printbytes("c", c, mlen);
  printbytes("t", t, CRYPTO_ABYTES);
  print("\n");
  return result;
}

int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;
  if (clen < CRYPTO_ABYTES) return -1;
  /* set plaintext size */
  *mlen = clen - CRYPTO_ABYTES;
  uint8_t* t = (uint8_t*)c + *mlen;
  print("decrypt\n");
  printbytes("k", k, CRYPTO_KEYBYTES);
  printbytes("n", npub, CRYPTO_NPUBBYTES);
  printbytes("a", ad, adlen);
  printbytes("c", c, *mlen);
  printbytes("t", t, CRYPTO_ABYTES);
  /* ascon decryption */
  int result = ascon_aead_decrypt(m, t, c, *mlen, ad, adlen, npub, k);
  printbytes("m", m, *mlen);
  print("\n");
  return result;
}

#endif
