/*
 * ascon_aead128.h - Ascon-AEAD128 (NIST SP 800-232)
 *
 * Forras: ascon-c (https://github.com/ascon/ascon-c), crypto_aead/asconaead128/bi32,
 * commit 446347f2 (2026-01-28). Licenc: CC0 1.0 Universal.
 * Tartalma: az eredeti api.h parameterei es a NIST LWC API (tests/crypto_aead.h)
 * fuggvenyprototipusai, valtozatlanul.
 */
#ifndef ASCON_AEAD128_H
#define ASCON_AEAD128_H

/* ===================== api.h ===================== */
#define CRYPTO_VERSION "1.3.0"
#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16
#define CRYPTO_NOOVERLAP 1
#define ASCON_AEAD_RATE 16
#define ASCON_VARIANT 1

/* ===================== crypto_aead.h ===================== */
int crypto_aead_encrypt(unsigned char *c, unsigned long long *clen,
                        const unsigned char *m, unsigned long long mlen,
                        const unsigned char *ad, unsigned long long adlen,
                        const unsigned char *nsec, const unsigned char *npub,
                        const unsigned char *k);

int crypto_aead_decrypt(unsigned char *m, unsigned long long *mlen,
                        unsigned char *nsec, const unsigned char *c,
                        unsigned long long clen, const unsigned char *ad,
                        unsigned long long adlen, const unsigned char *npub,
                        const unsigned char *k);

#endif /* ASCON_AEAD128_H */
