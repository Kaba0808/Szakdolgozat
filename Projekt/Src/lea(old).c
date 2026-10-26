/**
  ******************************************************************************
  * @file           : lea.c
  * @brief          : LEA-128/192/256 blokktitkosito (ECB)
  *
  * Sajat C-implementacio a specifikacio alapjan (Hong et al., WISA 2013;
  * Lee et al., Sensors 2014). 128 bites blokk, 4 db 32 bites szo,
  * ARX-alapu altalanositott Feistel-halozat. A meres a 128 bites kulcsot
  * hasznalja (24 kor). Helyesseg: KISA LEA-128 tesztvektor + korut.
  ******************************************************************************
  */
#include "lea.h"
#include <stdint.h>
#include <string.h>

/* 32 bites forgatasok. A (32-n)&31 maszk n = 0 eseten is definialt
   viselkedest ad; a fordito Cortex-M4-en egyetlen ROR utasitasra forditja. */
static inline uint32_t rol32(uint32_t x, unsigned int n) {
    return (x << n) | (x >> ((32U - n) & 31U));
}

static inline uint32_t ror32(uint32_t x, unsigned int n) {
    return (x >> n) | (x << ((32U - n) & 31U));
}

/* Little-endian betoltes/tarolas (a Cortex-M4 little-endian, igazitatlan
   hozzaferest is tamogat, a memcpy egyetlen LDR/STR-re fordul) */
static inline uint32_t load32_le(const uint8_t *src) {
    uint32_t val;
    memcpy(&val, src, 4);
    return val;
}

static inline void store32_le(uint8_t *dst, uint32_t x) {
    memcpy(dst, &x, 4);
}

/* Kulcsgeneralasi konstansok: delta_0..delta_7 (a specifikacio szerint) */
static const uint32_t delta_seed[8] = {
    0xc3efe9dbU, 0x44626b02U, 0x79e27c8aU, 0x78df30ecU,
    0x715ea49eU, 0xc785da0aU, 0xe04ef22aU, 0xe5c40957U
};

/* ROL_i(delta_j): a j. konstans i bittel balra forgatva */
static uint32_t delta_word(unsigned int row, unsigned int idx) {
    return rol32(delta_seed[row & 7U], idx & 31U);
}

/* Kulcsgeneralas: korkulcsonkent 6 db 32 bites szo, RK_i = (T0,T1,T2,T1,T3,T1)
   a 128 bites kulcsnal; osszesen 24 x 6 = 144 szo. */
void lea_set_key(LEA_KEY *key, const uint8_t *mk, unsigned int mk_len) {
    uint32_t t[8];
    unsigned int i;

    if (key == NULL || mk == NULL) {
        return;
    }

    for (i = 0; i < 8; ++i) {
        t[i] = 0;
    }

    if (mk_len == 16U) {
        key->rounds = 24U;
        t[0] = load32_le(mk + 0);
        t[1] = load32_le(mk + 4);
        t[2] = load32_le(mk + 8);
        t[3] = load32_le(mk + 12);

        for (i = 0; i < key->rounds; ++i) {
            uint32_t d0 = delta_word(i % 4U, i + 0U);
            uint32_t d1 = delta_word(i % 4U, i + 1U);
            uint32_t d2 = delta_word(i % 4U, i + 2U);
            uint32_t d3 = delta_word(i % 4U, i + 3U);

            t[0] = rol32(t[0] + d0, 1);
            t[1] = rol32(t[1] + d1, 3);
            t[2] = rol32(t[2] + d2, 6);
            t[3] = rol32(t[3] + d3, 11);

            key->rk[6U * i + 0U] = t[0];
            key->rk[6U * i + 1U] = t[1];
            key->rk[6U * i + 2U] = t[2];
            key->rk[6U * i + 3U] = t[1];
            key->rk[6U * i + 4U] = t[3];
            key->rk[6U * i + 5U] = t[1];
        }
    } else if (mk_len == 24U) {
        key->rounds = 28U;
        t[0] = load32_le(mk + 0);
        t[1] = load32_le(mk + 4);
        t[2] = load32_le(mk + 8);
        t[3] = load32_le(mk + 12);
        t[4] = load32_le(mk + 16);
        t[5] = load32_le(mk + 20);

        for (i = 0; i < key->rounds; ++i) {
            unsigned int row = i % 6U;
            t[0] = rol32(t[0] + delta_word(row, i + 0U), 1);
            t[1] = rol32(t[1] + delta_word(row, i + 1U), 3);
            t[2] = rol32(t[2] + delta_word(row, i + 2U), 6);
            t[3] = rol32(t[3] + delta_word(row, i + 3U), 11);
            t[4] = rol32(t[4] + delta_word(row, i + 4U), 13);
            t[5] = rol32(t[5] + delta_word(row, i + 5U), 17);

            key->rk[6U * i + 0U] = t[0];
            key->rk[6U * i + 1U] = t[1];
            key->rk[6U * i + 2U] = t[2];
            key->rk[6U * i + 3U] = t[3];
            key->rk[6U * i + 4U] = t[4];
            key->rk[6U * i + 5U] = t[5];
        }
    } else if (mk_len == 32U) {
        key->rounds = 32U;
        for (i = 0; i < 8U; ++i) {
            t[i] = load32_le(mk + 4U * i);
        }

        for (i = 0; i < key->rounds; ++i) {
            unsigned int row = i % 8U;
            unsigned int idx0 = (6U * i + 0U) % 8U;
            unsigned int idx1 = (6U * i + 1U) % 8U;
            unsigned int idx2 = (6U * i + 2U) % 8U;
            unsigned int idx3 = (6U * i + 3U) % 8U;
            unsigned int idx4 = (6U * i + 4U) % 8U;
            unsigned int idx5 = (6U * i + 5U) % 8U;

            t[idx0] = rol32(t[idx0] + delta_word(row, i + 0U), 1);
            t[idx1] = rol32(t[idx1] + delta_word(row, i + 1U), 3);
            t[idx2] = rol32(t[idx2] + delta_word(row, i + 2U), 6);
            t[idx3] = rol32(t[idx3] + delta_word(row, i + 3U), 11);
            t[idx4] = rol32(t[idx4] + delta_word(row, i + 4U), 13);
            t[idx5] = rol32(t[idx5] + delta_word(row, i + 5U), 17);

            key->rk[6U * i + 0U] = t[idx0];
            key->rk[6U * i + 1U] = t[idx1];
            key->rk[6U * i + 2U] = t[idx2];
            key->rk[6U * i + 3U] = t[idx3];
            key->rk[6U * i + 4U] = t[idx4];
            key->rk[6U * i + 5U] = t[idx5];
        }
    } else {
        key->rounds = 0U;
    }
}

/* Egy blokk titkositasa. A specifikacio szerinti szocsere (X3' = X0) helyett
   a kod a szavak szerepet koronkent forgatja (r & 3), igy nincs masolas. */
void lea_encrypt(uint8_t *ct, const uint8_t *pt, const LEA_KEY *key) {
    uint32_t x0, x1, x2, x3;
    unsigned int r;
    const uint32_t *rk;

    if (ct == NULL || pt == NULL || key == NULL || key->rounds == 0U) {
        return;
    }

    x0 = load32_le(pt + 0);
    x1 = load32_le(pt + 4);
    x2 = load32_le(pt + 8);
    x3 = load32_le(pt + 12);

    for (r = 0; r < key->rounds; ++r) {
        rk = &key->rk[6U * r];
        switch (r & 3U) {
            case 0U:
                x3 = ror32((x2 ^ rk[4]) + (x3 ^ rk[5]), 3);
                x2 = ror32((x1 ^ rk[2]) + (x2 ^ rk[3]), 5);
                x1 = rol32((x0 ^ rk[0]) + (x1 ^ rk[1]), 9);
                break;
            case 1U:
                x0 = ror32((x3 ^ rk[4]) + (x0 ^ rk[5]), 3);
                x3 = ror32((x2 ^ rk[2]) + (x3 ^ rk[3]), 5);
                x2 = rol32((x1 ^ rk[0]) + (x2 ^ rk[1]), 9);
                break;
            case 2U:
                x1 = ror32((x0 ^ rk[4]) + (x1 ^ rk[5]), 3);
                x0 = ror32((x3 ^ rk[2]) + (x0 ^ rk[3]), 5);
                x3 = rol32((x2 ^ rk[0]) + (x3 ^ rk[1]), 9);
                break;
            default:
                x2 = ror32((x1 ^ rk[4]) + (x2 ^ rk[5]), 3);
                x1 = ror32((x0 ^ rk[2]) + (x1 ^ rk[3]), 5);
                x0 = rol32((x3 ^ rk[0]) + (x0 ^ rk[1]), 9);
                break;
        }
    }

    store32_le(ct + 0, x0);
    store32_le(ct + 4, x1);
    store32_le(ct + 8, x2);
    store32_le(ct + 12, x3);
}

/* Egy blokk visszafejtese: forditott korsorrend, ROL<->ROR, osszeadas helyett kivonas */
void lea_decrypt(uint8_t *pt, const uint8_t *ct, const LEA_KEY *key) {
    uint32_t x0, x1, x2, x3;
    int r;
    const uint32_t *rk;

    if (pt == NULL || ct == NULL || key == NULL || key->rounds == 0U) {
        return;
    }

    x0 = load32_le(ct + 0);
    x1 = load32_le(ct + 4);
    x2 = load32_le(ct + 8);
    x3 = load32_le(ct + 12);

    for (r = (int)key->rounds - 1; r >= 0; --r) {
        rk = &key->rk[6U * (unsigned int)r];
        switch ((unsigned int)r & 3U) {
            case 0U:
                x1 = (ror32(x1, 9) - (x0 ^ rk[0])) ^ rk[1];
                x2 = (rol32(x2, 5) - (x1 ^ rk[2])) ^ rk[3];
                x3 = (rol32(x3, 3) - (x2 ^ rk[4])) ^ rk[5];
                break;
            case 1U:
                x2 = (ror32(x2, 9) - (x1 ^ rk[0])) ^ rk[1];
                x3 = (rol32(x3, 5) - (x2 ^ rk[2])) ^ rk[3];
                x0 = (rol32(x0, 3) - (x3 ^ rk[4])) ^ rk[5];
                break;
            case 2U:
                x3 = (ror32(x3, 9) - (x2 ^ rk[0])) ^ rk[1];
                x0 = (rol32(x0, 5) - (x3 ^ rk[2])) ^ rk[3];
                x1 = (rol32(x1, 3) - (x0 ^ rk[4])) ^ rk[5];
                break;
            default:
                x0 = (ror32(x0, 9) - (x3 ^ rk[0])) ^ rk[1];
                x1 = (rol32(x1, 5) - (x0 ^ rk[2])) ^ rk[3];
                x2 = (rol32(x2, 3) - (x1 ^ rk[4])) ^ rk[5];
                break;
        }
    }

    store32_le(pt + 0, x0);
    store32_le(pt + 4, x1);
    store32_le(pt + 8, x2);
    store32_le(pt + 12, x3);
}

/* ECB: a puffer 16 bajtos blokkonkent; a hossznak 16 tobbszorosenek kell lennie */
void lea_ecb_encrypt(uint8_t *ct, const uint8_t *pt, unsigned int len, const LEA_KEY *key) {
    unsigned int i;
    if (ct == NULL || pt == NULL || key == NULL) {
        return;
    }
    if ((len & (LEA_BLOCK_SIZE - 1U)) != 0U) {
        return;
    }
    for (i = 0; i < len; i += LEA_BLOCK_SIZE) {
        lea_encrypt(ct + i, pt + i, key);
    }
}

void lea_ecb_decrypt(uint8_t *pt, const uint8_t *ct, unsigned int len, const LEA_KEY *key) {
    unsigned int i;
    if (pt == NULL || ct == NULL || key == NULL) {
        return;
    }
    if ((len & (LEA_BLOCK_SIZE - 1U)) != 0U) {
        return;
    }
    for (i = 0; i < len; i += LEA_BLOCK_SIZE) {
        lea_decrypt(pt + i, ct + i, key);
    }
}
