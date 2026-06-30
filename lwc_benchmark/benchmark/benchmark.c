/**
 * benchmark.c
 * -----------
 * Lightweight kriptografiai algoritmusok teljesitmeny-merese STM32F4-en.
 * Minden algoritmus ugyanolyan feltetelekkel fut:
 *   - 16 byte plaintext (1 blokk)
 *   - 128-bites kulcs
 *   - BENCH_ITERATIONS ismetles
 *   - DWT cikluszamolo a meres eszkőze
 *
 * Mert mutatók:
 *   - Kulcsgenerálás (key schedule) ciklusa — egyszer
 *   - Titkositas: min/max/avg ciklus
 *   - Visszafejtés: min/max/avg ciklus
 */

#include "benchmark.h"
#include "dwt_timer.h"

/* Algoritmus headerek — eleresi ut a CubeIDE projektben allithato be
 * (Project Properties → C/C++ Build → Settings → Include Paths) */
#include "../algorithms/aes/aes.h"
#include "../algorithms/speck/speck.h"
#include "../algorithms/lea/lea.h"
#include "../algorithms/ascon/api.h"
#include "../algorithms/ascon/ascon.h"

#include <string.h>
#include <stdio.h>

/* -----------------------------------------------------------------------
 * Tesztadatok — minden algoritmus ugyanezt kapja
 * ----------------------------------------------------------------------- */

/* 128-bites (16 byte) kulcs */
static const uint8_t TEST_KEY[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

/* 16 byte plaintext */
static const uint8_t TEST_PT[16] = {
    0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x69, 0x74,
    0x20, 0x65, 0x71, 0x75, 0x69, 0x76, 0x61, 0x6c
};

/* ASCON nonce (16 byte) */
static const uint8_t TEST_NONCE[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

/* -----------------------------------------------------------------------
 * Segéd makro: min/max/avg szamitas
 * ----------------------------------------------------------------------- */
#define UPDATE_STATS(val, mn, mx, sum) \
    do { if ((val) < (mn)) (mn) = (val); \
         if ((val) > (mx)) (mx) = (val); \
         (sum) += (val); } while(0)

/* -----------------------------------------------------------------------
 * AES-128 benchmark (tiny-AES-c)
 * ----------------------------------------------------------------------- */
bench_result_t benchmark_aes(void) {
    bench_result_t r = { .name = "AES-128" };
    struct AES_ctx ctx;
    uint8_t buf[16];
    uint32_t t, i;
    uint32_t enc_sum = 0, dec_sum = 0;
    r.enc_min = UINT32_MAX; r.enc_max = 0;
    r.dec_min = UINT32_MAX; r.dec_max = 0;

    /* Kulcsgenerálás mérése */
    t = dwt_get();
    AES_init_ctx(&ctx, TEST_KEY);
    r.keyschedule = dwt_elapsed(t);

    for (i = 0; i < BENCH_ITERATIONS; i++) {
        memcpy(buf, TEST_PT, 16);

        /* Titkosítás */
        t = dwt_get();
        AES_ECB_encrypt(&ctx, buf);
        t = dwt_elapsed(t);
        UPDATE_STATS(t, r.enc_min, r.enc_max, enc_sum);

        /* Visszafejtés */
        t = dwt_get();
        AES_ECB_decrypt(&ctx, buf);
        t = dwt_elapsed(t);
        UPDATE_STATS(t, r.dec_min, r.dec_max, dec_sum);
    }

    r.enc_avg = enc_sum / BENCH_ITERATIONS;
    r.dec_avg = dec_sum / BENCH_ITERATIONS;
    return r;
}

/* -----------------------------------------------------------------------
 * SPECK-128/128 benchmark
 * ----------------------------------------------------------------------- */
bench_result_t benchmark_speck(void) {
    bench_result_t r = { .name = "SPECK-128/128" };
    speck128_ctx_t ctx;
    uint8_t pt[16], ct[16], dec[16];
    uint32_t t, i;
    uint32_t enc_sum = 0, dec_sum = 0;
    r.enc_min = UINT32_MAX; r.enc_max = 0;
    r.dec_min = UINT32_MAX; r.dec_max = 0;

    /* Kulcsgenerálás mérése */
    t = dwt_get();
    speck128_init(&ctx, TEST_KEY);
    r.keyschedule = dwt_elapsed(t);

    for (i = 0; i < BENCH_ITERATIONS; i++) {
        memcpy(pt, TEST_PT, 16);

        /* Titkosítás */
        t = dwt_get();
        speck128_encrypt(&ctx, pt, ct);
        t = dwt_elapsed(t);
        UPDATE_STATS(t, r.enc_min, r.enc_max, enc_sum);

        /* Visszafejtés */
        t = dwt_get();
        speck128_decrypt(&ctx, ct, dec);
        t = dwt_elapsed(t);
        UPDATE_STATS(t, r.dec_min, r.dec_max, dec_sum);
    }

    r.enc_avg = enc_sum / BENCH_ITERATIONS;
    r.dec_avg = dec_sum / BENCH_ITERATIONS;
    return r;
}

/* -----------------------------------------------------------------------
 * LEA-128 benchmark
 * ----------------------------------------------------------------------- */
bench_result_t benchmark_lea(void) {
    bench_result_t r = { .name = "LEA-128" };
    LEAKEY ctx;
    uint8_t ct[16], dec[16];
    uint32_t t, i;
    uint32_t enc_sum = 0, dec_sum = 0;
    r.enc_min = UINT32_MAX; r.enc_max = 0;
    r.dec_min = UINT32_MAX; r.dec_max = 0;

    /* Kulcsgenerálás mérése */
    t = dwt_get();
    leasetkey(&ctx, TEST_KEY, 16);  /* 16 byte = 128-bites kulcs */
    r.keyschedule = dwt_elapsed(t);

    for (i = 0; i < BENCH_ITERATIONS; i++) {
        /* Titkosítás */
        t = dwt_get();
        leaencrypt(ct, TEST_PT, &ctx);
        t = dwt_elapsed(t);
        UPDATE_STATS(t, r.enc_min, r.enc_max, enc_sum);

        /* Visszafejtés */
        t = dwt_get();
        leadecrypt(dec, ct, &ctx);
        t = dwt_elapsed(t);
        UPDATE_STATS(t, r.dec_min, r.dec_max, dec_sum);
    }

    r.enc_avg = enc_sum / BENCH_ITERATIONS;
    r.dec_avg = dec_sum / BENCH_ITERATIONS;
    return r;
}

/* -----------------------------------------------------------------------
 * ASCON-128a benchmark
 * ASCON AEAD: nincs különálló key schedule — az init a permutácio reszeként
 * fut minden híváskor. A "keyschedule" mezőt 0-ra állítjuk.
 * ----------------------------------------------------------------------- */
bench_result_t benchmark_ascon(void) {
    bench_result_t r = { .name = "ASCON-128a" };
    /* ASCON-128a: ct = pt + 16 byte tag */
    uint8_t ct[16 + CRYPTO_ABYTES];
    uint8_t dec[16];
    unsigned long long clen, mlen;
    uint32_t t, i;
    uint32_t enc_sum = 0, dec_sum = 0;
    r.enc_min = UINT32_MAX; r.enc_max = 0;
    r.dec_min = UINT32_MAX; r.dec_max = 0;
    r.keyschedule = 0;  /* ASCON-ban nincs elokeszitett key schedule */

    for (i = 0; i < BENCH_ITERATIONS; i++) {
        /* Titkosítás */
        t = dwt_get();
        crypto_aead_encrypt(
            ct, &clen,
            TEST_PT, 16,    /* plaintext, 16 byte */
            NULL, 0,        /* associated data: ures */
            NULL,           /* nsec: unused */
            TEST_NONCE,     /* nonce */
            TEST_KEY        /* key */
        );
        t = dwt_elapsed(t);
        UPDATE_STATS(t, r.enc_min, r.enc_max, enc_sum);

        /* Visszafejtés */
        t = dwt_get();
        crypto_aead_decrypt(
            dec, &mlen,
            NULL,           /* nsec: unused */
            ct, clen,       /* ciphertext + tag */
            NULL, 0,        /* associated data: ures */
            TEST_NONCE,
            TEST_KEY
        );
        t = dwt_elapsed(t);
        UPDATE_STATS(t, r.dec_min, r.dec_max, dec_sum);
    }

    r.enc_avg = enc_sum / BENCH_ITERATIONS;
    r.dec_avg = dec_sum / BENCH_ITERATIONS;
    return r;
}

/* -----------------------------------------------------------------------
 * Összes algoritmus futtatása + eredmény kiírás
 * ----------------------------------------------------------------------- */
void benchmark_run_all(void) {
    bench_result_t results[4];

    results[0] = benchmark_aes();
    results[1] = benchmark_speck();
    results[2] = benchmark_lea();
    results[3] = benchmark_ascon();

    benchmark_print_results(results, 4);
}

/* -----------------------------------------------------------------------
 * Eredmény kiírása UART-on (printf → UART redirect szükséges CubeIDE-ben)
 * ----------------------------------------------------------------------- */
void benchmark_print_results(const bench_result_t* results, uint8_t count) {
    uint8_t i;
    printf("\r\n========================================\r\n");
    printf("  LWC Benchmark eredmenyek — STM32F4\r\n");
    printf("  CPU: %lu MHz, Iteraciok: %u\r\n",
           BENCH_CPU_HZ / 1000000UL, BENCH_ITERATIONS);
    printf("  Meresegyseg: CPU ciklus (1 blokk = 16 byte)\r\n");
    printf("========================================\r\n\r\n");

    for (i = 0; i < count; i++) {
        const bench_result_t* r = &results[i];
        printf("--- %s ---\r\n", r->name);
        printf("  Kulcsgenerulas:  %7lu ciklus\r\n",
               (unsigned long)r->keyschedule);
        printf("  Titkositas  min: %7lu  avg: %7lu  max: %7lu ciklus\r\n",
               (unsigned long)r->enc_min,
               (unsigned long)r->enc_avg,
               (unsigned long)r->enc_max);
        printf("  Visszafejtes min:%7lu  avg: %7lu  max: %7lu ciklus\r\n",
               (unsigned long)r->dec_min,
               (unsigned long)r->dec_avg,
               (unsigned long)r->dec_max);
        /* cycles/byte: 16 byte-os blokkon */
        printf("  Titkositas:      %.2f ciklus/byte\r\n",
               (float)r->enc_avg / 16.0f);
        printf("  Visszafejtes:    %.2f ciklus/byte\r\n\r\n",
               (float)r->dec_avg / 16.0f);
    }
    printf("========================================\r\n");
}
