#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <stdint.h>

/* -----------------------------------------------------------------------
 * Benchmark konfiguráció
 * ----------------------------------------------------------------------- */

/* Egy mérési blokkban titkositott adatmennyiseg (byte) */
#define BENCH_DATA_BYTES   16u      /* 1 blokk = 16 byte (AES/SPECK/LEA) */

/* Ismetlesek szama — statisztikai megbizhatosaghoz */
#define BENCH_ITERATIONS   1000u

/* CPU frekvencia (Hz) — STM32F4 alapertelmezett 168 MHz */
#define BENCH_CPU_HZ       168000000UL

/* -----------------------------------------------------------------------
 * Eredmeny struktura
 * ----------------------------------------------------------------------- */
typedef struct {
    const char* name;           /* Algoritmus neve, pl. "AES-128" */
    uint32_t    enc_min;        /* Minimalis titkositasi ciklus */
    uint32_t    enc_max;        /* Maximalis titkositasi ciklus */
    uint32_t    enc_avg;        /* Atlagos titkositasi ciklus */
    uint32_t    dec_min;        /* Minimalis visszafejtes ciklus */
    uint32_t    dec_max;        /* Maximalis visszafejtes ciklus */
    uint32_t    dec_avg;        /* Atlagos visszafejtes ciklus */
    uint32_t    keyschedule;    /* Kulcsgenerálás ciklusa (egyszer) */
} bench_result_t;

/* -----------------------------------------------------------------------
 * Fuggveny deklaraciok
 * ----------------------------------------------------------------------- */

/**
 * @brief Az osszes algoritmus benchmarkjanak futtatasa.
 *        Sorrendben: AES-128, SPECK-128/128, LEA-128, ASCON-128a
 */
void benchmark_run_all(void);

/**
 * @brief Eredmenyek kiiratasa UART-on (HAL_UART_Transmit bazisu).
 */
void benchmark_print_results(const bench_result_t* results, uint8_t count);

/* Egyes algoritmusok benchmarkjai */
bench_result_t benchmark_aes(void);
bench_result_t benchmark_speck(void);
bench_result_t benchmark_lea(void);
bench_result_t benchmark_ascon(void);

#endif /* BENCHMARK_H */
