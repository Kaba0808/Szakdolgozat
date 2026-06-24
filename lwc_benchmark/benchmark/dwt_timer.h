#ifndef DWT_TIMER_H
#define DWT_TIMER_H

#include <stdint.h>

/* STM32 DWT (Data Watchpoint and Trace) cycle counter
 * Cortex-M4 beepitett cikluszamolo, 1 ciklus pontossaggal meri az eltelt
 * CPU ciklusokat. 168 MHz-en 1 ciklus = ~5.95 ns.
 */

/* CoreDebug es DWT regiszterek (CMSIS nelkuli, hordozhato definicio) */
#define DWT_CYCCNT   (*((volatile uint32_t*)0xE0001004))
#define DWT_CTRL     (*((volatile uint32_t*)0xE0001000))
#define CoreDebug_DEMCR (*((volatile uint32_t*)0xE000EDFC))
#define CoreDebug_DEMCR_TRCENA_Msk (1UL << 24)
#define DWT_CTRL_CYCCNTENA_Msk     (1UL << 0)

/**
 * @brief DWT cikluszamolo inicializalasa.
 *        A main() elejen egyszer kell meghivni.
 */
static inline void dwt_init(void) {
    CoreDebug_DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT_CYCCNT = 0;
    DWT_CTRL |= DWT_CTRL_CYCCNTENA_Msk;
}

/**
 * @brief Aktualis ciklusszam visszaadasa.
 */
static inline uint32_t dwt_get(void) {
    return DWT_CYCCNT;
}

/**
 * @brief Eltelt ciklus kiszamitasa (tulcsordulas-biztos).
 */
static inline uint32_t dwt_elapsed(uint32_t start) {
    return DWT_CYCCNT - start;
}

#endif /* DWT_TIMER_H */
