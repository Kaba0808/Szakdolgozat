/**
 * main_benchmark.c
 * ----------------
 * Ezt a tartalmat illeszd be a CubeIDE-ben generalt main.c fajlba,
 * a /* USER CODE BEGIN ... * / blokkok koze.
 *
 * SZÜKSÉGES BEALLITASOK (CubeIDE):
 *   1. UART redirect printf-hez:
 *      - syscalls.c-ben a _write() függvény irja at UART-ra
 *      - vagy: #include "usart.h" + HAL_UART_Transmit hasznalatával
 *   2. Include path: algorithms/ mappara mutasson
 *   3. Source files: algorithms/aes/aes.c,
 *                    algorithms/speck/speck.c,
 *                    algorithms/lea/lea_core.c,
 *                    algorithms/lea/lea_base.c,
 *                    algorithms/lea/lea_t_fallback.c,
 *                    algorithms/lea/lea_t_generic.c,
 *                    algorithms/lea/lea_gcm_generic.c,
 *                    algorithms/ascon/encrypt.c
 *      mind hozzaadva a projekthez (Add to Build)
 */

/* USER CODE BEGIN Includes */
#include "benchmark.h"
#include "dwt_timer.h"
/* USER CODE END Includes */

/* ... HAL init, SystemClock_Config(), MX_ init fuggvenyek ... */

int main(void) {
    /* USER CODE BEGIN 1 */
    /* USER CODE END 1 */

    HAL_Init();
    SystemClock_Config();
    MX_GPIO_Init();
    MX_USART2_UART_Init();   /* UART2: TX=PA2, RX=PA3 (Nucleo alapertelmezett) */

    /* USER CODE BEGIN 2 */
    dwt_init();              /* DWT cikluszamolo bekapcsolasa */

    HAL_Delay(100);          /* Varakozas az UART stabilizalasara */

    benchmark_run_all();     /* Mind a 4 algoritmus merese + kiiras */
    /* USER CODE END 2 */

    while (1) {
        /* USER CODE BEGIN WHILE */
        HAL_Delay(1000);
        /* USER CODE END WHILE */
    }
}
