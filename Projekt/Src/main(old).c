/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : AES-128 / SPECK-128 / LEA-128 / ASCON-128 teljesitmenymeres
  *                    NUCLEO-L432KC (STM32L432KC, Cortex-M4 @ 80 MHz)
  *
  * Menete:
  *   1) onellenorzes hivatalos tesztvektorokkal (hiba eseten nincs meres),
  *   2) NUM_RUNS egymast koveto, teljes meresi kor; egy kor tartalma:
  *      - kulcsgeneralas (AES, SPECK, LEA),
  *      - titkositas/visszafejtes 16, 64, 256 es 1024 bajton.
  *   3) osszesites: median, minimum, maximum, legnagyobb relativ elteres.
  *
  * Egy mert ertek: 1 nem mert bemelegito futas, majd ITERATIONS ismetles
  * atlaga a DWT ciklusszamlaloval, tiltott megszakitasok mellett.
  * Kimenet (USART2, 115200 baud): CSV + osszesito tablazat.
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "usart.h"
#include "gpio.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Az algoritmusok fejlecfajljai */
#include "aes.h"
#include "speck.h"
#include "lea.h"
#include "ascon128.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
/* Egy meres azonositoja (a cimkeket csak egyszer taroljuk, az ertekeket futasonkent) */
typedef struct {
    const char *algo;
    const char *operation;
    uint16_t size;
} MeasLabel;
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define ITERATIONS      100   /* ismetlesek szama egy mert erteken belul (atlag) */
#define NUM_RUNS        10    /* teljes meresi korok szama */
#define NUM_TEST_SIZES  4
#define MAX_MEAS        64    /* meresek szama egy korben (most 44) */

/* DWT regiszterek a cikluspontos mereshez */
#define DWT_CTRL         (*(volatile uint32_t*)0xE0001000)
#define DWT_CYCCNT       (*(volatile uint32_t*)0xE0001004)
#define DEMCR            (*(volatile uint32_t*)0xE000EDFC)
#define DEMCR_TRCENA     0x01000000
#define DWT_CR_CYCCNTENA 0x00000001

/* Forditasi szint felismerese a naplohoz (GCC elore definialt makroi) */
#if !defined(__OPTIMIZE__)
  #define BUILD_OPT "-O0"
#elif defined(__FAST_MATH__)
  #define BUILD_OPT "-Ofast"
#elif defined(__OPTIMIZE_SIZE__)
  #define BUILD_OPT "-Os/-Oz"
#else
  #define BUILD_OPT "-O1/-O2/-O3"
#endif
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */
/* Egy muvelet merese: 1 bemelegito (nem mert) futas, majd ITERATIONS ismetles
   tiltott megszakitasok mellett; az eredmeny az egy hivasra eso atlag. */
#define MEASURE(ALGO, OP, SIZE, CALL)                         \
    do {                                                      \
        CALL;                               /* bemelegites */ \
        __disable_irq();                                      \
        uint32_t t0_ = DWT_CYCCNT;                            \
        for (int k_ = 0; k_ < ITERATIONS; k_++) { CALL; }     \
        uint32_t t1_ = DWT_CYCCNT;                            \
        __enable_irq();                                       \
        Record_Result((ALGO), (OP), (SIZE), (t1_ - t0_) / ITERATIONS); \
    } while (0)
/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */
static MeasLabel labels[MAX_MEAS];
static uint32_t  cycles[NUM_RUNS][MAX_MEAS];
static uint32_t  meas_count = 0;   /* meresek szama egy korben */
static uint32_t  cur_run = 0;      /* aktualis kor sorszama */
static uint32_t  cur_meas = 0;     /* meres sorszama az aktualis korben */

const uint16_t test_sizes[NUM_TEST_SIZES] = {16, 64, 256, 1024};

/* 8 bajtos igazitas: a SPECK a puffereket uint64_t-kent olvassa */
__attribute__((aligned(8))) uint8_t key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
uint8_t iv[16]  = {0xF0, 0xE0, 0xD0, 0xC0, 0xB0, 0xA0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00};

__attribute__((aligned(8))) uint8_t plaintext[1040];
__attribute__((aligned(8))) volatile uint8_t ciphertext[1040];
__attribute__((aligned(8))) volatile uint8_t decrypted[1040];
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
/* USER CODE BEGIN PFP */
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
extern UART_HandleTypeDef huart2;

/* printf -> USART2 atiranyitas */
int _write(int file, char *ptr, int len) {
    (void)file;
    HAL_UART_Transmit(&huart2, (uint8_t*)ptr, len, HAL_MAX_DELAY);
    return len;
}

void DWT_Init(void) {
    DEMCR |= DEMCR_TRCENA;
    DWT_CYCCNT = 0;
    DWT_CTRL |= DWT_CR_CYCCNTENA;
}

// -------------------------------------------------------------------------
// EGYSEGES PUFFER-BURKOLOK (minden algoritmus a teljes uzenetet dolgozza fel)
// -------------------------------------------------------------------------

void aes_buffer_encrypt(struct AES_ctx* ctx, uint8_t* buf, uint16_t size) {
    for (uint16_t i = 0; i < size; i += 16) {
        AES_ECB_encrypt(ctx, buf + i);
    }
}

void aes_buffer_decrypt(struct AES_ctx* ctx, uint8_t* buf, uint16_t size) {
    for (uint16_t i = 0; i < size; i += 16) {
        AES_ECB_decrypt(ctx, buf + i);
    }
}

void speck_buffer_encrypt(const uint8_t* in, uint8_t* out, uint16_t size, const uint64_t* rk) {
    for (uint16_t i = 0; i < size; i += 16) {
        Speck128128Encrypt((const uint64_t*)(in + i), (uint64_t*)(out + i), rk);
    }
}

void speck_buffer_decrypt(const uint8_t* in, uint8_t* out, uint16_t size, const uint64_t* rk) {
    for (uint16_t i = 0; i < size; i += 16) {
        Speck128128Decrypt((const uint64_t*)(in + i), (uint64_t*)(out + i), rk);
    }
}

// -------------------------------------------------------------------------
// EREDMENYEK TAROLASA ES KIIRASA
// -------------------------------------------------------------------------

/* Az elso korben a cimket is eltarolja, a tovabbiakban csak az erteket */
void Record_Result(const char* algo, const char* op, uint16_t size, uint32_t cyc) {
    if (cur_meas < MAX_MEAS) {
        if (cur_run == 0) {
            labels[cur_meas].algo = algo;
            labels[cur_meas].operation = op;
            labels[cur_meas].size = size;
            meas_count = cur_meas + 1;
        }
        cycles[cur_run][cur_meas] = cyc;
        cur_meas++;
    }
}

/* Egy kor eredmenyeinek kiirasa CSV-sorokkent */
void Print_Run_CSV(uint32_t run) {
    for (uint32_t m = 0; m < meas_count; m++) {
        printf("%lu,%s,%s,%u,%lu\r\n", (unsigned long)(run + 1),
               labels[m].algo, labels[m].operation, labels[m].size,
               (unsigned long)cycles[run][m]);
    }
}

/* Median (paros elemszamnal a ket kozepso atlaga), minimum es maximum */
static void Stats(uint32_t m, uint32_t *med, uint32_t *mn, uint32_t *mx) {
    uint32_t v[NUM_RUNS];
    for (uint32_t r = 0; r < NUM_RUNS; r++) v[r] = cycles[r][m];
    for (uint32_t i = 1; i < NUM_RUNS; i++) {          /* beszuro rendezes */
        uint32_t x = v[i]; int32_t j = (int32_t)i - 1;
        while (j >= 0 && v[j] > x) { v[j + 1] = v[j]; j--; }
        v[j + 1] = x;
    }
    *mn = v[0];
    *mx = v[NUM_RUNS - 1];
    *med = (NUM_RUNS % 2) ? v[NUM_RUNS / 2]
                          : (v[NUM_RUNS / 2 - 1] + v[NUM_RUNS / 2] + 1) / 2;
}

/* Osszesito: median, min, max es a (max - min) / median relativ szoras.
   Egesz aritmetika (a newlib-nano printf nem ir ki lebegopontos szamot). */
void Print_Summary(void) {
    printf("\r\n=====================================================================\r\n");
    printf("| %-10s | %-8s | %-6s | %-10s | %-10s | %-10s | %-7s |\r\n",
           "Algoritmus", "Muvelet", "Meret", "Median", "Min", "Max", "Elteres");
    printf("=====================================================================\r\n");
    for (uint32_t m = 0; m < meas_count; m++) {
        uint32_t med, mn, mx;
        Stats(m, &med, &mn, &mx);
        uint32_t dev = (med > 0) ? (uint32_t)(((uint64_t)(mx - mn) * 10000u) / med) : 0;
        printf("| %-10s | %-8s | %-6u | %-10lu | %-10lu | %-10lu | %2lu.%02lu %% |\r\n",
               labels[m].algo, labels[m].operation, labels[m].size,
               (unsigned long)med, (unsigned long)mn, (unsigned long)mx,
               (unsigned long)(dev / 100), (unsigned long)(dev % 100));
    }
    printf("=====================================================================\r\n");

    printf("\r\n--- OSSZESITO CSV ---\r\n");
    printf("Algoritmus,Muvelet,Meret,Median,Min,Max\r\n");
    for (uint32_t m = 0; m < meas_count; m++) {
        uint32_t med, mn, mx;
        Stats(m, &med, &mn, &mx);
        printf("%s,%s,%u,%lu,%lu,%lu\r\n", labels[m].algo, labels[m].operation,
               labels[m].size, (unsigned long)med, (unsigned long)mn, (unsigned long)mx);
    }
    printf("---------------------\r\n");
}

// -------------------------------------------------------------------------
// ONELLENORZES: hivatalos tesztvektorok es titkositas->visszafejtes korut
// -------------------------------------------------------------------------
static int check(const char* name, const uint8_t* got, const uint8_t* exp, int n) {
    int ok = (memcmp(got, exp, n) == 0);
    printf("  %-28s %s\r\n", name, ok ? "OK" : "HIBA");
    return ok;
}

int Run_SelfTests(void) {
    int ok = 1;
    printf("Onellenorzes:\r\n");

    /* AES-128: NIST SP 800-38A, F.1.1 ECB-AES128 */
    {
        const uint8_t k[16]  = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
        const uint8_t p[16]  = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
        const uint8_t c[16]  = {0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97};
        struct AES_ctx ctx; uint8_t b[16];
        AES_init_ctx(&ctx, k); memcpy(b, p, 16);
        AES_ECB_encrypt(&ctx, b);  ok &= check("AES-128 tesztvektor", b, c, 16);
        AES_ECB_decrypt(&ctx, b);  ok &= check("AES-128 visszafejtes", b, p, 16);
    }
    /* SPECK128/128: NSA Implementation Guide v1.1, tesztvektor */
    {
        __attribute__((aligned(8))) const uint8_t k[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
        __attribute__((aligned(8))) const uint8_t p[16] = {0x20,0x6d,0x61,0x64,0x65,0x20,0x69,0x74,0x20,0x65,0x71,0x75,0x69,0x76,0x61,0x6c};
        const uint8_t c[16] = {0x18,0x0d,0x57,0x5c,0xdf,0xfe,0x60,0x78,0x65,0x32,0x78,0x79,0x51,0x98,0x5d,0xa6};
        uint64_t rk[32], b[2], d[2];
        Speck128128KeySchedule((const uint64_t*)k, rk);
        Speck128128Encrypt((const uint64_t*)p, b, rk);  ok &= check("SPECK-128 tesztvektor", (uint8_t*)b, c, 16);
        Speck128128Decrypt(b, d, rk);                   ok &= check("SPECK-128 visszafejtes", (uint8_t*)d, p, 16);
    }
    /* LEA-128: KISA tesztvektor */
    {
        const uint8_t k[16] = {0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,0x87,0x96,0xa5,0xb4,0xc3,0xd2,0xe1,0xf0};
        const uint8_t p[16] = {0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
        const uint8_t c[16] = {0x9f,0xc8,0x4e,0x35,0x28,0xc6,0xc6,0x18,0x55,0x32,0xc7,0xa7,0x04,0x64,0x8b,0xfd};
        LEA_KEY lk; uint8_t b[16], d[16];
        lea_set_key(&lk, k, 16);
        lea_encrypt(b, p, &lk);  ok &= check("LEA-128 tesztvektor", b, c, 16);
        lea_decrypt(d, b, &lk);  ok &= check("LEA-128 visszafejtes", d, p, 16);
    }
    /* ASCON-128: hivatalos KAT (LWC_AEAD_KAT_128_128.txt, Count 529 es 545)
       + korut + a meghamisitott titkositott szoveg elutasitasa */
    {
        uint8_t k[16], n[16], p[16], ad16[16], c[32], d[16];
        unsigned long long cl, ml;
        const uint8_t ct529[32] = {0xBC,0x82,0x0D,0xBD,0xF7,0xA4,0x63,0x1C,0x5B,0x29,0x88,0x4A,0xD6,0x91,0x75,0xC3,
                                   0xF5,0x8E,0x28,0x43,0x6D,0xD7,0x15,0x56,0xD5,0x8D,0xFA,0x56,0xAC,0x89,0x0B,0xEB};
        const uint8_t ct545[32] = {0x1E,0xE3,0x41,0x25,0xFD,0xBA,0x17,0x44,0x3D,0x01,0xDA,0x8A,0x0E,0xEF,0xB0,0x45,
                                   0x42,0x81,0xD1,0xD3,0xB9,0x62,0x41,0x8D,0x2E,0x1C,0x8A,0x6D,0x14,0xF3,0xE8,0xA2};
        for (int i = 0; i < 16; i++) { k[i] = n[i] = p[i] = ad16[i] = (uint8_t)i; }

        ascon128_aead_encrypt(c, &cl, p, 16, NULL, 0, NULL, n, k);
        ok &= check("ASCON-128 KAT (AD nelkul)", c, ct529, 32);
        int r1 = ascon128_aead_decrypt(d, &ml, NULL, c, cl, NULL, 0, n, k);
        ok &= check("ASCON-128 visszafejtes", d, p, 16) && (r1 == 0);

        ascon128_aead_encrypt(c, &cl, p, 16, ad16, 16, NULL, n, k);
        ok &= check("ASCON-128 KAT (16 B AD)", c, ct545, 32);

        c[0] ^= 1;
        int r2 = ascon128_aead_decrypt(d, &ml, NULL, c, cl, ad16, 16, n, k);
        printf("  %-28s %s\r\n", "ASCON-128 hamis uzenet", (r2 != 0) ? "OK (elutasitva)" : "HIBA");
        ok &= (r2 != 0);
    }
    printf("Onellenorzes: %s\r\n\r\n", ok ? "MINDEN OK" : "HIBA - a meres eredmenyei nem ervenyesek!");
    return ok;
}

// -------------------------------------------------------------------------
// EGY TELJES MERESI KOR
// -------------------------------------------------------------------------
void Run_Benchmark(void) {
    static struct AES_ctx aes_ctx;
    static LEA_KEY lea_key;
    static uint64_t speck_rk[32];

    uint8_t nonce[16] = {0};
    uint8_t ad[1] = {0};
    unsigned long long clen = 0;
    unsigned long long mlen = 0;

    cur_meas = 0;

    /* 1. Kulcsgeneralas */
    MEASURE("AES-128",   "KeyGen", 0, AES_init_ctx(&aes_ctx, key));
    MEASURE("SPECK-128", "KeyGen", 0, Speck128128KeySchedule((const uint64_t*)key, speck_rk));
    MEASURE("LEA-128",   "KeyGen", 0, lea_set_key(&lea_key, key, 16));
    Record_Result("ASCON-128", "KeyGen", 0, 0);   /* nincs kulon kulcsgeneralas */

    /* 2. Titkositas es visszafejtes a kulonbozo uzenetmereteken */
    for (int s = 0; s < NUM_TEST_SIZES; s++) {
        uint16_t size = test_sizes[s];

        /* --- AES-128 ECB --- */
        AES_init_ctx(&aes_ctx, key);
        memcpy((void*)ciphertext, plaintext, size);
        MEASURE("AES-128", "Encrypt", size, aes_buffer_encrypt(&aes_ctx, (uint8_t*)ciphertext, size));
        MEASURE("AES-128", "Decrypt", size, aes_buffer_decrypt(&aes_ctx, (uint8_t*)ciphertext, size));

        /* --- AES-128 CTR (kiegeszito, szimmetrikus meres) --- */
        AES_init_ctx_iv(&aes_ctx, key, iv);
        memcpy((void*)ciphertext, plaintext, size);
        MEASURE("AES-CTR", "Encrypt", size, AES_CTR_xcrypt_buffer(&aes_ctx, (uint8_t*)ciphertext, size));
        AES_init_ctx_iv(&aes_ctx, key, iv);
        MEASURE("AES-CTR", "Decrypt", size, AES_CTR_xcrypt_buffer(&aes_ctx, (uint8_t*)ciphertext, size));

        /* --- SPECK-128 (elore kiszamolt korkulcsokkal) --- */
        MEASURE("SPECK-128", "Encrypt", size, speck_buffer_encrypt(plaintext, (uint8_t*)ciphertext, size, speck_rk));
        MEASURE("SPECK-128", "Decrypt", size, speck_buffer_decrypt((uint8_t*)ciphertext, (uint8_t*)decrypted, size, speck_rk));

        /* --- LEA-128 (elore kiszamolt korkulcsokkal) --- */
        MEASURE("LEA-128", "Encrypt", size, lea_ecb_encrypt((uint8_t*)ciphertext, plaintext, size, &lea_key));
        MEASURE("LEA-128", "Decrypt", size, lea_ecb_decrypt((uint8_t*)decrypted, (uint8_t*)ciphertext, size, &lea_key));

        /* --- ASCON-128 (AEAD, ures kapcsolodo adat) --- */
        MEASURE("ASCON-128", "Encrypt", size,
                ascon128_aead_encrypt((uint8_t*)ciphertext, &clen, plaintext, size, ad, 0, NULL, nonce, key));
        MEASURE("ASCON-128", "Decrypt", size,
                ascon128_aead_decrypt((uint8_t*)decrypted, &mlen, NULL, (uint8_t*)ciphertext, clen, ad, 0, nonce, key));
    }
}
/* USER CODE END 0 */

int main(void)
{
  /* MCU Configuration--------------------------------------------------------*/
  HAL_Init();
  SystemClock_Config();
  MX_GPIO_Init();
  MX_USART2_UART_Init();

  /* USER CODE BEGIN 2 */
  DWT_Init();

  for (int i = 0; i < 1040; i++) plaintext[i] = (uint8_t)(i % 256);

  printf("\r\n\r\n========================================\r\n");
  printf("STM32 Crypto Benchmark Indul...\r\n");
  printf("Orajel: %lu Hz\r\n", (unsigned long)HAL_RCC_GetHCLKFreq());
  printf("Forditas: %s, ismetles/meres: %d, korok: %d\r\n", BUILD_OPT, ITERATIONS, NUM_RUNS);
  printf("========================================\r\n\r\n");

  if (!Run_SelfTests()) {
      while (1) { HAL_Delay(1000); }   /* hibas implementacioval nem merunk */
  }

  /* NUM_RUNS teljes meresi kor; minden kor utan kiirjuk a CSV-sorokat.
     A kiiras a mert szakaszokon kivul tortenik, igy a merest nem befolyasolja. */
  printf("--- CSV (minden kor) ---\r\n");
  printf("Futas,Algoritmus,Muvelet,Meret,Ciklus\r\n");
  for (cur_run = 0; cur_run < NUM_RUNS; cur_run++) {
      Run_Benchmark();
      Print_Run_CSV(cur_run);
  }
  printf("------------------------\r\n");

  Print_Summary();
  printf("\r\nMeres befejezve. Ujrainditashoz nyomd meg a RESET gombot a panelen.\r\n");
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    HAL_Delay(1000);
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1) != HAL_OK)
  {
    Error_Handler();
  }

  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_MSI;
  RCC_OscInitStruct.MSIState = RCC_MSI_ON;
  RCC_OscInitStruct.MSICalibrationValue = 0;
  RCC_OscInitStruct.MSIClockRange = RCC_MSIRANGE_6;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_MSI;
  RCC_OscInitStruct.PLL.PLLM = 1;
  RCC_OscInitStruct.PLL.PLLN = 40;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV7;
  RCC_OscInitStruct.PLL.PLLQ = RCC_PLLQ_DIV2;
  RCC_OscInitStruct.PLL.PLLR = RCC_PLLR_DIV2;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_4) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  __disable_irq();
  while (1)
  {
  }
}

#ifdef  USE_FULL_ASSERT
void assert_failed(uint8_t *file, uint32_t line)
{
}
#endif /* USE_FULL_ASSERT */
