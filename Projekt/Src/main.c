/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body (Advanced Crypto Benchmark)
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

// Az algoritmusok header fájljai
#include "aes.h"
#include "speck.h"
#include "lea.h"
#include "ascon128.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */
/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */
/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
/* USER CODE BEGIN PV */
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);

/* USER CODE BEGIN PFP */
// A SPECK nyers függvényeinek bekötése a kulcsgenerálás és a blokk-kezelés méréséhez
extern void Speck128128KeySchedule(const uint64_t K[2], uint64_t rk[32]);
extern void Speck128128Encrypt(const uint64_t Pt[2], uint64_t Ct[2], const uint64_t rk[32]);
extern void Speck128128Decrypt(const uint64_t Ct[2], uint64_t Pt[2], const uint64_t rk[32]);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
// Hivatkozás a generált UART handle-re
extern UART_HandleTypeDef huart2;

// A printf kimenetének átirányítása a soros portra a logoláshoz
int _write(int file, char *ptr, int len) {
    HAL_UART_Transmit(&huart2, (uint8_t*)ptr, len, HAL_MAX_DELAY);
    return len;
}

// DWT regiszterek definíciói a cikluspontos méréshez
#define DWT_CTRL        (*(volatile uint32_t*)0xE0001000)
#define DWT_CYCCNT      (*(volatile uint32_t*)0xE0001004)
#define DEMCR           (*(volatile uint32_t*)0xE000EDFC)
#define DEMCR_TRCENA    0x01000000
#define DWT_CR_CYCCNTENA 0x00000001

// DWT Inicializáló függvény
void DWT_Init(void) {
    DEMCR |= DEMCR_TRCENA;        // Trace engedélyezése
    DWT_CYCCNT = 0;               // Számláló nullázása
    DWT_CTRL |= DWT_CR_CYCCNTENA; // Számláló elindítása
}
/* USER CODE END 0 */

int main(void)
{
  /* MCU Configuration--------------------------------------------------------*/
  HAL_Init();
  SystemClock_Config();

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_USART2_UART_Init();

  /* USER CODE BEGIN 2 */
  DWT_Init(); // DWT cikluszámláló bekapcsolása

  printf("\r\n========================================\r\n");
  printf("STM32 Advanced Crypto Benchmark Indul!\r\n");
  printf("Orajel: %lu Hz\r\n", HAL_RCC_GetHCLKFreq());
  printf("========================================\r\n");

  // Globális mérési beállítások
  #define ITERATIONS 100 // 100-szor futtatjuk le, majd átlagoljuk a zaj kiszűrése végett!
  const uint16_t test_sizes[] = {16, 64, 256, 1024};
  const int num_sizes = 4;

  // 1024 bájtos (+16 a tagnak) pufferek a legnagyobb tesztekhez
  uint8_t key[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
  uint8_t plaintext[1040];
  volatile uint8_t ciphertext[1040];
  volatile uint8_t decrypted[1040];

  // Pufferek feltöltése dummy adattal
  for(int i=0; i<1040; i++) plaintext[i] = i % 256;

  // Algoritmus specifikus struktúrák
  struct AES_ctx aes_ctx;
  LEA_KEY lea_key;
  uint64_t speck_rk[32]; // SPECK kiterjesztett kulcs

  // ASCON specifikus adatok
  uint8_t nonce[16] = {0};
  uint8_t ad[1] = {0};
  unsigned long long clen = 0;
  unsigned long long mlen = 0;

  // Változók a ciklusok méréséhez
  uint32_t start, end;
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */

    // =========================================================================
    // 1. KULCSGENERÁLÁS MÉRÉSE (Key Schedule)
    // =========================================================================

    // AES KeyGen
    start = DWT_CYCCNT;
    for(int i=0; i<ITERATIONS; i++) { AES_init_ctx(&aes_ctx, key); }
    end = DWT_CYCCNT;
    printf("AES-128,KeyGen,0,%lu\r\n", (end - start)/ITERATIONS);

    // SPECK KeyGen
    start = DWT_CYCCNT;
    for(int i=0; i<ITERATIONS; i++) { Speck128128KeySchedule((uint64_t*)key, speck_rk); }
    end = DWT_CYCCNT;
    printf("SPECK-128,KeyGen,0,%lu\r\n", (end - start)/ITERATIONS);

    // LEA KeyGen
    start = DWT_CYCCNT;
    for(int i=0; i<ITERATIONS; i++) { lea_set_key(&lea_key, key, 16); }
    end = DWT_CYCCNT;
    printf("LEA-128,KeyGen,0,%lu\r\n", (end - start)/ITERATIONS);

    // ASCON (Nincs külön kulcsgenerálása a hagyományos értelemben)
    printf("ASCON-128,KeyGen,0,0\r\n");
    HAL_Delay(100);

    // =========================================================================
    // 2. SEBESSÉGMÉRÉS DINAMIKUS CSOMAGMÉRETEKKEL (16, 64, 256, 1024)
    // =========================================================================
    for(int s=0; s<num_sizes; s++)
    {
        uint16_t size = test_sizes[s];

        // ------------------ AES-128 ------------------
        memcpy((void*)ciphertext, plaintext, size); // AES in-place dolgozik

        start = DWT_CYCCNT;
        for(int k=0; k<ITERATIONS; k++) {
            for(int i=0; i<size; i+=16) { AES_ECB_encrypt(&aes_ctx, (uint8_t*)(ciphertext+i)); }
        }
        end = DWT_CYCCNT;
        printf("AES-128,Encrypt,%u,%lu\r\n", size, (end - start)/ITERATIONS);

        start = DWT_CYCCNT;
        for(int k=0; k<ITERATIONS; k++) {
            for(int i=0; i<size; i+=16) { AES_ECB_decrypt(&aes_ctx, (uint8_t*)(ciphertext+i)); }
        }
        end = DWT_CYCCNT;
        printf("AES-128,Decrypt,%u,%lu\r\n", size, (end - start)/ITERATIONS);

        // ------------------ SPECK-128 ------------------
        start = DWT_CYCCNT;
        for(int k=0; k<ITERATIONS; k++) {
            for(int i=0; i<size; i+=16) {
                Speck128128Encrypt((uint64_t*)(plaintext+i), (uint64_t*)(ciphertext+i), speck_rk);
            }
        }
        end = DWT_CYCCNT;
        printf("SPECK-128,Encrypt,%u,%lu\r\n", size, (end - start)/ITERATIONS);

        start = DWT_CYCCNT;
        for(int k=0; k<ITERATIONS; k++) {
            for(int i=0; i<size; i+=16) {
                Speck128128Decrypt((uint64_t*)(ciphertext+i), (uint64_t*)(decrypted+i), speck_rk);
            }
        }
        end = DWT_CYCCNT;
        printf("SPECK-128,Decrypt,%u,%lu\r\n", size, (end - start)/ITERATIONS);

        // ------------------ LEA-128 ------------------
        start = DWT_CYCCNT;
        for(int k=0; k<ITERATIONS; k++) {
            lea_ecb_encrypt((uint8_t*)ciphertext, plaintext, size, &lea_key);
        }
        end = DWT_CYCCNT;
        printf("LEA-128,Encrypt,%u,%lu\r\n", size, (end - start)/ITERATIONS);

        start = DWT_CYCCNT;
        for(int k=0; k<ITERATIONS; k++) {
            lea_ecb_decrypt((uint8_t*)decrypted, (uint8_t*)ciphertext, size, &lea_key);
        }
        end = DWT_CYCCNT;
        printf("LEA-128,Decrypt,%u,%lu\r\n", size, (end - start)/ITERATIONS);

        // ------------------ ASCON-128 ------------------
        start = DWT_CYCCNT;
        for(int k=0; k<ITERATIONS; k++) {
            ascon128_aead_encrypt((uint8_t*)ciphertext, &clen, plaintext, size, ad, 0, NULL, nonce, key);
        }
        end = DWT_CYCCNT;
        printf("ASCON-128,Encrypt,%u,%lu\r\n", size, (end - start)/ITERATIONS);

        start = DWT_CYCCNT;
        for(int k=0; k<ITERATIONS; k++) {
            ascon128_aead_decrypt((uint8_t*)decrypted, &mlen, NULL, (uint8_t*)ciphertext, clen, ad, 0, nonce, key);
        }
        end = DWT_CYCCNT;
        printf("ASCON-128,Decrypt,%u,%lu\r\n", size, (end - start)/ITERATIONS);

        HAL_Delay(100); // Kicsi szünet a méretek között az UART kímélésére
    }

    printf("========================================\r\n");
    HAL_Delay(10000); // 10 másodperc szünet egy teljes tesztkör után

  }
  /* USER CODE END 3 */
}

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
