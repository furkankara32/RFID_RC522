/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : PROJ-2 RFID VERIFY (hardcoded password)
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <stdio.h>
#include <string.h>
#include "MFRC522_STM32.h"
#include "MFRC522_MIFARE.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
/* ---------- USER SETTINGS ---------- */
#define TOKEN_BLOCK   4                 // Sector1, Block0 (safe data block)
static const char EXPECTED_PW[] = "furkan123";

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/

SPI_HandleTypeDef hspi1;

UART_HandleTypeDef huart3;

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_SPI1_Init(void);
static void MX_USART3_UART_Init(void);
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
static MFRC522_t rfid;

/* --- printf -> USART3 --- */
int _write(int fd, char *buf, int len)
{
    (void)fd;
    HAL_UART_Transmit(&huart3, (uint8_t*)buf, (uint16_t)len, 200);
    return len;
}

/* Token format: 'P','W',len,(ascii...) */
static int token_has_pw(const uint8_t t[16])
{
    if (t[0] != 'P' || t[1] != 'W') return 0;
    if (t[2] > 13) return 0;
    return 1;
}

static void token_get_pw(const uint8_t t[16], char out[14])
{
    memset(out, 0, 14);
    uint8_t n = t[2];
    if (n > 13) n = 13;
    memcpy(out, &t[3], n);
}

static void leds_ok(void)
{
    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_0,  GPIO_PIN_SET);   // PB0 ON
    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_14, GPIO_PIN_RESET); // PB14 OFF
}

static void leds_fail(void)
{
    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_0,  GPIO_PIN_RESET); // PB0 OFF
    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_14, GPIO_PIN_SET);   // PB14 ON
}

static void leds_idle(void)
{
    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_0,  GPIO_PIN_RESET);
    HAL_GPIO_WritePin(GPIOB, GPIO_PIN_14, GPIO_PIN_RESET);
}

static void waitcardRemoval(void)
{
    uint8_t atqa[2];
    /* Card removal detection: keep trying REQA; once it fails consistently -> removed */
    uint32_t stableMiss = 0;
    while (1) {
        if (MFRC522_PICC_RequestA(&rfid, atqa) == STATUS_OK) {
            stableMiss = 0;
        } else {
            stableMiss++;
            if (stableMiss > 10) break; // ~10*50ms = 500ms
        }
        HAL_Delay(50);
    }
}

static void process_card_once_verify(void)
{
    uint8_t atqa[2] = {0};
    uint8_t uid_bcc[5] = {0};
    uint8_t uid4[4] = {0};
    uint8_t sak = 0;

    /* Try REQA; if card is halted, try WUPA */
    uint8_t st = MFRC522_PICC_RequestA(&rfid, atqa);
    if (st != STATUS_OK) {
        st = MFRC522_PICC_WakeupA(&rfid, atqa);
        if (st != STATUS_OK) return;
    }

    if (MFRC522_PICC_AnticollCL1(&rfid, uid_bcc) != STATUS_OK) return;

    memcpy(uid4, uid_bcc, 4);

    printf("\r\n[CARD] UID: %02X %02X %02X %02X\r\n", uid4[0],uid4[1],uid4[2],uid4[3]);
    printf("[CARD] ATQA: %02X %02X\r\n", atqa[0], atqa[1]);

    if (MFRC522_SelectCL1_GetSAK(&rfid, uid_bcc, &sak) != STATUS_OK) {
        printf("[CARD] SELECT FAIL\r\n");
        leds_fail();
        printf("[CARD] Kart kaldirilinca devam...\r\n");
        waitcardRemoval();
        return;
    }
    printf("[CARD] SAK: %02X\r\n", sak);

    /* AUTH + READ token */
    uint8_t keyA[6] = KEYA_DEFAULT_6B;
    uint8_t tok[16] = {0};

    if (MFRC522_MifareAuthKeyA(&rfid, TOKEN_BLOCK, keyA, uid4) != STATUS_OK) {
        printf("[AUTH] FAIL (Block %d)\r\n", TOKEN_BLOCK);
        leds_fail();
        MFRC522_StopCrypto1(&rfid);
        (void)MFRC522_PICC_HaltA(&rfid);
        printf("[CARD] Kart kaldirilinca devam...\r\n");
        waitcardRemoval();
        return;
    }

    if (MFRC522_MifareReadBlock16(&rfid, TOKEN_BLOCK, tok) != STATUS_OK) {
        printf("[READ] FAIL (Block %d)\r\n", TOKEN_BLOCK);
        leds_fail();
        MFRC522_StopCrypto1(&rfid);
        (void)MFRC522_PICC_HaltA(&rfid);
        printf("[CARD] Kart kaldirilinca devam...\r\n");
        waitcardRemoval();
        return;
    }

    if (!token_has_pw(tok)) {
        printf("[CARD] TOKEN YOK (Block %d)\r\n", TOKEN_BLOCK);
        leds_fail();
    } else {
        char pw[14];
        token_get_pw(tok, pw);
        printf("TOKEN(PW): %s\r\n", pw);

        if (strcmp(pw, EXPECTED_PW) == 0) {
            printf("[CHECK] SIFRE DOGRU -> PB0 ON\r\n");
            leds_ok();
        } else {
            printf("[CHECK] SIFRE YANLIS -> PB14 ON\r\n");
            leds_fail();
        }
    }

    MFRC522_StopCrypto1(&rfid);
    (void)MFRC522_PICC_HaltA(&rfid);

    printf("[CARD] Kart kaldirilinca devam...\r\n");
    waitcardRemoval();
}

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_SPI1_Init();
  MX_USART3_UART_Init();
  /* USER CODE BEGIN 2 */
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_4, GPIO_PIN_SET); // CS high at boot

    rfid.hspi    = &hspi1;
    rfid.csPort  = GPIOA;
    rfid.csPin   = GPIO_PIN_4;   // CS = PA4
    rfid.rstPort = GPIOA;
    rfid.rstPin  = GPIO_PIN_3;   // RST = PA3

    MFRC522_Init(&rfid);

    leds_idle();

    printf("\r\n=== PROJ-2 RFID VERIFY (HARDCODED PW) ===\r\n");
    printf("EXPECTED_PW = %s\r\n", EXPECTED_PW);
    printf("Token block = %d\r\n", TOKEN_BLOCK);
    printf("Kart okut -> token oku -> karsilastir -> PB0/PB14\r\n");


  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */

      process_card_once_verify();
      HAL_Delay(50);

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

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE3);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSI;
  RCC_OscInitStruct.HSIState = RCC_HSI_ON;
  RCC_OscInitStruct.HSICalibrationValue = RCC_HSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_NONE;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_HSI;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_0) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief SPI1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_SPI1_Init(void)
{

  /* USER CODE BEGIN SPI1_Init 0 */

  /* USER CODE END SPI1_Init 0 */

  /* USER CODE BEGIN SPI1_Init 1 */

  /* USER CODE END SPI1_Init 1 */
  /* SPI1 parameter configuration*/
  hspi1.Instance = SPI1;
  hspi1.Init.Mode = SPI_MODE_MASTER;
  hspi1.Init.Direction = SPI_DIRECTION_2LINES;
  hspi1.Init.DataSize = SPI_DATASIZE_8BIT;
  hspi1.Init.CLKPolarity = SPI_POLARITY_LOW;
  hspi1.Init.CLKPhase = SPI_PHASE_1EDGE;
  hspi1.Init.NSS = SPI_NSS_SOFT;
  hspi1.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_16;
  hspi1.Init.FirstBit = SPI_FIRSTBIT_MSB;
  hspi1.Init.TIMode = SPI_TIMODE_DISABLE;
  hspi1.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLE;
  hspi1.Init.CRCPolynomial = 7;
  hspi1.Init.CRCLength = SPI_CRC_LENGTH_DATASIZE;
  hspi1.Init.NSSPMode = SPI_NSS_PULSE_ENABLE;
  if (HAL_SPI_Init(&hspi1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN SPI1_Init 2 */

  /* USER CODE END SPI1_Init 2 */

}

/**
  * @brief USART3 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART3_UART_Init(void)
{

  /* USER CODE BEGIN USART3_Init 0 */

  /* USER CODE END USART3_Init 0 */

  /* USER CODE BEGIN USART3_Init 1 */

  /* USER CODE END USART3_Init 1 */
  huart3.Instance = USART3;
  huart3.Init.BaudRate = 115200;
  huart3.Init.WordLength = UART_WORDLENGTH_8B;
  huart3.Init.StopBits = UART_STOPBITS_1;
  huart3.Init.Parity = UART_PARITY_NONE;
  huart3.Init.Mode = UART_MODE_TX_RX;
  huart3.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart3.Init.OverSampling = UART_OVERSAMPLING_16;
  huart3.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart3.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart3) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART3_Init 2 */

  /* USER CODE END USART3_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOD_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_3, GPIO_PIN_RESET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_4, GPIO_PIN_SET);

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOB, GPIO_PIN_0|GPIO_PIN_14, GPIO_PIN_RESET);

  /*Configure GPIO pin : PA3 */
  GPIO_InitStruct.Pin = GPIO_PIN_3;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_MEDIUM;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

  /*Configure GPIO pin : PA4 */
  GPIO_InitStruct.Pin = GPIO_PIN_4;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_HIGH;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

  /*Configure GPIO pins : PB0 PB14 */
  GPIO_InitStruct.Pin = GPIO_PIN_0|GPIO_PIN_14;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
