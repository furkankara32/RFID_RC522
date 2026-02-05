/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "MFRC522_STM32.h"
#include "MFRC522_MIFARE.h"
#include <string.h>
#include <stdio.h>
#include <ctype.h>
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

SPI_HandleTypeDef hspi1;

UART_HandleTypeDef huart3;

/* USER CODE BEGIN PV */
static MFRC522_t rfid;
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART3_UART_Init(void);
static void MX_SPI1_Init(void);
/* USER CODE BEGIN PFP */

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
/* --- printf -> USART3 --- */
int _write(int fd, char *buf, int len)
{
    (void)fd;
    HAL_UART_Transmit(&huart3, (uint8_t*)buf, (uint16_t)len, 200);
    return len;
}

/* --- UART line input (interrupt) --- */
static uint8_t rxByte;
static volatile uint8_t lineReady = 0;
static char lineBuf[80];
static volatile uint16_t lineLen = 0;

static uint8_t pendingToken[16];
static volatile uint8_t pendingWrite = 0;

/* --- Token helper (PW + len + ascii) --- */
static void make_token_from_password(const char *pw, uint8_t out16[16], uint8_t *usedLen)
{
    memset(out16, 0x00, 16);
    out16[0] = 'P';
    out16[1] = 'W';

    size_t n = strlen(pw);
    if (n > 13) n = 13;          // 16 byte içinde header var
    out16[2] = (uint8_t)n;
    memcpy(&out16[3], pw, n);

    if (usedLen) *usedLen = (uint8_t)n;
}

static int token_has_pw(const uint8_t t[16])
{
    if (t[0] != 'P' || t[1] != 'W') return 0;
    if (t[2] > 13) return 0;
    return 1;
}

static void print_token_pw(const uint8_t t[16])
{
    uint8_t n = t[2];
    char s[14] = {0};
    memcpy(s, &t[3], n);
    printf("TOKEN(PW): %s (len=%u)\r\n", s, n);
}

static void handle_line(void)
{
    if (!lineReady) return;
    lineReady = 0;

    if (strncmp(lineBuf, "PSWRD:", 6) == 0) {
        const char *pw = &lineBuf[6];

        uint8_t usedLen = 0;
        make_token_from_password(pw, pendingToken, &usedLen);
        pendingWrite = 1;

        printf("[CMD] PSWRD alindi: %s\r\n", pw);
        printf("[CMD] Karti okutulu tut (token yazilacak)\r\n");
    } else {
        printf("[CMD] Bilinmeyen komut: %s\r\n", lineBuf);
    }
}




static void process_card_once(void)
{
    uint8_t atqa[2] = {0};
    uint8_t uid_bcc[5] = {0};
    uint8_t uid4[4] = {0};

    if (MFRC522_PICC_WakeupA(&rfid, atqa) != STATUS_OK && MFRC522_PICC_RequestA(&rfid, atqa) != STATUS_OK) return;
    if (MFRC522_PICC_Anticoll_CL1(&rfid, uid_bcc) != STATUS_OK) return;

    memcpy(uid4, uid_bcc, 4);
    printf("\r\n[CARD] UID: %02X %02X %02X %02X\r\n", uid4[0], uid4[1], uid4[2], uid4[3]);
    printf("[CARD] ATQA: %02X %02X\r\n", atqa[0], atqa[1]);

    uint8_t sak = 0;
    if (MFRC522_SelectCL1(&rfid, uid_bcc, &sak) == STATUS_OK) {
        printf("[CARD] SAK: %02X\r\n", sak);
    } else {
        printf("[CARD] SELECT FAIL\r\n");
        printf("[CARD] Kart kaldirilinca devam...\r\n");
        MFRC522_WaitCardRemoval(&rfid);
        return;
    }

    const uint8_t keyA[6] = KEYA_DEFAULT_6B;

    // 1) Önce TOKEN_BLOCK dene, olmazsa Block 1'e fallback
    uint8_t blocks_to_try[2] = {TOKEN_BLOCK, 1};
    uint8_t used_block = 0xFF;

    for (int bi = 0; bi < 2; bi++) {
        uint8_t b = blocks_to_try[bi];

        uint8_t stAuth = MFRC522_MifareAuthKeyA(&rfid, b, keyA, uid4);
        if (stAuth != STATUS_OK) {
            printf("[AUTH] KeyA FAIL (Block %u). st=%u ErrorReg=0x%02X Status2Reg=0x%02X\r\n",
                   b, stAuth, MFRC522_ReadReg(&rfid, PCD_ErrorReg), MFRC522_ReadReg(&rfid, PCD_Status2Reg));
            continue;
        }

        used_block = b;

        // Token oku (aynı auth oturumunda)
        uint8_t tok[16] = {0};
        if (MFRC522_MifareReadBlock16(&rfid, b, tok) == STATUS_OK) {
            if (token_has_pw(tok)) {
                print_token_pw(tok);
            } else {
                printf("[CARD] TOKEN YOK (Block %u)\r\n", b);
            }
        } else {
            printf("[CARD] TOKEN okunamadi. (READ hata) Block %u\r\n", b);
        }

        // Eğer terminalden PSWRD geldiyse aynı auth oturumunda yaz + verify
        if (pendingWrite) {
            printf("[WRITE] Token yaziliyor (Block %u)...\r\n", b);

            if (MFRC522_MifareWriteBlock16(&rfid, b, pendingToken) == STATUS_OK) {
                uint8_t ver[16] = {0};
                if (MFRC522_MifareReadBlock16(&rfid, b, ver) == STATUS_OK &&
                    memcmp(ver, pendingToken, 16) == 0)
                {
                    printf("[WRITE] OK. Sifre karta yazildi ve dogrulandi.\r\n");
                    if (token_has_pw(ver)) print_token_pw(ver);
                    pendingWrite = 0;
                } else {
                    printf("[WRITE] HATA: Dogrulama basarisiz.\r\n");
                }
            } else {
                printf("[WRITE] HATA: Yazma basarisiz.\r\n");
            }
        }

        // İşimiz bitti
        break;
    }

    // Crypto kapat + kartı HALT'a al
    MFRC522_StopCrypto1(&rfid);
    (void)MFRC522_PICC_HaltA(&rfid);

    if (used_block == 0xFF) {
        printf("[CARD] AUTH basarisiz: TOKEN_BLOCK ve Block1 ile auth yapilamadi.\r\n");
    } else if (used_block != TOKEN_BLOCK) {
        printf("[CARD] Not: TOKEN_BLOCK (%d) auth olmadi, Block %u kullanildi.\r\n", TOKEN_BLOCK, used_block);
    }

    printf("[CARD] Kart kaldirilinca devam...\r\n");
    MFRC522_WaitCardRemoval(&rfid);
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
  MX_USART3_UART_Init();
  MX_SPI1_Init();
  /* USER CODE BEGIN 2 */
  HAL_UART_Receive_IT(&huart3, &rxByte, 1);

	HAL_GPIO_WritePin(GPIOA, GPIO_PIN_4, GPIO_PIN_SET);
	rfid.hspi = &hspi1;
	rfid.csPort = GPIOA;
	rfid.csPin = GPIO_PIN_4;  // CS = PA4
	rfid.rstPort = GPIOA;
	rfid.rstPin = GPIO_PIN_3;  // RST = PA3

	MFRC522_Init(&rfid);

	printf("\r\n=== PROJ-1 RFID TOKEN PROGRAM ===\r\n");
	printf("Kart okut -> UID + token oku\r\n");
	printf("Komut: PSWRD:mySecret123 (max 13 char)\r\n");
	printf("Token block: %d\r\n\r\n", TOKEN_BLOCK);
  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
		handle_line();
		process_card_once();
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
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_BYPASS;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 4;
  RCC_OscInitStruct.PLL.PLLN = 96;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 4;
  RCC_OscInitStruct.PLL.PLLR = 2;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Activate the Over-Drive mode
  */
  if (HAL_PWREx_EnableOverDrive() != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_3) != HAL_OK)
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
  hspi1.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_64;
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
  __HAL_RCC_GPIOD_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(GPIOA, GPIO_PIN_3|GPIO_PIN_4, GPIO_PIN_RESET);

  /*Configure GPIO pins : PA3 PA4 */
  GPIO_InitStruct.Pin = GPIO_PIN_3|GPIO_PIN_4;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */
void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart)
{
    if (huart->Instance == USART3) {
        char c = (char)rxByte;

        if (c == '\r' || c == '\n') {
            if (lineLen > 0) {
                lineBuf[lineLen] = 0;
                lineReady = 1;
                lineLen = 0;
            }
        } else {
            if (lineLen < (sizeof(lineBuf) - 1)) {
                lineBuf[lineLen++] = c;
            }
        }
        HAL_UART_Receive_IT(&huart3, &rxByte, 1);
    }
}
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
