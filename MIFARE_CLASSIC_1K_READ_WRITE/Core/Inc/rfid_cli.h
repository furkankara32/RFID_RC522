#pragma once
#include "stm32f7xx_hal.h"
#include "rc522.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    UART_HandleTypeDef *huart;
    rc522_t rc522;
} rfid_cli_t;

/**
 * @brief Blocking CLI loop over UART (VCP).
 * Prompts: scan card -> choose R/W -> choose sector/block -> read/write ASCII.
 */
void RFID_CLI_Run(rfid_cli_t *cli);

#ifdef __cplusplus
}
#endif
