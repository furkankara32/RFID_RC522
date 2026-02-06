#pragma once
#include "stm32f7xx_hal.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    RC522_OK = 0,
    RC522_ERR,
    RC522_TIMEOUT,
    RC522_COLLISION,
    RC522_AUTH_FAIL,
    RC522_NAK
} rc522_status_t;

typedef struct {
    SPI_HandleTypeDef *hspi;
    GPIO_TypeDef *cs_port;
    uint16_t cs_pin;
    GPIO_TypeDef *rst_port;
    uint16_t rst_pin;
} rc522_t;

typedef struct {
    uint8_t uid[10];
    uint8_t uid_len; // MIFARE Classic 1K: typically 4
} rc522_uid_t;

rc522_status_t rc522_init(rc522_t *dev);
void           rc522_reset(rc522_t *dev);
void           rc522_antenna_on(rc522_t *dev);

rc522_status_t rc522_is_new_card_present(rc522_t *dev);
rc522_status_t rc522_read_card_serial(rc522_t *dev, rc522_uid_t *out_uid);

rc522_status_t rc522_auth_keyA(rc522_t *dev, uint8_t block_addr, const uint8_t keyA[6], const rc522_uid_t *uid);
void           rc522_stop_crypto1(rc522_t *dev);

rc522_status_t rc522_mifare_read(rc522_t *dev, uint8_t block_addr, uint8_t out16[16]);
rc522_status_t rc522_mifare_write(rc522_t *dev, uint8_t block_addr, const uint8_t in16[16]);

void           rc522_haltA(rc522_t *dev);

#ifdef __cplusplus
}
#endif
