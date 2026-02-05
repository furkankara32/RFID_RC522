#ifndef __MFRC522_STM32_H
#define __MFRC522_STM32_H

#include "stm32f7xx_hal.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- Status codes ---------- */
#define STATUS_OK         0
#define STATUS_ERROR      1
#define STATUS_COLLISION  2
#define STATUS_TIMEOUT    3
#define STATUS_NO_ROOM    4
#define STATUS_INVALID    5
#define STATUS_CRC_WRONG  6

typedef struct {
    SPI_HandleTypeDef *hspi;
    GPIO_TypeDef *csPort;
    uint16_t csPin;
    GPIO_TypeDef *rstPort;
    uint16_t rstPin;
} MFRC522_t;

/* ---------- MFRC522 registers ---------- */
#define PCD_CommandReg        0x01
#define PCD_ComIEnReg         0x02
#define PCD_DivIEnReg         0x03
#define PCD_ComIrqReg         0x04
#define PCD_DivIrqReg         0x05
#define PCD_ErrorReg          0x06
#define PCD_Status1Reg        0x07
#define PCD_Status2Reg        0x08
#define PCD_FIFODataReg       0x09
#define PCD_FIFOLevelReg      0x0A
#define PCD_ControlReg        0x0C
#define PCD_BitFramingReg     0x0D
#define PCD_CollReg           0x0E

#define PCD_ModeReg           0x11
#define PCD_TxModeReg         0x12
#define PCD_RxModeReg         0x13
#define PCD_TxControlReg      0x14
#define PCD_TxASKReg          0x15
#define PCD_ModWidthReg       0x24

#define PCD_TModeReg          0x2A
#define PCD_TPrescalerReg     0x2B
#define PCD_TReloadRegH       0x2C
#define PCD_TReloadRegL       0x2D

#define PCD_CRCResultRegH     0x21
#define PCD_CRCResultRegL     0x22

/* ---------- MFRC522 commands ---------- */
#define PCD_Idle              0x00
#define PCD_Mem               0x01
#define PCD_GenerateRandomID  0x02
#define PCD_CalcCRC           0x03
#define PCD_Transmit          0x04
#define PCD_NoCmdChange       0x07
#define PCD_Receive           0x08
#define PCD_Transceive        0x0C
#define PCD_MFAuthent         0x0E
#define PCD_SoftReset         0x0F

/* ---------- API ---------- */
void    MFRC522_Init(MFRC522_t *dev);
uint8_t MFRC522_ReadReg(MFRC522_t *dev, uint8_t reg);
void    MFRC522_WriteReg(MFRC522_t *dev, uint8_t reg, uint8_t val);
void    MFRC522_SetBitMask(MFRC522_t *dev, uint8_t reg, uint8_t mask);
void    MFRC522_ClearBitMask(MFRC522_t *dev, uint8_t reg, uint8_t mask);

#ifdef __cplusplus
}
#endif

#endif /* __MFRC522_STM32_H */
