#ifndef __MFRC522_MIFARE_H
#define __MFRC522_MIFARE_H

#include "MFRC522_STM32.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* PICC commands */
#define PICC_CMD_REQA        0x26
#define PICC_CMD_WUPA        0x52
#define PICC_CMD_SEL_CL1     0x93
#define PICC_CMD_HLTA        0x50

/* MIFARE Classic commands */
#define PICC_MF_AUTH_KEYA    0x60
#define PICC_MF_AUTH_KEYB    0x61
#define PICC_MF_READ         0x30
#define PICC_MF_WRITE        0xA0

/* Default keys */
#define KEYA_DEFAULT_6B  {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}

/* API */
uint8_t MFRC522_PICC_RequestA(MFRC522_t *dev, uint8_t atqa[2]);
uint8_t MFRC522_PICC_WakeupA(MFRC522_t *dev, uint8_t atqa[2]);
uint8_t MFRC522_PICC_AnticollCL1(MFRC522_t *dev, uint8_t uid_bcc5[5]);
uint8_t MFRC522_SelectCL1_GetSAK(MFRC522_t *dev, const uint8_t uid_bcc5[5], uint8_t *sak_out);

uint8_t MFRC522_MifareAuthKeyA(MFRC522_t *dev, uint8_t blockAddr, const uint8_t keyA6[6], const uint8_t uid4[4]);
uint8_t MFRC522_MifareAuthKeyB(MFRC522_t *dev, uint8_t blockAddr, const uint8_t keyB6[6], const uint8_t uid4[4]);

uint8_t MFRC522_MifareReadBlock16(MFRC522_t *dev, uint8_t blockAddr, uint8_t out16[16]);
uint8_t MFRC522_MifareWriteBlock16(MFRC522_t *dev, uint8_t blockAddr, const uint8_t in16[16]);

void    MFRC522_StopCrypto1(MFRC522_t *dev);
uint8_t MFRC522_PICC_HaltA(MFRC522_t *dev);

#ifdef __cplusplus
}
#endif

#endif /* __MFRC522_MIFARE_H */
