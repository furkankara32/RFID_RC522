#ifndef MFRC522_MIFARE_H
#define MFRC522_MIFARE_H

#include "MFRC522_STM32.h"
#include <stdint.h>

/* Token storage */
#ifndef TOKEN_BLOCK
#define TOKEN_BLOCK 4
#endif

/* Default KeyA (factory) */
#define KEYA_DEFAULT_6B {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}

/* Public API (reliable, MiguelBalboa-style) */
uint8_t MFRC522_PICC_RequestA(MFRC522_t *dev, uint8_t atqa[2]);
uint8_t MFRC522_PICC_WakeupA(MFRC522_t *dev, uint8_t atqa[2]);


uint8_t MFRC522_PICC_AnticollCL1(MFRC522_t *dev, uint8_t uid_bcc5[5]);
/* CL1 Anti-collision: returns 5 bytes (UID0..UID3 + BCC) */
uint8_t MFRC522_PICC_Anticoll_CL1(MFRC522_t *dev, uint8_t uid_bcc5[5]);

/* CL1 Select: input is uid_bcc5 (UID0..UID3 + BCC), returns SAK */
uint8_t MFRC522_SelectCL1(MFRC522_t *dev, const uint8_t uid_bcc5[5], uint8_t *sak_out);

/* Put PICC into HALT state (optional, helps stabilize repeated reads) */
uint8_t MFRC522_PICC_HaltA(MFRC522_t *dev);

/* MIFARE Classic auth/read/write (16B blocks) */
uint8_t MFRC522_MifareAuthKeyA(MFRC522_t *dev, uint8_t blockAddr,
                               const uint8_t keyA6[6], const uint8_t uid4[4]);
uint8_t MFRC522_MifareAuthKeyB(MFRC522_t *dev, uint8_t blockAddr,
                               const uint8_t keyB6[6], const uint8_t uid4[4]);

uint8_t MFRC522_MifareReadBlock16(MFRC522_t *dev, uint8_t blockAddr, uint8_t out16[16]);
uint8_t MFRC522_MifareWriteBlock16(MFRC522_t *dev, uint8_t blockAddr, const uint8_t in16[16]);

void    MFRC522_StopCrypto1(MFRC522_t *dev);

/* Helper: wait until card is physically removed */
uint8_t MFRC522_WaitCardRemoval(MFRC522_t *dev);

#endif
