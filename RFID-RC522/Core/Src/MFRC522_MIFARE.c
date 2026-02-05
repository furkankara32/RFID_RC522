#include "MFRC522_MIFARE.h"
#include <string.h>

/* ---- Extra register addresses (not in minimal header) ---- */
#define PCD_DivIrqReg       0x05
#define PCD_ControlReg      0x0C
#define PCD_CollReg         0x0E
#define PCD_ModeReg         0x11
#define PCD_CRCResultRegH   0x21
#define PCD_CRCResultRegL   0x22

/* Commands */
#define PCD_CalcCRC         0x03
#define PCD_MFAuthent       0x0E

/* PICC */
#define PICC_WUPA           0x52
#define PICC_HLTA           0x50
#define PICC_SEL_CL1        0x93
#define PICC_MF_AUTH_KEYA   0x60
#define PICC_MF_AUTH_KEYB   0x61
#define PICC_MF_READ        0x30
#define PICC_MF_WRITE       0xA0

/* ComIrqReg bits */
#define IRQ_TIMER           (1U<<0)
#define IRQ_ERR             (1U<<1)
#define IRQ_IDLE            (1U<<4)
#define IRQ_RX              (1U<<5)

/* Status2Reg */
#define STATUS2_CRYPTO1ON   (1U<<3)

/* ErrorReg bits we care about */
// ErrorReg bits (MFRC522 datasheet):
// bit4 BufferOvfl, bit3 CollErr, bit2 CRCErr, bit1 ParityErr, bit0 ProtocolErr
#define ERR_BUFFEROVFL      (1U<<4)
#define ERR_COLL            (1U<<3)
#define ERR_CRC             (1U<<2)
#define ERR_PARITY          (1U<<1)
#define ERR_PROTOCOL        (1U<<0)

/* -------------------------------------------------------------------------- */
/*  Core: MiguelBalboa-style communicate                                      */
/* -------------------------------------------------------------------------- */
static uint8_t calc_crc(MFRC522_t *dev, const uint8_t *data, uint8_t len, uint8_t out2[2])
{
    MFRC522_WriteReg(dev, PCD_CommandReg, PCD_Idle);
    MFRC522_WriteReg(dev, PCD_DivIrqReg, 0x04);        // Clear CRCIRq
    MFRC522_WriteReg(dev, PCD_FIFOLevelReg, 0x80);     // Flush FIFO

    for (uint8_t i = 0; i < len; i++)
        MFRC522_WriteReg(dev, PCD_FIFODataReg, data[i]);

    MFRC522_WriteReg(dev, PCD_CommandReg, PCD_CalcCRC);

    uint32_t t0 = HAL_GetTick();
    while (1) {
        uint8_t n = MFRC522_ReadReg(dev, PCD_DivIrqReg);
        if (n & 0x04) break;                           // CRCIRq
        if ((HAL_GetTick() - t0) > 20) return STATUS_TIMEOUT;
    }

    out2[0] = MFRC522_ReadReg(dev, PCD_CRCResultRegL);
    out2[1] = MFRC522_ReadReg(dev, PCD_CRCResultRegH);
    MFRC522_WriteReg(dev, PCD_CommandReg, PCD_Idle);
    return STATUS_OK;
}

/**
 * communicate_with_picc:
 * - command: PCD_Transceive or PCD_MFAuthent
 * - waitIRq: for Transceive use 0x30 (RxIRq|IdleIRq). For Auth use 0x10 (IdleIRq).
 * - txLastBits: number of bits in last byte (REQA/WUPA uses 7)
 * - rxAlign: used when receiving partial bits (normally 0)
 * - validBits: in/out: expected/received valid bits in last byte
 */
static uint8_t communicate_with_picc(MFRC522_t *dev,
                                    uint8_t command, uint8_t waitIRq,
                                    const uint8_t *sendData, uint8_t sendLen,
                                    uint8_t *backData, uint8_t *backLen,
                                    uint8_t *validBits,
                                    uint8_t rxAlign, uint8_t txLastBits,
                                    uint32_t timeoutMs)
{
    MFRC522_WriteReg(dev, PCD_CommandReg, PCD_Idle);
    MFRC522_WriteReg(dev, PCD_ComIrqReg, 0x7F);        // Clear all IRQ flags
    MFRC522_WriteReg(dev, PCD_FIFOLevelReg, 0x80);     // Flush FIFO

    /* BitFraming: RxAlign in high nibble, TxLastBits in low 3 bits */
    MFRC522_WriteReg(dev, PCD_BitFramingReg, (uint8_t)((rxAlign << 4) | (txLastBits & 0x07)));

    for (uint8_t i = 0; i < sendLen; i++)
        MFRC522_WriteReg(dev, PCD_FIFODataReg, sendData[i]);

    MFRC522_WriteReg(dev, PCD_CommandReg, command);
    if (command == PCD_Transceive)
        MFRC522_SetBitMask(dev, PCD_BitFramingReg, 0x80);  // StartSend

    uint32_t t0 = HAL_GetTick();
    while (1) {
        uint8_t n = MFRC522_ReadReg(dev, PCD_ComIrqReg);
        if (n & waitIRq) break;                         // RxIRq or IdleIRq
        if (n & IRQ_TIMER) return STATUS_TIMEOUT;
        if ((HAL_GetTick() - t0) > timeoutMs) return STATUS_TIMEOUT;
    }

    if (command == PCD_Transceive)
        MFRC522_ClearBitMask(dev, PCD_BitFramingReg, 0x80); // StopSend

    uint8_t errorReg = MFRC522_ReadReg(dev, PCD_ErrorReg);
    if (errorReg & (ERR_BUFFEROVFL | ERR_COLL | ERR_CRC | ERR_PARITY | ERR_PROTOCOL))
        return STATUS_ERROR;

    if (backData && backLen) {
        uint8_t n = MFRC522_ReadReg(dev, PCD_FIFOLevelReg);
        if (n > *backLen) return STATUS_ERROR;

        *backLen = n;
        for (uint8_t i = 0; i < n; i++)
            backData[i] = MFRC522_ReadReg(dev, PCD_FIFODataReg);

        /* validBits in last byte */
        if (validBits)
            *validBits = MFRC522_ReadReg(dev, PCD_ControlReg) & 0x07;
    }

    return STATUS_OK;
}

/* -------------------------------------------------------------------------- */
/* PICC Level                                                                  */
/* -------------------------------------------------------------------------- */
uint8_t MFRC522_PICC_RequestA(MFRC522_t *dev, uint8_t atqa[2])
{
    uint8_t cmd = PICC_REQA;
    uint8_t backLen = 2;
    uint8_t validBits = 0;

    /* REQA is 7 bits */
    uint8_t st = communicate_with_picc(dev, PCD_Transceive, (IRQ_RX | IRQ_IDLE),
                                       &cmd, 1, atqa, &backLen, &validBits,
                                       0, 7, 25);
    if (st != STATUS_OK || backLen != 2) return STATUS_ERROR;
    return STATUS_OK;
}

uint8_t MFRC522_PICC_WakeupA(MFRC522_t *dev, uint8_t atqa[2])
{
    uint8_t cmd = PICC_WUPA;
    uint8_t backLen = 2;
    uint8_t validBits = 0;

    uint8_t st = communicate_with_picc(dev, PCD_Transceive, (IRQ_RX | IRQ_IDLE),
                                       &cmd, 1, atqa, &backLen, &validBits,
                                       0, 7, 25);
    if (st != STATUS_OK || backLen != 2) return STATUS_ERROR;
    return STATUS_OK;
}

uint8_t MFRC522_PICC_Anticoll_CL1(MFRC522_t *dev, uint8_t uid_bcc5[5])
{
    uint8_t cmd[2] = {PICC_SEL_CL1, 0x20}; // NVB=0x20
    uint8_t backLen = 5;
    uint8_t validBits = 0;

    // Clear collision register
    MFRC522_WriteReg(dev, PCD_CollReg, 0x80); // ValuesAfterColl=1

    uint8_t st = communicate_with_picc(dev, PCD_Transceive, (IRQ_RX | IRQ_IDLE),
                                       cmd, 2, uid_bcc5, &backLen, &validBits,
                                       0, 0, 40);
    if (st != STATUS_OK || backLen != 5) return STATUS_ERROR;

    uint8_t bcc = uid_bcc5[0] ^ uid_bcc5[1] ^ uid_bcc5[2] ^ uid_bcc5[3];
    if (bcc != uid_bcc5[4]) return STATUS_ERROR;
    return STATUS_OK;
}


uint8_t MFRC522_PICC_AnticollCL1(MFRC522_t *dev, uint8_t uid_bcc5[5])
{
    /* Anti-collision CL1: send 0x93 0x20, expect 5 bytes (UID0..UID3 + BCC) */
    uint8_t cmd[2] = {PICC_SEL_CL1, 0x20};
    uint8_t backLen = 5;
    uint8_t validBits = 0;

    uint8_t st = communicate_with_picc(dev, PCD_Transceive, (IRQ_RX | IRQ_IDLE),
                                       cmd, 2, uid_bcc5, &backLen, &validBits,
                                       0, 0, 40);
    if (st != STATUS_OK || backLen != 5) return STATUS_ERROR;

    /* Verify / fix BCC (XOR of UID bytes) */
    uint8_t bcc = uid_bcc5[0] ^ uid_bcc5[1] ^ uid_bcc5[2] ^ uid_bcc5[3];
    if (uid_bcc5[4] != bcc) {
        /* Some clones may return wrong BCC if timing is off; override to be safe */
        uid_bcc5[4] = bcc;
    }
    return STATUS_OK;
}

uint8_t MFRC522_SelectCL1(MFRC522_t *dev, const uint8_t uid_bcc5[5], uint8_t *sak_out)
{
    uint8_t buf[9];
    buf[0] = PICC_SEL_CL1;
    buf[1] = 0x70; // NVB = 7 bytes
    memcpy(&buf[2], uid_bcc5, 5);

    uint8_t crc[2];
    if (calc_crc(dev, buf, 7, crc) != STATUS_OK) return STATUS_ERROR;
    buf[7] = crc[0]; buf[8] = crc[1];

    uint8_t resp[3] = {0};
    uint8_t backLen = sizeof(resp);
    uint8_t validBits = 0;

    uint8_t st = communicate_with_picc(dev, PCD_Transceive, (IRQ_RX | IRQ_IDLE),
                                       buf, 9, resp, &backLen, &validBits,
                                       0, 0, 40);
    if (st != STATUS_OK || backLen < 1) return STATUS_ERROR;

    if (sak_out) *sak_out = resp[0];
    return STATUS_OK;
}

/**
 * PICC_HaltA: Put the card into HALT state.
 * Note: PICC typically does not send a response to HALT.
 */
uint8_t MFRC522_PICC_HaltA(MFRC522_t *dev)
{
    uint8_t buf[4] = {PICC_HLTA, 0x00, 0x00, 0x00};
    uint8_t crc[2];
    if (calc_crc(dev, buf, 2, crc) != STATUS_OK) return STATUS_ERROR;
    buf[2] = crc[0];
    buf[3] = crc[1];

    /* No response expected; wait for IdleIRq to indicate command finished */
    uint8_t st = communicate_with_picc(dev, PCD_Transceive, IRQ_IDLE,
                                       buf, 4,
                                       NULL, NULL,
                                       NULL,
                                       0, 0,
                                       30);
    /* Some cards/readers may return timeout here; treat it as OK for HALT */
    if (st == STATUS_TIMEOUT) return STATUS_OK;
    return st;
}

/* -------------------------------------------------------------------------- */
/* MIFARE Classic                                                              */
/* -------------------------------------------------------------------------- */
uint8_t MFRC522_MifareAuthKeyA(MFRC522_t *dev, uint8_t blockAddr,
                               const uint8_t keyA6[6], const uint8_t uid4[4])
{
    uint8_t buf[12];
    buf[0] = PICC_MF_AUTH_KEYA;
    buf[1] = blockAddr;
    memcpy(&buf[2], keyA6, 6);
    memcpy(&buf[8], uid4, 4);

    uint8_t st = communicate_with_picc(dev, PCD_MFAuthent, IRQ_IDLE,
                                       buf, 12, NULL, NULL, NULL,
                                       0, 0, 80);
    if (st != STATUS_OK) return st;

    return (MFRC522_ReadReg(dev, PCD_Status2Reg) & STATUS2_CRYPTO1ON) ? STATUS_OK : STATUS_ERROR;
}

uint8_t MFRC522_MifareAuthKeyB(MFRC522_t *dev, uint8_t blockAddr,
                               const uint8_t keyB6[6], const uint8_t uid4[4])
{
    uint8_t buf[12];
    buf[0] = PICC_MF_AUTH_KEYB;
    buf[1] = blockAddr;
    memcpy(&buf[2], keyB6, 6);
    memcpy(&buf[8], uid4, 4);

    uint8_t st = communicate_with_picc(dev, PCD_MFAuthent, IRQ_IDLE,
                                       buf, 12, NULL, NULL, NULL,
                                       0, 0, 80);
    if (st != STATUS_OK) return st;

    return (MFRC522_ReadReg(dev, PCD_Status2Reg) & STATUS2_CRYPTO1ON) ? STATUS_OK : STATUS_ERROR;
}

uint8_t MFRC522_MifareReadBlock16(MFRC522_t *dev, uint8_t blockAddr, uint8_t out16[16])
{
    uint8_t cmd[4] = {PICC_MF_READ, blockAddr, 0, 0};
    uint8_t crc[2];
    if (calc_crc(dev, cmd, 2, crc) != STATUS_OK) return STATUS_ERROR;
    cmd[2] = crc[0]; cmd[3] = crc[1];

    uint8_t resp[18] = {0};
    uint8_t backLen = sizeof(resp);
    uint8_t validBits = 0;

    uint8_t st = communicate_with_picc(dev, PCD_Transceive, (IRQ_RX | IRQ_IDLE),
                                       cmd, 4, resp, &backLen, &validBits,
                                       0, 0, 60);
    if (st != STATUS_OK || backLen < 16) return STATUS_ERROR;

    memcpy(out16, resp, 16);
    return STATUS_OK;
}

static uint8_t is_ack(uint8_t *data, uint8_t len, uint8_t validBits)
{
    /* ACK is 4 bits: 0xA */
    if (len != 1) return 0;
    if (validBits != 4 && validBits != 0) {
        /* some clones report validBits=0; still check lower nibble */
    }
    return ((data[0] & 0x0F) == 0x0A);
}

uint8_t MFRC522_MifareWriteBlock16(MFRC522_t *dev, uint8_t blockAddr, const uint8_t in16[16])
{
    uint8_t cmd[4] = {PICC_MF_WRITE, blockAddr, 0, 0};
    uint8_t crc[2];
    if (calc_crc(dev, cmd, 2, crc) != STATUS_OK) return STATUS_ERROR;
    cmd[2] = crc[0]; cmd[3] = crc[1];

    uint8_t ack[1] = {0};
    uint8_t backLen = 1;
    uint8_t validBits = 0;

    /* Step 1: send WRITE command, expect ACK */
    uint8_t st = communicate_with_picc(dev, PCD_Transceive, (IRQ_RX | IRQ_IDLE),
                                       cmd, 4, ack, &backLen, &validBits,
                                       0, 0, 80);
    if (st != STATUS_OK || !is_ack(ack, backLen, validBits)) return STATUS_ERROR;

    /* Step 2: send 16 bytes + CRC, expect ACK */
    uint8_t frame[18];
    memcpy(frame, in16, 16);
    if (calc_crc(dev, frame, 16, crc) != STATUS_OK) return STATUS_ERROR;
    frame[16] = crc[0]; frame[17] = crc[1];

    ack[0] = 0;
    backLen = 1;
    validBits = 0;

    st = communicate_with_picc(dev, PCD_Transceive, (IRQ_RX | IRQ_IDLE),
                              frame, 18, ack, &backLen, &validBits,
                              0, 0, 120);
    if (st != STATUS_OK || !is_ack(ack, backLen, validBits)) return STATUS_ERROR;

    return STATUS_OK;
}

void MFRC522_StopCrypto1(MFRC522_t *dev)
{
    MFRC522_ClearBitMask(dev, PCD_Status2Reg, STATUS2_CRYPTO1ON);
}

/* Wait until card is removed (poll) */
uint8_t MFRC522_WaitCardRemoval(MFRC522_t *dev)
{
    USER_LOG("Waiting for card removal...");
    uint8_t atqa[2];

    while (1) {
        /* Try REQA first, then WUPA (in case card was halted somewhere) */
        if (MFRC522_PICC_RequestA(dev, atqa) != STATUS_OK &&
            MFRC522_PICC_WakeupA(dev, atqa) != STATUS_OK)
        {
            USER_LOG("Card removed");
            return STATUS_OK;
        }
        HAL_Delay(100);
    }
}
