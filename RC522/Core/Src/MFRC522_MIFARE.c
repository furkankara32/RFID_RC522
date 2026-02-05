#include "MFRC522_MIFARE.h"
#include <string.h>

/* IRQ bits in ComIrqReg */
#define IRQ_TX        (1U<<6)
#define IRQ_RX        (1U<<5)
#define IRQ_IDLE      (1U<<4)
#define IRQ_ERR       (1U<<1)
#define IRQ_TIMER     (1U<<0)

/* Status2Reg Crypto1On */
#define STATUS2_CRYPTO1ON   (1U<<3)

/* DivIrqReg CRCIRq bit */
#define DIVIRQ_CRCIRq       (1U<<2)

/* ErrorReg mask (Balboa uses 0x13 for BufferOvfl, ParityErr, ProtocolErr) */
#define ERROR_MASK          0x13

static uint8_t calc_crc(MFRC522_t *dev, const uint8_t *data, uint8_t len, uint8_t out2[2])
{
    MFRC522_WriteReg(dev, PCD_CommandReg, PCD_Idle);
    MFRC522_WriteReg(dev, PCD_DivIrqReg, 0x7F);
    MFRC522_WriteReg(dev, PCD_FIFOLevelReg, 0x80); /* flush FIFO */

    for (uint8_t i = 0; i < len; i++) MFRC522_WriteReg(dev, PCD_FIFODataReg, data[i]);

    MFRC522_WriteReg(dev, PCD_CommandReg, PCD_CalcCRC);

    uint32_t t0 = HAL_GetTick();
    while (1) {
        uint8_t n = MFRC522_ReadReg(dev, PCD_DivIrqReg);
        if (n & DIVIRQ_CRCIRq) break;
        if ((HAL_GetTick() - t0) > 30) return STATUS_TIMEOUT;
    }

    out2[0] = MFRC522_ReadReg(dev, PCD_CRCResultRegL);
    out2[1] = MFRC522_ReadReg(dev, PCD_CRCResultRegH);

    MFRC522_WriteReg(dev, PCD_CommandReg, PCD_Idle);
    return STATUS_OK;
}

/* communicate_with_picc (MiguelBalboa-like) */
static uint8_t communicate_with_picc(MFRC522_t *dev,
                                     uint8_t command,
                                     uint8_t waitIRq,
                                     const uint8_t *sendData, uint8_t sendLen,
                                     uint8_t *backData, uint8_t *backLen,
                                     uint8_t *validBits,
                                     uint8_t rxAlign, uint8_t txLastBits,
                                     uint32_t timeoutMs)
{
    MFRC522_WriteReg(dev, PCD_CommandReg, PCD_Idle);
    MFRC522_WriteReg(dev, PCD_ComIrqReg, 0x7F);
    MFRC522_WriteReg(dev, PCD_FIFOLevelReg, 0x80); /* flush FIFO */

    /* Bit framing */
    MFRC522_WriteReg(dev, PCD_BitFramingReg, (uint8_t)((rxAlign << 4) | (txLastBits & 0x07)));

    for (uint8_t i = 0; i < sendLen; i++) MFRC522_WriteReg(dev, PCD_FIFODataReg, sendData[i]);

    MFRC522_WriteReg(dev, PCD_CommandReg, command);
    if (command == PCD_Transceive) {
        MFRC522_SetBitMask(dev, PCD_BitFramingReg, 0x80); /* StartSend */
    }

    uint32_t t0 = HAL_GetTick();
    while (1) {
        uint8_t n = MFRC522_ReadReg(dev, PCD_ComIrqReg);
        if (n & waitIRq) break;
        if (n & IRQ_TIMER) return STATUS_TIMEOUT;
        if ((HAL_GetTick() - t0) > timeoutMs) return STATUS_TIMEOUT;
    }

    if (command == PCD_Transceive) {
        MFRC522_ClearBitMask(dev, PCD_BitFramingReg, 0x80); /* StopSend */
    }

    uint8_t err = MFRC522_ReadReg(dev, PCD_ErrorReg);
    if (err & ERROR_MASK) return STATUS_ERROR;

    if (backData && backLen) {
        uint8_t n = MFRC522_ReadReg(dev, PCD_FIFOLevelReg) & 0x7F;
        if (n > *backLen) return STATUS_NO_ROOM;

        *backLen = n;
        for (uint8_t i = 0; i < n; i++) backData[i] = MFRC522_ReadReg(dev, PCD_FIFODataReg);

        uint8_t _validBits = MFRC522_ReadReg(dev, PCD_ControlReg) & 0x07;
        if (validBits) *validBits = _validBits;
    }

    return STATUS_OK;
}

static uint8_t picc_reqa_wupa(MFRC522_t *dev, uint8_t cmd, uint8_t atqa[2])
{
    uint8_t buf[1] = {cmd};
    uint8_t len = 2;
    uint8_t vb = 0;

    /* REQA/WUPA: 7 bits */
    uint8_t st = communicate_with_picc(dev, PCD_Transceive, (IRQ_RX | IRQ_IDLE),
                                       buf, 1,
                                       atqa, &len,
                                       &vb,
                                       0, 7,
                                       50);
    if (st != STATUS_OK) return st;
    if (len != 2 || vb != 0) return STATUS_ERROR;
    return STATUS_OK;
}

uint8_t MFRC522_PICC_RequestA(MFRC522_t *dev, uint8_t atqa[2])
{
    return picc_reqa_wupa(dev, PICC_CMD_REQA, atqa);
}

uint8_t MFRC522_PICC_WakeupA(MFRC522_t *dev, uint8_t atqa[2])
{
    return picc_reqa_wupa(dev, PICC_CMD_WUPA, atqa);
}

uint8_t MFRC522_PICC_AnticollCL1(MFRC522_t *dev, uint8_t uid_bcc5[5])
{
    uint8_t buf[2] = {PICC_CMD_SEL_CL1, 0x20};
    uint8_t backLen = 5;
    uint8_t vb = 0;

    /* Clear collision bits */
    MFRC522_ClearBitMask(dev, PCD_CollReg, 0x80);

    uint8_t st = communicate_with_picc(dev, PCD_Transceive, (IRQ_RX | IRQ_IDLE),
                                       buf, 2,
                                       uid_bcc5, &backLen,
                                       &vb,
                                       0, 0,
                                       60);
    if (st != STATUS_OK) return st;
    if (backLen != 5 || vb != 0) return STATUS_ERROR;

    /* Fix/verify BCC (XOR of first 4 bytes) */
    uint8_t bcc = uid_bcc5[0] ^ uid_bcc5[1] ^ uid_bcc5[2] ^ uid_bcc5[3];
    uid_bcc5[4] = bcc;

    return STATUS_OK;
}

uint8_t MFRC522_SelectCL1_GetSAK(MFRC522_t *dev, const uint8_t uid_bcc5[5], uint8_t *sak_out)
{
    uint8_t buf[9];
    buf[0] = PICC_CMD_SEL_CL1;
    buf[1] = 0x70;
    memcpy(&buf[2], uid_bcc5, 5);

    uint8_t crc[2];
    if (calc_crc(dev, buf, 7, crc) != STATUS_OK) return STATUS_ERROR;
    buf[7] = crc[0];
    buf[8] = crc[1];

    uint8_t resp[3] = {0};
    uint8_t respLen = sizeof(resp);
    uint8_t vb = 0;

    uint8_t st = communicate_with_picc(dev, PCD_Transceive, (IRQ_RX | IRQ_IDLE),
                                       buf, 9,
                                       resp, &respLen,
                                       &vb,
                                       0, 0,
                                       60);
    if (st != STATUS_OK) return st;
    if (respLen < 1) return STATUS_ERROR;

    if (sak_out) *sak_out = resp[0];
    return STATUS_OK;
}

static uint8_t mifare_auth(MFRC522_t *dev, uint8_t cmd, uint8_t blockAddr,
                           const uint8_t key6[6], const uint8_t uid4[4])
{
    uint8_t buf[12];
    buf[0] = cmd;
    buf[1] = blockAddr;
    memcpy(&buf[2], key6, 6);
    memcpy(&buf[8], uid4, 4);

    MFRC522_WriteReg(dev, PCD_CommandReg, PCD_Idle);
    MFRC522_WriteReg(dev, PCD_ComIrqReg, 0x7F);
    MFRC522_WriteReg(dev, PCD_FIFOLevelReg, 0x80);
    for (uint8_t i = 0; i < sizeof(buf); i++) MFRC522_WriteReg(dev, PCD_FIFODataReg, buf[i]);

    MFRC522_WriteReg(dev, PCD_CommandReg, PCD_MFAuthent);

    uint32_t t0 = HAL_GetTick();
    while (1) {
        uint8_t irq = MFRC522_ReadReg(dev, PCD_ComIrqReg);
        if (irq & (IRQ_IDLE | IRQ_ERR | IRQ_TIMER)) break;
        if ((HAL_GetTick() - t0) > 120) return STATUS_TIMEOUT;
    }

    return (MFRC522_ReadReg(dev, PCD_Status2Reg) & STATUS2_CRYPTO1ON) ? STATUS_OK : STATUS_ERROR;
}

uint8_t MFRC522_MifareAuthKeyA(MFRC522_t *dev, uint8_t blockAddr, const uint8_t keyA6[6], const uint8_t uid4[4])
{
    return mifare_auth(dev, PICC_MF_AUTH_KEYA, blockAddr, keyA6, uid4);
}

uint8_t MFRC522_MifareAuthKeyB(MFRC522_t *dev, uint8_t blockAddr, const uint8_t keyB6[6], const uint8_t uid4[4])
{
    return mifare_auth(dev, PICC_MF_AUTH_KEYB, blockAddr, keyB6, uid4);
}

uint8_t MFRC522_MifareReadBlock16(MFRC522_t *dev, uint8_t blockAddr, uint8_t out16[16])
{
    uint8_t cmd[4] = {PICC_MF_READ, blockAddr, 0, 0};
    uint8_t crc[2];
    if (calc_crc(dev, cmd, 2, crc) != STATUS_OK) return STATUS_ERROR;
    cmd[2] = crc[0]; cmd[3] = crc[1];

    uint8_t resp[18] = {0};
    uint8_t respLen = sizeof(resp);
    uint8_t vb = 0;

    uint8_t st = communicate_with_picc(dev, PCD_Transceive, (IRQ_RX | IRQ_IDLE),
                                       cmd, 4,
                                       resp, &respLen,
                                       &vb,
                                       0, 0,
                                       80);
    if (st != STATUS_OK) return st;
    if (respLen < 16) return STATUS_ERROR;

    memcpy(out16, resp, 16);
    return STATUS_OK;
}

static uint8_t is_ack4bits(uint8_t resp, uint8_t validBits)
{
    /* ACK is 4 bits: 0b1010 = 0xA */
    return (validBits == 4) && ((resp & 0x0F) == 0x0A);
}

uint8_t MFRC522_MifareWriteBlock16(MFRC522_t *dev, uint8_t blockAddr, const uint8_t in16[16])
{
    uint8_t cmd[4] = {PICC_MF_WRITE, blockAddr, 0, 0};
    uint8_t crc[2];
    if (calc_crc(dev, cmd, 2, crc) != STATUS_OK) return STATUS_ERROR;
    cmd[2] = crc[0]; cmd[3] = crc[1];

    uint8_t ack = 0;
    uint8_t ackLen = 1;
    uint8_t vb = 0;

    uint8_t st = communicate_with_picc(dev, PCD_Transceive, (IRQ_RX | IRQ_IDLE),
                                       cmd, 4,
                                       &ack, &ackLen,
                                       &vb,
                                       0, 0,
                                       80);
    if (st != STATUS_OK) return st;
    if (ackLen != 1 || !is_ack4bits(ack, vb)) return STATUS_ERROR;

    uint8_t frame[18];
    memcpy(frame, in16, 16);
    if (calc_crc(dev, frame, 16, crc) != STATUS_OK) return STATUS_ERROR;
    frame[16] = crc[0]; frame[17] = crc[1];

    ack = 0; ackLen = 1; vb = 0;
    st = communicate_with_picc(dev, PCD_Transceive, (IRQ_RX | IRQ_IDLE),
                               frame, 18,
                               &ack, &ackLen,
                               &vb,
                               0, 0,
                               120);
    if (st != STATUS_OK) return st;
    if (ackLen != 1 || !is_ack4bits(ack, vb)) return STATUS_ERROR;

    return STATUS_OK;
}

void MFRC522_StopCrypto1(MFRC522_t *dev)
{
    MFRC522_ClearBitMask(dev, PCD_Status2Reg, STATUS2_CRYPTO1ON);
}

uint8_t MFRC522_PICC_HaltA(MFRC522_t *dev)
{
    uint8_t buf[4] = {PICC_CMD_HLTA, 0x00, 0x00, 0x00};
    uint8_t crc[2];
    if (calc_crc(dev, buf, 2, crc) != STATUS_OK) return STATUS_ERROR;
    buf[2] = crc[0];
    buf[3] = crc[1];

    /* Many PICCs do not respond to HALT; ignore TIMEOUT */
    uint8_t dummy = 0;
    uint8_t len = 1;
    uint8_t vb = 0;
    uint8_t st = communicate_with_picc(dev, PCD_Transceive, IRQ_IDLE,
                                       buf, 4,
                                       &dummy, &len,
                                       &vb,
                                       0, 0,
                                       30);
    if (st == STATUS_TIMEOUT) return STATUS_OK;
    return st;
}
