#include "MFRC522_STM32.h"

/* SPI helper */
static inline void cs_low(MFRC522_t *d)  { HAL_GPIO_WritePin(d->csPort, d->csPin, GPIO_PIN_RESET); }
static inline void cs_high(MFRC522_t *d) { HAL_GPIO_WritePin(d->csPort, d->csPin, GPIO_PIN_SET);   }

void MFRC522_WriteReg(MFRC522_t *dev, uint8_t reg, uint8_t val)
{
    uint8_t buf[2];
    buf[0] = (uint8_t)((reg << 1) & 0x7E); /* MSB=0 write */
    buf[1] = val;

    cs_low(dev);
    (void)HAL_SPI_Transmit(dev->hspi, buf, 2, 100);
    cs_high(dev);
}

uint8_t MFRC522_ReadReg(MFRC522_t *dev, uint8_t reg)
{
    uint8_t addr = (uint8_t)(((reg << 1) & 0x7E) | 0x80); /* MSB=1 read */
    uint8_t val  = 0x00;

    cs_low(dev);
    (void)HAL_SPI_Transmit(dev->hspi, &addr, 1, 100);
    (void)HAL_SPI_Receive(dev->hspi, &val, 1, 100);
    cs_high(dev);

    return val;
}

void MFRC522_SetBitMask(MFRC522_t *dev, uint8_t reg, uint8_t mask)
{
    uint8_t tmp = MFRC522_ReadReg(dev, reg);
    MFRC522_WriteReg(dev, reg, (uint8_t)(tmp | mask));
}

void MFRC522_ClearBitMask(MFRC522_t *dev, uint8_t reg, uint8_t mask)
{
    uint8_t tmp = MFRC522_ReadReg(dev, reg);
    MFRC522_WriteReg(dev, reg, (uint8_t)(tmp & (~mask)));
}

static void antenna_on(MFRC522_t *dev)
{
    uint8_t val = MFRC522_ReadReg(dev, PCD_TxControlReg);
    if ((val & 0x03U) != 0x03U) {
        MFRC522_SetBitMask(dev, PCD_TxControlReg, 0x03U);
    }
}

static void soft_reset(MFRC522_t *dev)
{
    MFRC522_WriteReg(dev, PCD_CommandReg, PCD_SoftReset);
    HAL_Delay(50);
    /* wait for PowerDown bit to clear */
    for (int i = 0; i < 50; i++) {
        if ((MFRC522_ReadReg(dev, PCD_CommandReg) & (1U<<4)) == 0) break;
        HAL_Delay(1);
    }
}

void MFRC522_Init(MFRC522_t *dev)
{
    /* Ensure CS is high */
    cs_high(dev);

    /* Optional HW reset pin */
    if (dev->rstPort) {
        HAL_GPIO_WritePin(dev->rstPort, dev->rstPin, GPIO_PIN_RESET);
        HAL_Delay(2);
        HAL_GPIO_WritePin(dev->rstPort, dev->rstPin, GPIO_PIN_SET);
        HAL_Delay(50);
    }

    soft_reset(dev);

    /* Timer settings (close to MiguelBalboa defaults) */
    MFRC522_WriteReg(dev, PCD_TModeReg,      0x80);
    MFRC522_WriteReg(dev, PCD_TPrescalerReg, 0xA9);
    MFRC522_WriteReg(dev, PCD_TReloadRegH,   0x03);
    MFRC522_WriteReg(dev, PCD_TReloadRegL,   0xE8);

    /* Force 100% ASK */
    MFRC522_WriteReg(dev, PCD_TxASKReg, 0x40);

    /* IMPORTANT: CRC preset = 0x6363 for ISO14443A */
    MFRC522_WriteReg(dev, PCD_ModeReg, 0x3D);

    /* Recommended */
    MFRC522_WriteReg(dev, PCD_TxModeReg,   0x00);
    MFRC522_WriteReg(dev, PCD_RxModeReg,   0x00);
    MFRC522_WriteReg(dev, PCD_ModWidthReg, 0x26);

    antenna_on(dev);
}
