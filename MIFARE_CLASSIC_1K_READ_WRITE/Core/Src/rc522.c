#include "rc522.h"
#include <string.h>

/* ---------- MFRC522 Registers (subset) ---------- */
#define CommandReg       0x01
#define ComIrqReg        0x04
#define DivIrqReg        0x05
#define ErrorReg         0x06
#define Status2Reg       0x08
#define FIFODataReg      0x09
#define FIFOLevelReg     0x0A
#define ControlReg       0x0C
#define BitFramingReg    0x0D
#define CollReg          0x0E
#define ModeReg          0x11
#define RxModeReg        0x13
#define TxControlReg     0x14
#define TxASKReg         0x15
#define TModeReg         0x2A
#define TPrescalerReg    0x2B
#define TReloadRegH      0x2C
#define TReloadRegL      0x2D
#define CRCResultRegH    0x21
#define CRCResultRegL    0x22

/* ---------- MFRC522 Commands ---------- */
#define PCD_Idle         0x00
#define PCD_CalcCRC      0x03
#define PCD_Transceive   0x0C
#define PCD_MFAuthent    0x0E
#define PCD_SoftReset    0x0F

/* ---------- PICC Commands (ISO14443A / MIFARE) ---------- */
#define PICC_REQA         0x26
#define PICC_ANTICOLL_CL1  0x93
#define PICC_SELECT_CL1    0x93
#define PICC_HLTA          0x50

#define PICC_AUTH_KEYA    0x60
#define PICC_READ         0x30
#define PICC_WRITE        0xA0

/* ---------- Helpers ---------- */
static inline void cs_low(rc522_t *d)  { HAL_GPIO_WritePin(d->cs_port, d->cs_pin, GPIO_PIN_RESET); }
static inline void cs_high(rc522_t *d) { HAL_GPIO_WritePin(d->cs_port, d->cs_pin, GPIO_PIN_SET);   }

static void spi_write_reg(rc522_t *d, uint8_t reg, uint8_t val)
{
    /* Address byte format: MSB=0 write, bits6..1=addr, bit0=0 */
    uint8_t addr = (uint8_t)((reg << 1) & 0x7E);
    uint8_t tx[2] = { addr, val };

    cs_low(d);
    (void)HAL_SPI_Transmit(d->hspi, tx, 2, 100);
    cs_high(d);
}

static uint8_t spi_read_reg(rc522_t *d, uint8_t reg)
{
    /* MSB=1 read */
    uint8_t addr = (uint8_t)(((reg << 1) & 0x7E) | 0x80);
    uint8_t tx[2] = { addr, 0x00 };
    uint8_t rx[2] = { 0, 0 };

    cs_low(d);
    (void)HAL_SPI_TransmitReceive(d->hspi, tx, rx, 2, 100);
    cs_high(d);
    return rx[1];
}

static void set_bit_mask(rc522_t *d, uint8_t reg, uint8_t mask)
{
    spi_write_reg(d, reg, spi_read_reg(d, reg) | mask);
}

static void clear_bit_mask(rc522_t *d, uint8_t reg, uint8_t mask)
{
    spi_write_reg(d, reg, spi_read_reg(d, reg) & (uint8_t)(~mask));
}

static rc522_status_t calc_crc(rc522_t *d, const uint8_t *data, uint8_t len, uint8_t out[2])
{
    spi_write_reg(d, CommandReg, PCD_Idle);
    spi_write_reg(d, DivIrqReg, 0x04);          // Clear CRCIRq
    set_bit_mask(d, FIFOLevelReg, 0x80);        // Flush FIFO

    for (uint8_t i = 0; i < len; i++)
        spi_write_reg(d, FIFODataReg, data[i]);

    spi_write_reg(d, CommandReg, PCD_CalcCRC);

    uint32_t t0 = HAL_GetTick();
    while (1) {
        uint8_t n = spi_read_reg(d, DivIrqReg);
        if (n & 0x04) break;                    // CRCIRq
        if ((HAL_GetTick() - t0) > 20) return RC522_TIMEOUT;
    }

    out[0] = spi_read_reg(d, CRCResultRegL);
    out[1] = spi_read_reg(d, CRCResultRegH);
    return RC522_OK;
}

/* Core exchange */
static rc522_status_t transceive(rc522_t *d,
                                 const uint8_t *send, uint8_t send_len,
                                 uint8_t *back, uint8_t *back_len,
                                 uint8_t *valid_bits,
                                 uint8_t tx_last_bits)
{
    spi_write_reg(d, CommandReg, PCD_Idle);
    spi_write_reg(d, ComIrqReg, 0x7F);          // Clear all IRQ
    set_bit_mask(d, FIFOLevelReg, 0x80);        // Flush FIFO

    // Ensure normal receive end (avoid RxMultiple surprises)
    clear_bit_mask(d, RxModeReg, 0x04);         // RxMultiple = 0

    // Set bit framing (TxLastBits)
    spi_write_reg(d, BitFramingReg, (uint8_t)(tx_last_bits & 0x07));

    for (uint8_t i = 0; i < send_len; i++)
        spi_write_reg(d, FIFODataReg, send[i]);

    spi_write_reg(d, CommandReg, PCD_Transceive);
    set_bit_mask(d, BitFramingReg, 0x80);       // StartSend

    uint32_t t0 = HAL_GetTick();
    while (1) {
        uint8_t irq = spi_read_reg(d, ComIrqReg);
        if (irq & 0x30) break;                  // RxIRq or IdleIRq
        if (irq & 0x01) return RC522_TIMEOUT;   // TimerIRq
        if ((HAL_GetTick() - t0) > 50) return RC522_TIMEOUT;
    }

    clear_bit_mask(d, BitFramingReg, 0x80);     // StopStartSend

    uint8_t err = spi_read_reg(d, ErrorReg);
    // BufferOvfl | ParityErr | ProtocolErr are typical "hard errors"
    if (err & 0x13) {
        if (err & 0x08) return RC522_COLLISION; // CollErr
        return RC522_ERR;
    }

    uint8_t n = spi_read_reg(d, FIFOLevelReg);
    uint8_t last_bits = spi_read_reg(d, ControlReg) & 0x07;

    if (back && back_len) {
        if (n > *back_len) return RC522_ERR;
        *back_len = n;

        for (uint8_t i = 0; i < n; i++)
            back[i] = spi_read_reg(d, FIFODataReg);
    }
    if (valid_bits) *valid_bits = last_bits;
    return RC522_OK;
}

/* ---------- Public API ---------- */
void rc522_reset(rc522_t *d)
{
    // Hardware reset pulse (recommended for stable start)
    HAL_GPIO_WritePin(d->rst_port, d->rst_pin, GPIO_PIN_RESET);
    HAL_Delay(2);
    HAL_GPIO_WritePin(d->rst_port, d->rst_pin, GPIO_PIN_SET);
    HAL_Delay(50);

    spi_write_reg(d, CommandReg, PCD_SoftReset);
    HAL_Delay(50);
}

void rc522_antenna_on(rc522_t *d)
{
    uint8_t v = spi_read_reg(d, TxControlReg);
    if (!(v & 0x03)) spi_write_reg(d, TxControlReg, v | 0x03);
}

rc522_status_t rc522_init(rc522_t *d)
{
    cs_high(d);
    rc522_reset(d);

    // Timer + CRC preset typical init values
    spi_write_reg(d, TModeReg, 0x8D);
    spi_write_reg(d, TPrescalerReg, 0x3E);
    spi_write_reg(d, TReloadRegL, 30);
    spi_write_reg(d, TReloadRegH, 0);

    // Force 100% ASK
    spi_write_reg(d, TxASKReg, 0x40);
    spi_write_reg(d, ModeReg, 0x3D);

    rc522_antenna_on(d);
    return RC522_OK;
}

rc522_status_t rc522_is_new_card_present(rc522_t *d)
{
    uint8_t req = PICC_REQA;
    uint8_t back[2] = {0};
    uint8_t blen = 2;
    uint8_t vbits = 0;

    // REQA is 7-bit
    rc522_status_t st = transceive(d, &req, 1, back, &blen, &vbits, 7);
    if (st != RC522_OK) return st;

    return (blen == 2) ? RC522_OK : RC522_ERR;
}

rc522_status_t rc522_read_card_serial(rc522_t *d, rc522_uid_t *out_uid)
{
    // Anti-collision CL1
    uint8_t cmd[2] = { PICC_ANTICOLL_CL1, 0x20 };
    uint8_t back[5] = {0};
    uint8_t blen = 5;
    uint8_t vbits = 0;

    // Clear collision settings
    clear_bit_mask(d, CollReg, 0x80);

    rc522_status_t st = transceive(d, cmd, 2, back, &blen, &vbits, 0);
    if (st != RC522_OK) return st;
    if (blen != 5) return RC522_ERR;

    // BCC check
    uint8_t bcc = back[0] ^ back[1] ^ back[2] ^ back[3];
    if (bcc != back[4]) return RC522_ERR;

    out_uid->uid_len = 4;
    memcpy(out_uid->uid, back, 4);

    // Select CL1
    uint8_t sel[9] = {0};
    sel[0] = PICC_SELECT_CL1;
    sel[1] = 0x70;
    sel[2] = back[0];
    sel[3] = back[1];
    sel[4] = back[2];
    sel[5] = back[3];
    sel[6] = back[4];

    uint8_t crc[2];
    if (calc_crc(d, sel, 7, crc) != RC522_OK) return RC522_ERR;
    sel[7] = crc[0];
    sel[8] = crc[1];

    uint8_t sak[3] = {0};
    uint8_t sak_len = 3;
    st = transceive(d, sel, 9, sak, &sak_len, &vbits, 0);
    if (st != RC522_OK) return st;

    return RC522_OK;
}

rc522_status_t rc522_auth_keyA(rc522_t *d, uint8_t block_addr, const uint8_t keyA[6], const rc522_uid_t *uid)
{
    // MFAuthent FIFO must be: authcmd + blockaddr + key(6) + uid(4)
    uint8_t buf[12];
    buf[0] = PICC_AUTH_KEYA;
    buf[1] = block_addr;
    memcpy(&buf[2], keyA, 6);
    memcpy(&buf[8], uid->uid, 4);

    spi_write_reg(d, CommandReg, PCD_Idle);
    spi_write_reg(d, ComIrqReg, 0x7F);
    set_bit_mask(d, FIFOLevelReg, 0x80);

    for (int i = 0; i < 12; i++)
        spi_write_reg(d, FIFODataReg, buf[i]);

    spi_write_reg(d, CommandReg, PCD_MFAuthent);

    uint32_t t0 = HAL_GetTick();
    while (1) {
        uint8_t irq = spi_read_reg(d, ComIrqReg);
        if (irq & 0x10) break; // IdleIRq indicates end
        if ((HAL_GetTick() - t0) > 50) return RC522_TIMEOUT;
    }

    // Status2Reg MFCrypto1On bit indicates Crypto1 enabled after successful auth
    if (!(spi_read_reg(d, Status2Reg) & 0x08))
        return RC522_AUTH_FAIL;

    return RC522_OK;
}

void rc522_stop_crypto1(rc522_t *d)
{
    clear_bit_mask(d, Status2Reg, 0x08);
}

rc522_status_t rc522_mifare_read(rc522_t *d, uint8_t block_addr, uint8_t out16[16])
{
    uint8_t cmd[4];
    cmd[0] = PICC_READ;
    cmd[1] = block_addr;

    uint8_t crc[2];
    if (calc_crc(d, cmd, 2, crc) != RC522_OK) return RC522_ERR;
    cmd[2] = crc[0];
    cmd[3] = crc[1];

    uint8_t back[18] = {0};
    uint8_t blen = 18;
    uint8_t vbits = 0;

    rc522_status_t st = transceive(d, cmd, 4, back, &blen, &vbits, 0);
    if (st != RC522_OK) return st;
    if (blen < 16) return RC522_ERR;

    memcpy(out16, back, 16);
    return RC522_OK;
}

static bool mifare_ack_ok(const uint8_t *resp, uint8_t len)
{
    // ACK is 4-bit 0xA (usually arrives in low nibble)
    if (len != 1) return false;
    return ((resp[0] & 0x0F) == 0x0A);
}

rc522_status_t rc522_mifare_write(rc522_t *d, uint8_t block_addr, const uint8_t in16[16])
{
    uint8_t cmd[4];
    cmd[0] = PICC_WRITE;
    cmd[1] = block_addr;

    uint8_t crc[2];
    if (calc_crc(d, cmd, 2, crc) != RC522_OK) return RC522_ERR;
    cmd[2] = crc[0];
    cmd[3] = crc[1];

    uint8_t resp[2] = {0};
    uint8_t rlen = 2;
    uint8_t vbits = 0;

    rc522_status_t st = transceive(d, cmd, 4, resp, &rlen, &vbits, 0);
    if (st != RC522_OK) return st;
    if (!mifare_ack_ok(resp, rlen)) return RC522_NAK;

    uint8_t frame[18];
    memcpy(frame, in16, 16);
    if (calc_crc(d, frame, 16, crc) != RC522_OK) return RC522_ERR;
    frame[16] = crc[0];
    frame[17] = crc[1];

    rlen = 2; vbits = 0;
    st = transceive(d, frame, 18, resp, &rlen, &vbits, 0);
    if (st != RC522_OK) return st;
    if (!mifare_ack_ok(resp, rlen)) return RC522_NAK;

    return RC522_OK;
}

void rc522_haltA(rc522_t *d)
{
    uint8_t cmd[4];
    cmd[0] = PICC_HLTA;
    cmd[1] = 0x00;
    uint8_t crc[2];
    if (calc_crc(d, cmd, 2, crc) != RC522_OK) return;
    cmd[2] = crc[0];
    cmd[3] = crc[1];

    uint8_t back[2];
    uint8_t blen = 2;
    uint8_t vbits = 0;
    (void)transceive(d, cmd, 4, back, &blen, &vbits, 0);
}
