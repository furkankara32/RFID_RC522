#include "rfid_cli.h"
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

static void uart_print(UART_HandleTypeDef *huart, const char *s)
{
    HAL_UART_Transmit(huart, (uint8_t*)s, (uint16_t)strlen(s), HAL_MAX_DELAY);
}

static void uart_println(UART_HandleTypeDef *huart, const char *s)
{
    uart_print(huart, s);
    uart_print(huart, "\r\n");
}

static int uart_getc(UART_HandleTypeDef *huart)
{
    uint8_t c;
    if (HAL_UART_Receive(huart, &c, 1, HAL_MAX_DELAY) != HAL_OK) return -1;
    return (int)c;
}

static void uart_readline(UART_HandleTypeDef *huart, char *buf, size_t max)
{
    size_t i = 0;
    while (i + 1 < max) {
        int ch = uart_getc(huart);
        if (ch < 0) continue;
        if (ch == '\r') continue;
        if (ch == '\n') break;

        // backspace
        if (ch == 0x08 || ch == 0x7F) {
            if (i > 0) {
                i--;
                uart_print(huart, "\b \b");
            }
            continue;
        }

        buf[i++] = (char)ch;
        HAL_UART_Transmit(huart, (uint8_t*)&ch, 1, HAL_MAX_DELAY); // echo
    }
    buf[i] = 0;
    uart_print(huart, "\r\n");
}

static bool parse_loc(const char *s, uint8_t *sector, uint8_t *block)
{
    // expected: s,<sec>:b,<blk>
    while (isspace((unsigned char)*s)) s++;
    if (tolower((unsigned char)s[0]) != 's') return false;
    s++;
    if (*s != ',') return false;
    s++;

    char *end = NULL;
    long sec = strtol(s, &end, 10);
    if (end == s) return false;
    s = end;

    if (*s != ':') return false;
    s++;
    if (tolower((unsigned char)s[0]) != 'b') return false;
    s++;
    if (*s != ',') return false;
    s++;

    long blk = strtol(s, &end, 10);
    if (end == s) return false;

    if (sec < 0 || sec > 15) return false;
    if (blk < 0 || blk > 3) return false;

    *sector = (uint8_t)sec;
    *block  = (uint8_t)blk;
    return true;
}

static void print_uid(UART_HandleTypeDef *huart, const rc522_uid_t *uid)
{
    char line[128];
    int n = 0;
    n += snprintf(line + n, sizeof(line) - n, "UID: ");
    for (uint8_t i = 0; i < uid->uid_len; i++)
        n += snprintf(line + n, sizeof(line) - n, "%02X ", uid->uid[i]);
    uart_println(huart, line);
}

static void dump_block(UART_HandleTypeDef *huart, const uint8_t b[16])
{
    char line[256];
    int n = 0;

    n += snprintf(line + n, sizeof(line) - n, "HEX : ");
    for (int i = 0; i < 16; i++)
        n += snprintf(line + n, sizeof(line) - n, "%02X ", b[i]);

    n += snprintf(line + n, sizeof(line) - n, "\r\nASCII: ");
    for (int i = 0; i < 16; i++) {
        char c = (b[i] >= 32 && b[i] <= 126) ? (char)b[i] : '.';
        n += snprintf(line + n, sizeof(line) - n, "%c", c);
    }
    uart_println(huart, line);
}

static bool is_write_forbidden(uint8_t sector, uint8_t block)
{
    // sector0:block0 is manufacturer data (avoid)
    if (sector == 0 && block == 0) return true;
    // trailer block contains keys/access bits => forbidden as requested
    if (block == 3) return true;
    return false;
}

static void wait_card_present(rc522_t *r)
{
    while (rc522_is_new_card_present(r) != RC522_OK) {
        HAL_Delay(50);
    }
}

static void wait_card_removed(rc522_t *r)
{
    // Wait until REQA fails consistently
    while (rc522_is_new_card_present(r) == RC522_OK) {
        HAL_Delay(80);
    }
}

void RFID_CLI_Run(rfid_cli_t *cli)
{
    UART_HandleTypeDef *huart = cli->huart;

    uart_println(huart, "");
    uart_println(huart, "=== MFRC522 CLI (Nucleo-F767 / SPI1 / USART3 115200) ===");
    uart_println(huart, "Konum format: s,<sektor>:b,<blok>   (sektor 0-15, blok 0-3)");
    uart_println(huart, "Yazmada yasak: s0:b0 ve trailer b3");

    const uint8_t keyA[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

    (void)rc522_init(&cli->rc522);

    while (1) {
        uart_println(huart, "");
        uart_println(huart, "Kartı okutun...");
        wait_card_present(&cli->rc522);

        rc522_uid_t uid;
        if (rc522_read_card_serial(&cli->rc522, &uid) != RC522_OK) {
            uart_println(huart, "Kart okunamadı. Kartı kaldırıp tekrar okutun.");
            wait_card_removed(&cli->rc522);
            continue;
        }
        print_uid(huart, &uid);

        uart_println(huart, "Islem sec (R=Oku, W=Yaz): ");
        char op_line[16];
        uart_readline(huart, op_line, sizeof(op_line));
        char op = (char)toupper((unsigned char)op_line[0]);
        if (op != 'R' && op != 'W') {
            uart_println(huart, "Gecersiz secim. Kartı kaldırın.");
            rc522_haltA(&cli->rc522);
            rc522_stop_crypto1(&cli->rc522);
            wait_card_removed(&cli->rc522);
            continue;
        }

        uart_println(huart, "Konum gir (ornek: s,2:b,2): ");
        char loc_line[32];
        uart_readline(huart, loc_line, sizeof(loc_line));

        uint8_t sector, block;
        if (!parse_loc(loc_line, &sector, &block)) {
            uart_println(huart, "Format hatali. Kartı kaldırın.");
            rc522_haltA(&cli->rc522);
            rc522_stop_crypto1(&cli->rc522);
            wait_card_removed(&cli->rc522);
            continue;
        }

        if (op == 'W' && is_write_forbidden(sector, block)) {
            uart_println(huart, "Bu blok yazmaya kapali (s0:b0 veya trailer b3).");
            rc522_haltA(&cli->rc522);
            rc522_stop_crypto1(&cli->rc522);
            wait_card_removed(&cli->rc522);
            continue;
        }

        uint8_t abs_block = (uint8_t)(sector * 4 + block);

        // Authenticate (Key A)
        if (rc522_auth_keyA(&cli->rc522, abs_block, keyA, &uid) != RC522_OK) {
            uart_println(huart, "AUTH FAIL. KeyA/Access Bits degismis olabilir.");
            rc522_haltA(&cli->rc522);
            rc522_stop_crypto1(&cli->rc522);
            uart_println(huart, "Kartı kaldırın ve tekrar deneyin.");
            wait_card_removed(&cli->rc522);
            continue;
        }

        if (op == 'R') {
            uint8_t data[16];
            rc522_status_t st = rc522_mifare_read(&cli->rc522, abs_block, data);
            if (st == RC522_OK) {
                uart_println(huart, "OK - Okundu:");
                dump_block(huart, data);
            } else {
                uart_println(huart, "READ FAIL. Kartı kaldırıp tekrar okutun.");
            }
        } else {
            uart_println(huart, "Yazilacak ASCII (max 16 char): ");
            char msg[64];
            uart_readline(huart, msg, sizeof(msg));

            uint8_t block16[16];
            memset(block16, ' ', sizeof(block16));   // pad with spaces
            size_t L = strlen(msg);
            if (L > 16) L = 16;
            memcpy(block16, msg, L);

            rc522_status_t st = rc522_mifare_write(&cli->rc522, abs_block, block16);
            if (st == RC522_OK) uart_println(huart, "OK - Yazma tamamlandi.");
            else if (st == RC522_NAK) uart_println(huart, "WRITE NAK (Access/Key sorunu olabilir).");
            else uart_println(huart, "WRITE FAIL. Kartı kaldırıp tekrar okutun.");
        }

        // Proper end-of-session for stability
        rc522_haltA(&cli->rc522);
        rc522_stop_crypto1(&cli->rc522);

        uart_println(huart, "Kartı kaldırın...");
        wait_card_removed(&cli->rc522);
    }
}
