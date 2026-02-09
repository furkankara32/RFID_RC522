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

/* --- CR/LF robust handling (Enter = '\r' or '\n', CRLF supported) --- */
static uint8_t s_last_was_cr = 0;

static int uart_getc(UART_HandleTypeDef *huart)
{
    uint8_t c;

    while (1) {
        if (HAL_UART_Receive(huart, &c, 1, HAL_MAX_DELAY) != HAL_OK)
            return -1;

        if (s_last_was_cr && c == '\n') {
            s_last_was_cr = 0;
            continue;
        }

        s_last_was_cr = (c == '\r') ? 1 : 0;
        return (int)c;
    }
}

static void uart_readline(UART_HandleTypeDef *huart, char *buf, size_t max)
{
    size_t i = 0;
    while (i + 1 < max) {
        int ch = uart_getc(huart);
        if (ch < 0) continue;

        if (ch == '\r' || ch == '\n')
            break;

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

/* -------- Location selection -------- */
typedef struct {
    uint8_t sector;
    uint8_t block;
    uint8_t sector_full;
    uint8_t block_full;
} loc_sel_t;

static int starts_with_full(const char *p)
{
    if (!p || !p[0] || !p[1] || !p[2] || !p[3]) return 0;

    return (tolower((unsigned char)p[0])=='f' &&
            tolower((unsigned char)p[1])=='u' &&
            tolower((unsigned char)p[2])=='l' &&
            tolower((unsigned char)p[3])=='l');
}

static bool parse_loc_ext(const char *s, loc_sel_t *out)
{
    memset(out, 0, sizeof(*out));
    while (isspace((unsigned char)*s)) s++;

    if (tolower((unsigned char)s[0]) != 's') return false;
    s++;
    if (*s != ',') return false;
    s++;

    if (starts_with_full(s)) {
        out->sector_full = 1;
        s += 4;
    } else {
        char *end = NULL;
        long sec = strtol(s, &end, 10);
        if (end == s) return false;
        if (sec < 0 || sec > 15) return false;
        out->sector = (uint8_t)sec;
        s = end;
    }

    if (*s != ':') return false;
    s++;
    if (tolower((unsigned char)s[0]) != 'b') return false;
    s++;
    if (*s != ',') return false;
    s++;

    if (starts_with_full(s)) {
        out->block_full = 1;
        s += 4;
    } else {
        char *end = NULL;
        long blk = strtol(s, &end, 10);
        if (end == s) return false;
        if (blk < 0 || blk > 3) return false;
        out->block = (uint8_t)blk;
        s = end;
    }

    while (isspace((unsigned char)*s)) s++;
    return (*s == '\0');
}

/* -------- Print helpers -------- */
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
    if (sector == 0 && block == 0) return true;
    if (block == 3) return true;
    return false;
}

/* -------- Card wait helpers -------- */
static void wait_card_present(rc522_t *r)
{
    while (rc522_is_new_card_present(r) != RC522_OK) {
        HAL_Delay(50);
    }
}

static void wait_card_removed(rc522_t *r)
{
    while (rc522_is_new_card_present(r) == RC522_OK) {
        HAL_Delay(80);
    }
}

/* -------- AUTH retry (DUMP için: DÖNGÜ İÇİNDE stop_crypto1 YOK) -------- */
static rc522_status_t authA_retry_dump(rc522_t *r,
                                      uint8_t block_addr,
                                      const uint8_t keyA[6],
                                      const rc522_uid_t *uid,
                                      int tries)
{
    rc522_status_t st = RC522_AUTH_FAIL;

    for (int i = 0; i < tries; i++) {
        st = rc522_auth_keyA(r, block_addr, keyA, uid);
        if (st == RC522_OK) return RC522_OK;
        HAL_Delay(12);
    }
    return st;
}

/* -------- READ retry -------- */
static rc522_status_t mifare_read_retry(rc522_t *r,
                                       uint8_t block_addr,
                                       uint8_t out16[16],
                                       int tries)
{
    rc522_status_t st = RC522_ERR;

    for (int i = 0; i < tries; i++) {
        st = rc522_mifare_read(r, block_addr, out16);
        if (st == RC522_OK) return RC522_OK;
        HAL_Delay(8);
    }
    return st;
}

/* -------- (tekli mod için) AUTH retry: stop_crypto1 VAR (senin stabil tekli akışın) -------- */
static rc522_status_t authA_retry_single(rc522_t *r,
                                        uint8_t block_addr,
                                        const uint8_t keyA[6],
                                        const rc522_uid_t *uid,
                                        int tries)
{
    rc522_status_t st = RC522_AUTH_FAIL;

    for (int i = 0; i < tries; i++) {
        rc522_stop_crypto1(r);
        HAL_Delay(4);

        st = rc522_auth_keyA(r, block_addr, keyA, uid);
        if (st == RC522_OK) return RC522_OK;

        HAL_Delay(12);
    }
    return st;
}

void RFID_CLI_Run(rfid_cli_t *cli)
{
    UART_HandleTypeDef *huart = cli->huart;

    uart_println(huart, "");
    uart_println(huart, "=== MFRC522 CLI (Nucleo-F767 / SPI1 / USART3 115200) ===");
    uart_println(huart, "Konum format: s,<sektor|full>:b,<blok|full>   (sektor 0-15, blok 0-3)");
    uart_println(huart, "Yazmada yasak: s0:b0 ve trailer b3");
    uart_println(huart, "FULL sadece okuma (R) icin: s,full:b,full");

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

        uart_println(huart, "Konum gir (ornek: s,2:b,2 veya s,full:b,full): ");
        char loc_line[32];
        uart_readline(huart, loc_line, sizeof(loc_line));

        loc_sel_t loc;
        if (!parse_loc_ext(loc_line, &loc)) {
            uart_println(huart, "Format hatali. Kartı kaldırın.");
            rc522_haltA(&cli->rc522);
            rc522_stop_crypto1(&cli->rc522);
            wait_card_removed(&cli->rc522);
            continue;
        }

        if (op == 'W' && (loc.sector_full || loc.block_full)) {
            uart_println(huart, "FULL sadece okuma (R) icin destekleniyor.");
            rc522_haltA(&cli->rc522);
            rc522_stop_crypto1(&cli->rc522);
            wait_card_removed(&cli->rc522);
            continue;
        }

        /* ---------------- FULL DUMP (Read only) ---------------- */
        if (op == 'R' && (loc.sector_full || loc.block_full)) {

            uint8_t s_start = loc.sector_full ? 0 : loc.sector;
            uint8_t s_end   = loc.sector_full ? 15 : loc.sector;
            uint8_t b_start = loc.block_full  ? 0 : loc.block;
            uint8_t b_end   = loc.block_full  ? 3 : loc.block;

            uart_println(huart, "DUMP basliyor... (Kart sabit kalsin)");

            // DUMP'a temiz başla
            rc522_stop_crypto1(&cli->rc522);
            HAL_Delay(5);

            for (uint8_t s = s_start; s <= s_end; s++) {

                // Her sektör için 1 kez AUTH (genelde trailer'a auth en stabil)
                uint8_t trailer_block = (uint8_t)(s * 4 + 3);

                rc522_status_t ast = authA_retry_dump(&cli->rc522, trailer_block, keyA, &uid, 10);
                if (ast != RC522_OK) {
                    char msg[96];
                    snprintf(msg, sizeof(msg), "s[%u] AUTH FAIL", s);
                    uart_println(huart, msg);
                    continue;
                }

                for (uint8_t b = b_start; b <= b_end; b++) {
                    uint8_t ab = (uint8_t)(s * 4 + b);
                    uint8_t data[16];

                    rc522_status_t st = mifare_read_retry(&cli->rc522, ab, data, 3);

                    char ascii[17];
                    for (int i = 0; i < 16; i++) {
                        ascii[i] = (data[i] >= 32 && data[i] <= 126) ? (char)data[i] : '.';
                    }
                    ascii[16] = 0;

                    char line[220];
                    if (st == RC522_OK) {
                        snprintf(line, sizeof(line), "s[%u]b[%u] = \"%s\"", s, b, ascii);
                    } else {
                        snprintf(line, sizeof(line), "s[%u]b[%u] = <READ_FAIL>", s, b);
                    }
                    uart_println(huart, line);

                    HAL_Delay(2);
                }

                HAL_Delay(5);
            }

            uart_println(huart, "DUMP bitti.");

            // DUMP sonunda tek sefer düzgün kapat
            rc522_haltA(&cli->rc522);
            rc522_stop_crypto1(&cli->rc522);

            uart_println(huart, "Kartı kaldırın...");
            wait_card_removed(&cli->rc522);
            continue;
        }

        /* ---------------- Normal single block R/W ---------------- */
        if (op == 'W' && is_write_forbidden(loc.sector, loc.block)) {
            uart_println(huart, "Bu blok yazmaya kapali (s0:b0 veya trailer b3).");
            rc522_haltA(&cli->rc522);
            rc522_stop_crypto1(&cli->rc522);
            wait_card_removed(&cli->rc522);
            continue;
        }

        uint8_t abs_block = (uint8_t)(loc.sector * 4 + loc.block);

        if (authA_retry_single(&cli->rc522, abs_block, keyA, &uid, 10) != RC522_OK) {
            uart_println(huart, "AUTH FAIL. Kartı kaldırıp tekrar deneyin.");
            rc522_haltA(&cli->rc522);
            rc522_stop_crypto1(&cli->rc522);
            wait_card_removed(&cli->rc522);
            continue;
        }

        if (op == 'R') {
            uint8_t data[16];
            rc522_status_t st = mifare_read_retry(&cli->rc522, abs_block, data, 3);
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
            memset(block16, ' ', sizeof(block16));
            size_t L = strlen(msg);
            if (L > 16) L = 16;
            memcpy(block16, msg, L);

            rc522_status_t st = rc522_mifare_write(&cli->rc522, abs_block, block16);
            if (st == RC522_OK) uart_println(huart, "OK - Yazma tamamlandi.");
            else if (st == RC522_NAK) uart_println(huart, "WRITE NAK (Access/Key sorunu olabilir).");
            else uart_println(huart, "WRITE FAIL. Kartı kaldırıp tekrar okutun.");
        }

        rc522_haltA(&cli->rc522);
        rc522_stop_crypto1(&cli->rc522);

        uart_println(huart, "Kartı kaldırın...");
        wait_card_removed(&cli->rc522);
    }
}
