#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* 受控 PNG fixture：IHDR 宽高按 32 位相乘，溢出后分配过小，随后按真实宽高写入。
   用于验证 P2 结构化变异（PNG IHDR）能否稳定命中写入型越界。 */
static volatile uint32_t g_sink;

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void parse_ihdr(const uint8_t *data, size_t size) {
    if (size < 33) return;
    if (memcmp(data + 12, "IHDR", 4) != 0) return;
    uint32_t w = be32(data + 16);
    uint32_t h = be32(data + 20);
    if (w == 0 || h == 0) return;
    if (w > 1000000u || h > 1000000u) return;
    uint32_t total32 = w * h;              /* 32 位溢出点 */
    size_t total = (size_t)total32;
    uint8_t *buf = (uint8_t *)malloc(total ? total : 1);
    if (!buf) return;
    for (uint32_t y = 0; y < h; y++) {
        memset(buf + (size_t)y * w, 0x41, w);   /* 写入 w*h 字节 */
    }
    g_sink += buf[0];
    free(buf);
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 2;
    uint8_t buf[4096];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);
    if (n < 8 || memcmp(buf, "\x89PNG\r\n\x1a\n", 8) != 0) return 1;
    char hdr[16];
    memcpy(hdr, buf, 16);
    g_sink += (uint32_t)(unsigned char)hdr[0];
    parse_ihdr(buf, n);
    if (g_sink == 0xdeadbeefu) fprintf(stderr, "sink=%u\n", g_sink);
    return 0;
}
