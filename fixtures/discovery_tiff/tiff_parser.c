#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* 受控 TIFF fixture：读第一段 Strip 的 count/offset，按文件可用长度截断后
   拷贝进 64 字节缓冲区。count 被结构化成大值即可触发写入型越界。 */
static volatile uint32_t g_sink;

static uint16_t rd16(const uint8_t *p, int le) {
    return le ? (uint16_t)(p[0] | (p[1] << 8)) : (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t rd32(const uint8_t *p, int le) {
    if (le) return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                   ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void parse_ifd(const uint8_t *data, size_t size) {
    if (size < 26) return;
    int le;
    if (data[0] == 'I' && data[1] == 'I') le = 1;
    else if (data[0] == 'M' && data[1] == 'M') le = 0;
    else return;
    if (rd16(data + 2, le) != 42) return;
    uint32_t ifd = rd32(data + 4, le);
    if (ifd + 18 > size) return;
    uint16_t n = rd16(data + ifd, le);
    if (n == 0) return;
    uint32_t cnt = rd32(data + ifd + 6, le);   /* 第一项 count */
    uint32_t off = rd32(data + ifd + 10, le);  /* 第一项 value/offset */
    size_t avail = (off < size) ? size - off : 0;
    if (cnt > (1u << 20)) return;
    size_t take = (cnt < avail) ? cnt : avail;
    uint8_t *buf = (uint8_t *)malloc(64);
    if (!buf) return;
    if (take) memcpy(buf, data + off, take);   /* take > 64 时写越界 */
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
    if (n < 8) return 1;
    if (!((buf[0] == 'I' && buf[1] == 'I') || (buf[0] == 'M' && buf[1] == 'M')))
        return 1;
    char hdr[8];
    memcpy(hdr, buf, 8);
    g_sink += (uint32_t)(unsigned char)hdr[0];
    parse_ifd(buf, n);
    if (g_sink == 0xdeadbeefu) fprintf(stderr, "sink=%u\n", g_sink);
    return 0;
}
