/* PICO runtime: parse the blob, expose code size and tag offsets.
 * The loader copies the code to an RX region and calls tags by
 * offset. For Go runtimes the blob is the two-RET stub. */
#include "loader.h"
#include "pico.h"
#include "services.h"

static uint32_t pico_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int pico_code_size(const void *blob) {
    const uint8_t *b = (const uint8_t *)blob;
    uint32_t total = pico_u32(b);
    uint32_t n = pico_u32(b + 4);
    if (total < 8 + 8 * n)
        return -1;
    return (int)(total - 8 - 8 * n);
}

/* Returns the code-relative offset for tag, or -1. */
int pico_export_offset(const void *blob, int tag) {
    const uint8_t *b = (const uint8_t *)blob;
    uint32_t n = pico_u32(b + 4);
    if (n > 256)
        return -1;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t t = pico_u32(b + 8 + i * 8);
        uint32_t off = pico_u32(b + 12 + i * 8);
        if ((int)t == tag)
            return (int)off;
    }
    return -1;
}
