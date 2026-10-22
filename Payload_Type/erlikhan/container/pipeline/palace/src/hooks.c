/* IAT hooks. Default: stubs (Go runtimes must not hook: the
 * preemptive scheduler corrupts hook state between preemptions).
 *
 * With PALACE_HOOKS (native only): patch the current image's IAT
 * for GetProcAddress, LoadLibraryW and ExitThread. The first two
 * are interception points that pass through to the originals; the
 * ExitThread detour wipes the shellcode region before exiting so a
 * host-driven exit cannot leave secrets behind. */
#include "loader.h"
#include "services.h"

#ifndef PALACE_HOOKS

int hooks_install(void *region, size_t len) {
    (void)region;
    (void)len;
    return 0;
}

void hooks_remove(void) {
}

#else

static void *hooked_region = 0;
static size_t hooked_len = 0;

static void *(*orig_GetProcAddress)(void *, const char *) = 0;
static void *(*orig_LoadLibraryW)(const uint16_t *) = 0;
static void (*orig_ExitThread)(uint32_t) = 0;

static void *hook_GetProcAddress(void *mod, const char *name) {
    return orig_GetProcAddress(mod, name);
}

static void *hook_LoadLibraryW(const uint16_t *name) {
    return orig_LoadLibraryW(name);
}

static void hook_ExitThread(uint32_t code) {
    if (hooked_region && hooked_len)
        secure_wipe(hooked_region, hooked_len);
    orig_ExitThread(code);
}

static uint32_t hook_u32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static int ascii_iequals(const char *a, const char *b) {
    for (;; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z')
            x += (char)('a' - 'A');
        if (y >= 'A' && y <= 'Z')
            y += (char)('a' - 'A');
        if (x != y)
            return 0;
        if (x == 0)
            return 1;
    }
}

/* Patch one IAT slot in image_base; returns the previous value. */
static void *hook_iat(void *image_base, const char *dll, const char *func, void *detour) {
    uint8_t *base = (uint8_t *)image_base;
    if (base[0] != 'M' || base[1] != 'Z')
        return 0;
    uint32_t pe = hook_u32(base + 0x3C);
    if (pe > 0x1000)
        return 0;
    uint8_t *nt = base + pe;
    if (nt[24] != 0x0B || nt[25] != 0x02) /* PE32+ */
        return 0;
    uint32_t imp_rva = hook_u32(nt + 24 + 120);
    if (!imp_rva)
        return 0;
    for (uint8_t *d = base + imp_rva;; d += 20) {
        uint32_t oft = hook_u32(d);
        uint32_t name = hook_u32(d + 12);
        uint32_t ft = hook_u32(d + 16);
        if (!oft && !name && !ft)
            return 0;
        if (!ascii_iequals(dll, (const char *)(base + name)))
            continue;
        for (uint32_t i = 0;; i++) {
            uint8_t *slot = base + ft + i * 8;
            uint8_t *name_thunk = base + (oft ? oft : ft) + i * 8;
            uint64_t ord = 0;
            for (int k = 0; k < 8; k++)
                ord |= (uint64_t)name_thunk[k] << (k * 8);
            if (!ord)
                break;
            if (ord & 0x8000000000000000ULL)
                continue; /* ordinal import */
            uint32_t hint_name = (uint32_t)(ord & 0x7FFFFFFFULL);
            if (!ascii_iequals(func, (const char *)(base + hint_name + 2)))
                continue;
            void *prev = 0;
            for (int k = 0; k < 8; k++)
                ((uint8_t *)&prev)[k] = slot[k];
            ULONG old = 0;
            if (!_VirtualProtect(slot, 8, PAGE_READWRITE, &old))
                return 0;
            for (int k = 0; k < 8; k++)
                slot[k] = ((uint8_t *)&detour)[k];
            ULONG tmp = 0;
            _VirtualProtect(slot, 8, old, &tmp);
            return prev;
        }
        return 0;
    }
}

static void *unhook_iat(void *image_base, const char *dll, const char *func, void *orig) {
    return hook_iat(image_base, dll, func, orig);
}

int hooks_install(void *region, size_t len) {
    hooked_region = region;
    hooked_len = len;
    void *img = peb_image_base();
    if (!img)
        return 0;
    void *p;
    p = hook_iat(img, "kernel32.dll", "GetProcAddress", (void *)hook_GetProcAddress);
    if (p)
        orig_GetProcAddress = (void *(*)(void *, const char *))p;
    p = hook_iat(img, "kernel32.dll", "LoadLibraryW", (void *)hook_LoadLibraryW);
    if (p)
        orig_LoadLibraryW = (void *(*)(const uint16_t *))p;
    p = hook_iat(img, "kernel32.dll", "ExitThread", (void *)hook_ExitThread);
    if (p)
        orig_ExitThread = (void (*)(uint32_t))p;
    /* Best-effort: a host without these imports still runs. */
    return 1;
}

void hooks_remove(void) {
    void *img = peb_image_base();
    if (!img)
        return;
    if (orig_GetProcAddress)
        unhook_iat(img, "kernel32.dll", "GetProcAddress", (void *)orig_GetProcAddress);
    if (orig_LoadLibraryW)
        unhook_iat(img, "kernel32.dll", "LoadLibraryW", (void *)orig_LoadLibraryW);
    if (orig_ExitThread)
        unhook_iat(img, "kernel32.dll", "ExitThread", (void *)orig_ExitThread);
    orig_GetProcAddress = 0;
    orig_LoadLibraryW = 0;
    orig_ExitThread = 0;
    hooked_region = 0;
    hooked_len = 0;
}

#endif
