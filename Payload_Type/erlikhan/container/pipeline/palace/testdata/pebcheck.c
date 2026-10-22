/* PEB resolver check: normal EXE that runs resolve_all and
 * prints every resolved pointer for inspection. */
#include <stdio.h>
#include "loader.h"
#include "services.h"

#define SHOW(f) printf("%-28s %p\n", #f, (void *)_##f)

int main(void) {
    printf("image=%p ntdll=%p kernel32=%p\n",
        peb_image_base(), peb_module_base("ntdll.dll"), peb_module_base("kernel32.dll"));
    printf("ror13(NtAllocateVirtualMemory)=0x%08X\n", palace_ror13("NtAllocateVirtualMemory"));
    if (!resolve_all()) {
        printf("RESOLVE_FAILED\n");
        return 1;
    }
    SHOW(NtAllocateVirtualMemory);
    SHOW(NtWriteVirtualMemory);
    SHOW(NtProtectVirtualMemory);
    SHOW(NtCreateThreadEx);
    SHOW(NtWaitForSingleObject);
    SHOW(NtFreeVirtualMemory);
    SHOW(NtSuspendThread);
    SHOW(NtResumeThread);
    SHOW(NtDelayExecution);
    SHOW(RtlExitUserThread);
    SHOW(VirtualAlloc);
    SHOW(VirtualProtect);
    SHOW(VirtualFree);
    SHOW(LoadLibraryA);
    SHOW(GetProcAddress);
    SHOW(CreateToolhelp32Snapshot);
    SHOW(Process32FirstW);
    SHOW(Process32NextW);
    SHOW(Thread32First);
    SHOW(Thread32Next);
    SHOW(OpenProcess);
    SHOW(OpenThread);
    SHOW(CreateProcessW);
    SHOW(CloseHandle);
    SHOW(ResumeThread);
    printf("RESOLVE_OK\n");
    /* Exercise one resolved call. */
    void *m = _VirtualAlloc(0, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("alloc=%p\n", m);
    if (m)
        _VirtualFree(m, 0, MEM_RELEASE);
    return 0;
}
