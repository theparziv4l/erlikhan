/* Shared loader types and prototypes. Freestanding: stdint/stddef
 * only, no windows.h, no CRT calls anywhere in the loader. */
#ifndef PALACE_LOADER_H
#define PALACE_LOADER_H

#include <stddef.h>
#include <stdint.h>

#ifndef NULL
#define NULL ((void *)0)
#endif

typedef int32_t NTSTATUS;
typedef int32_t LONG;
typedef uint32_t ULONG;
typedef uint16_t USHORT;
typedef uint8_t BOOLEAN;
typedef uint8_t BYTE;
typedef uint16_t WCHAR;
typedef uint64_t ULONG_PTR;
typedef uint64_t SIZE_T;
typedef int64_t LONGLONG;
typedef uint32_t DWORD;
typedef void *HANDLE;
typedef void *PVOID;
typedef void *HMODULE;
typedef ULONG *PULONG;

#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_TIMEOUT ((NTSTATUS)0x00000102)

#define MEM_COMMIT 0x1000u
#define MEM_RESERVE 0x2000u
#define MEM_RELEASE 0x8000u
#define PAGE_READWRITE 0x04u
#define PAGE_EXECUTE_READ 0x20u
#define PAGE_EXECUTE_READWRITE 0x40u

#define TH32CS_SNAPPROCESS 0x2u
#define TH32CS_SNAPTHREAD 0x4u
#define CREATE_SUSPENDED 0x4u
#define THREAD_SUSPEND_RESUME 0x2u
#define PROCESS_VM_ACCESS 0x043Au /* create-thread|vm-op|vm-w|r|query */

/* RESOURCE mirrors the Go PrependLen layout: {uint32 len; bytes}. */
typedef struct {
    uint32_t len;
    uint8_t value[];
} RESOURCE;

#define GETRESOURCE(sym) ((RESOURCE *)(void *)&(sym))

/* GETRESOURCE markers: zero-length definitions in named sections.
 * The spec linker fills each section with a RESOURCE blob. */
extern char _DLL_[];
extern char _MASK_[];
extern char _PICO_[];

/* Small helpers (services.c). */
void palace_zero(void *p, size_t n);
int palace_ascii_iequals_w(const char *a, const WCHAR *w);
uint32_t palace_ror13(const char *name);

/* services.c: API resolution. */
int resolve_all(void);
void *peb_image_base(void);
void *peb_module_base(const char *dll_ascii);
void *patch_resolve(uint32_t hash);
void *patch_find(const char *name);

/* pico.c: tag-dispatch runtime. */
int pico_code_size(const void *blob);
int pico_export_offset(const void *blob, int tag);

/* hooks.c */
int hooks_install(void *region, size_t len);
void hooks_remove(void);

/* mask.c */
void mask_region(void *addr, size_t len, const uint8_t *key, size_t keylen);
int masked_join(void *thread, void *region, size_t len, const uint8_t *key, size_t keylen, int *rounds);

/* spoof.c */
int spoof_enter(void);
void spoof_leave(void);

/* cfg.c */
void cfg_register(void *base, size_t size);

/* cleanup.c */
void cleanup_zero(void *addr, size_t len);
void secure_wipe(void *addr, size_t len);

#endif
