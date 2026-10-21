/* Minimal in-process COFF/BOF loader (x64): maps relocatable objects,
 * applies relocations, resolves Beacon plus Win32 imports through
 * near thunks (REL32 only reaches +-2GB), and runs the entrypoint on a
 * worker thread with a timeout. BOF output (BeaconPrintf / BeaconOutput)
 * is captured into the task result.
 *
 * Unlike the Go agent, C functions are directly callable with varargs,
 * so BeaconPrintf/BeaconFormatPrintf need no trampoline: the loader
 * address is the function itself.
 */
#include "coff.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>

#define COFF_MACHINE_AMD64 0x8664
#define REL_AMD64_ADDR64 1
#define REL_AMD64_ADDR32NB 3
#define REL_AMD64_REL32 4

#define SCN_CNT_CODE 0x20
#define SCN_CNT_IDATA 0x40
#define SCN_CNT_UDATA 0x80

#define MAX_COFF_BYTES (16u * 1024u * 1024u)
#define MAX_BEACON_OUTPUT (4u * 1024u * 1024u)
#define MAX_SECTIONS 96
#define MAX_SYMBOLS 100000

/* BOF-side parser struct (x64 layout): two pointers, two ints. */
typedef struct {
    char *original;
    char *buffer;
    int length;
    int size;
} datap_t;

/* Opaque format buffer the BeaconFormat* API operates on. BOFs only ever
 * pass back the pointer we return, so it doubles as a table key. */
typedef struct {
    char *data;
    size_t len;
    size_t cap;
    char **owned; /* ToString copies, freed on reset/free */
    size_t nowned;
} formatbuf_t;

typedef struct {
    char *out;
    size_t outlen;
    size_t outcap;
    formatbuf_t **formats;
    size_t nformats;
    CRITICAL_SECTION lock;
} beacon_run_t;

/* Dispatch runs tasks sequentially; the run pointer is only live while
 * the BOF worker thread is joined (or deliberately abandoned on
 * timeout, in which case the heap run stays valid for the stray
 * thread). Callbacks take the lock because they arrive off-thread.
 */
static beacon_run_t *g_run;

static void run_lock(beacon_run_t *r) {
    if (r)
        EnterCriticalSection(&r->lock);
}

static void run_unlock(beacon_run_t *r) {
    if (r)
        LeaveCriticalSection(&r->lock);
}

static void run_append(beacon_run_t *r, const char *data, size_t len) {
    size_t room;
    if (!r || !data || len == 0 || r->outlen >= MAX_BEACON_OUTPUT)
        return;
    room = MAX_BEACON_OUTPUT - r->outlen;
    if (len > room)
        len = room;
    if (r->outlen + len + 1 > r->outcap) {
        size_t ncap = r->outlen + len + 1;
        char *grown = (char *)realloc(r->out, ncap);
        if (!grown)
            return;
        r->out = grown;
        r->outcap = ncap;
    }
    memcpy(r->out + r->outlen, data, len);
    r->outlen += len;
    r->out[r->outlen] = 0;
}

static void beacon_emit(const char *data, size_t len) {
    beacon_run_t *r = g_run;
    run_lock(r);
    run_append(r, data, len);
    run_unlock(r);
}

/* --- Beacon data API (Apollo-compatible packing: u32LE total prefix,
 * raw LE int16/int32, LE-length-prefixed blobs) --- */

void BeaconDataParse(datap_t *parser, char *buffer, int size) {
    parser->original = buffer;
    parser->buffer = buffer + 4;
    parser->length = size - 4 < 0 ? 0 : size - 4;
    parser->size = parser->length;
}

int BeaconDataInt(datap_t *parser) {
    int v;
    if (parser->length < 4)
        return 0;
    memcpy(&v, parser->buffer, 4);
    parser->buffer += 4;
    parser->length -= 4;
    return v;
}

short BeaconDataShort(datap_t *parser) {
    short v;
    if (parser->length < 2)
        return 0;
    memcpy(&v, parser->buffer, 2);
    parser->buffer += 2;
    parser->length -= 2;
    return v;
}

char *BeaconDataExtract(datap_t *parser, int *size) {
    int len;
    char *ptr;
    if (parser->length < 4) {
        if (size)
            *size = 0;
        return parser->buffer;
    }
    memcpy(&len, parser->buffer, 4);
    if (len < 0 || len > parser->length - 4) {
        if (size)
            *size = 0;
        return parser->buffer + 4;
    }
    ptr = parser->buffer + 4;
    parser->buffer += 4 + len;
    parser->length -= 4 + len;
    if (size)
        *size = len;
    return ptr;
}

int BeaconDataLength(datap_t *parser) {
    return parser->length;
}

/* --- Beacon output API --- */

int BeaconPrintf(int type, const char *fmt, ...) {
    char stackbuf[8192];
    va_list ap;
    int n;
    char *heapbuf = NULL;
    const char *text;
    char prefix[32];
    if (!fmt)
        return 0;
    va_start(ap, fmt);
    n = vsnprintf(stackbuf, sizeof(stackbuf), fmt, ap);
    va_end(ap);
    if (n < 0)
        return 0;
    text = stackbuf;
    if ((size_t)n >= sizeof(stackbuf)) {
        heapbuf = (char *)malloc((size_t)n + 1);
        if (heapbuf) {
            va_start(ap, fmt);
            vsnprintf(heapbuf, (size_t)n + 1, fmt, ap);
            va_end(ap);
            text = heapbuf;
        } else {
            n = (int)sizeof(stackbuf) - 1;
        }
    }
    if (type != 0) {
        snprintf(prefix, sizeof(prefix), "[type %d] ", type);
        beacon_emit(prefix, strlen(prefix));
    }
    beacon_emit(text, (size_t)n);
    free(heapbuf);
    return n;
}

void BeaconOutput(int type, const char *data, int len) {
    (void)type;
    if (data && len > 0)
        beacon_emit(data, (size_t)len);
}

unsigned long long BeaconGetValue(int type) {
    (void)type;
    return 0;
}

BOOL BeaconIsAdmin(void) {
    typedef BOOL(WINAPI *isadmin_t)(void);
    static isadmin_t fn;
    static int looked_up;
    if (!looked_up) {
        HMODULE shell32 = GetModuleHandleA("shell32.dll");
        if (shell32)
            fn = (isadmin_t)(void *)GetProcAddress(shell32, "IsUserAnAdmin");
        looked_up = 1;
    }
    if (fn)
        return fn();
    return FALSE;
}

/* --- Beacon format API --- */

typedef void formatp_t;

static formatbuf_t *format_lookup(formatp_t *p) {
    beacon_run_t *r = g_run;
    size_t i;
    if (!r || !p)
        return NULL;
    for (i = 0; i < r->nformats; i++) {
        if ((formatp_t *)r->formats[i] == p)
            return r->formats[i];
    }
    return NULL;
}

formatp_t *BeaconFormatAlloc(char *buffer, int size) {
    beacon_run_t *r = g_run;
    formatbuf_t *f;
    formatbuf_t **grown;
    (void)buffer;
    (void)size;
    if (!r)
        return NULL;
    /* Fresh growable buffer (ignores the caller buffer like the Go
     * loader does); BOFs only read it back through ToString. */
    f = (formatbuf_t *)calloc(1, sizeof(*f));
    if (!f)
        return NULL;
    run_lock(r);
    grown = (formatbuf_t **)realloc(r->formats, (r->nformats + 1) * sizeof(*grown));
    if (!grown) {
        run_unlock(r);
        free(f);
        return NULL;
    }
    r->formats = grown;
    r->formats[r->nformats++] = f;
    run_unlock(r);
    return (formatp_t *)f;
}

static void format_free_owned(formatbuf_t *f) {
    size_t i;
    for (i = 0; i < f->nowned; i++)
        free(f->owned[i]);
    free(f->owned);
    f->owned = NULL;
    f->nowned = 0;
}

void BeaconFormatReset(formatp_t *p) {
    formatbuf_t *f;
    beacon_run_t *r = g_run;
    run_lock(r);
    f = format_lookup(p);
    if (f) {
        format_free_owned(f);
        f->len = 0;
    }
    run_unlock(r);
}

void BeaconFormatFree(formatp_t *p) {
    beacon_run_t *r = g_run;
    size_t i;
    run_lock(r);
    for (i = 0; i < r->nformats; i++) {
        if ((formatp_t *)r->formats[i] == p) {
            format_free_owned(r->formats[i]);
            free(r->formats[i]->data);
            free(r->formats[i]);
            r->formats[i] = r->formats[--r->nformats];
            break;
        }
    }
    run_unlock(r);
}

static void format_reserve(formatbuf_t *f, size_t extra) {
    size_t want = f->len + extra;
    char *grown;
    if (want > MAX_BEACON_OUTPUT)
        want = MAX_BEACON_OUTPUT;
    if (want + 1 <= f->cap)
        return;
    grown = (char *)realloc(f->data, want + 1);
    if (grown) {
        f->data = grown;
        f->cap = want + 1;
    }
}

void BeaconFormatAppend(formatp_t *p, char *data, int len) {
    formatbuf_t *f;
    beacon_run_t *r = g_run;
    size_t room;
    if (!data || len <= 0)
        return;
    run_lock(r);
    f = format_lookup(p);
    if (f && f->len < MAX_BEACON_OUTPUT) {
        room = MAX_BEACON_OUTPUT - f->len;
        if ((size_t)len > room)
            len = (int)room;
        format_reserve(f, (size_t)len);
        if (f->len + (size_t)len <= f->cap) {
            memcpy(f->data + f->len, data, (size_t)len);
            f->len += (size_t)len;
        }
    }
    run_unlock(r);
}

void BeaconFormatPrintf(formatp_t *p, char *fmt, ...) {
    char stackbuf[8192];
    va_list ap;
    int n;
    if (!fmt)
        return;
    va_start(ap, fmt);
    n = vsnprintf(stackbuf, sizeof(stackbuf), fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if ((size_t)n < sizeof(stackbuf)) {
        BeaconFormatAppend(p, stackbuf, n);
    } else {
        char *heapbuf = (char *)malloc((size_t)n + 1);
        if (heapbuf) {
            va_start(ap, fmt);
            vsnprintf(heapbuf, (size_t)n + 1, fmt, ap);
            va_end(ap);
            BeaconFormatAppend(p, heapbuf, n);
            free(heapbuf);
        }
    }
}

char *BeaconFormatToString(formatp_t *p, int *size) {
    formatbuf_t *f;
    beacon_run_t *r = g_run;
    char *copy = NULL;
    char **grown;
    run_lock(r);
    f = format_lookup(p);
    if (f) {
        copy = (char *)malloc(f->len + 1);
        if (copy) {
            memcpy(copy, f->data ? f->data : "", f->len);
            copy[f->len] = 0;
            grown = (char **)realloc(f->owned, (f->nowned + 1) * sizeof(*grown));
            if (grown) {
                f->owned = grown;
                f->owned[f->nowned++] = copy;
            } else {
                free(copy);
                copy = NULL;
            }
        }
        if (size)
            *size = (int)f->len;
    } else if (size) {
        *size = 0;
    }
    run_unlock(r);
    return copy;
}

void BeaconFormatInt(formatp_t *p, int value) {
    unsigned char b[4];
    b[0] = (unsigned char)value;
    b[1] = (unsigned char)(value >> 8);
    b[2] = (unsigned char)(value >> 16);
    b[3] = (unsigned char)(value >> 24);
    BeaconFormatAppend(p, (char *)b, 4);
}

BOOL BeaconGetSpawnTo(BOOL x86, char *buffer, int length) {
    const char *path = x86 ? "C:\\Windows\\SysWOW64\\rundll32.exe"
                           : "C:\\Windows\\System32\\rundll32.exe";
    size_t n;
    if (!buffer || length <= 0)
        return FALSE;
    n = strlen(path);
    if (n + 1 > (size_t)length)
        n = (size_t)length - 1;
    memcpy(buffer, path, n);
    buffer[n] = 0;
    return TRUE;
}

unsigned long long BeaconInformation(int info) {
    (void)info;
    return 0;
}

void BeaconUseToken(HANDLE token) {
    (void)token;
}

BOOL BeaconInjectProcess(HANDLE hProc, int pid, char *payload, int payload_len,
                         int offset, char *args, int args_len) {
    (void)hProc;
    (void)pid;
    (void)payload;
    (void)payload_len;
    (void)offset;
    (void)args;
    (void)args_len;
    return FALSE;
}

BOOL BeaconInjectTemporaryProcess(char *proc, char *args, char *payload,
                                  int payload_len, int offset, char *arg_data,
                                  int arg_len) {
    (void)proc;
    (void)args;
    (void)payload;
    (void)payload_len;
    (void)offset;
    (void)arg_data;
    (void)arg_len;
    return FALSE;
}

BOOL BeaconSpawnTemporaryProcess(BOOL x86, BOOL ignore_token, STARTUPINFOA *si,
                                 PROCESS_INFORMATION *pi) {
    (void)x86;
    (void)ignore_token;
    (void)si;
    (void)pi;
    return FALSE;
}

void BeaconCleanupProcess(BOOL original, BOOL ignore_token, STARTUPINFOA *si,
                          PROCESS_INFORMATION *pi) {
    (void)original;
    (void)ignore_token;
    (void)si;
    (void)pi;
}

/* --- Win32 import search (ntdll exports the CRT memory routines BOF
 * compilers emit calls to, e.g. memcpy/memset) --- */

static const char *import_modules[] = {
    "kernel32.dll", "ntdll.dll",     "advapi32.dll", "user32.dll",
    "ws2_32.dll",   "winhttp.dll",   "iphlpapi.dll", "shell32.dll",
    "ole32.dll",    "oleaut32.dll",  "crypt32.dll",  "netapi32.dll",
    "secur32.dll",  "wtsapi32.dll",  "psapi.dll",    "version.dll",
    NULL,
};

static FARPROC win32_address(const char *name) {
    int i;
    for (i = 0; import_modules[i]; i++) {
        HMODULE mod = GetModuleHandleA(import_modules[i]);
        FARPROC addr;
        if (!mod)
            mod = LoadLibraryA(import_modules[i]);
        if (!mod)
            continue;
        addr = GetProcAddress(mod, name);
        if (addr)
            return addr;
    }
    return NULL;
}

typedef struct {
    const char *name;
    FARPROC addr;
} beacon_import_t;

static beacon_import_t beacon_imports[] = {
    {"BeaconPrintf", (FARPROC)BeaconPrintf},
    {"BeaconOutput", (FARPROC)BeaconOutput},
    {"BeaconGetValue", (FARPROC)BeaconGetValue},
    {"BeaconDataParse", (FARPROC)BeaconDataParse},
    {"BeaconDataInt", (FARPROC)BeaconDataInt},
    {"BeaconDataShort", (FARPROC)BeaconDataShort},
    {"BeaconDataExtract", (FARPROC)BeaconDataExtract},
    {"BeaconDataLength", (FARPROC)BeaconDataLength},
    {"BeaconFormatAlloc", (FARPROC)BeaconFormatAlloc},
    {"BeaconFormatReset", (FARPROC)BeaconFormatReset},
    {"BeaconFormatFree", (FARPROC)BeaconFormatFree},
    {"BeaconFormatAppend", (FARPROC)BeaconFormatAppend},
    {"BeaconFormatPrintf", (FARPROC)BeaconFormatPrintf},
    {"BeaconFormatToString", (FARPROC)BeaconFormatToString},
    {"BeaconFormatInt", (FARPROC)BeaconFormatInt},
    {"BeaconIsAdmin", (FARPROC)BeaconIsAdmin},
    {"BeaconGetSpawnTo", (FARPROC)BeaconGetSpawnTo},
    {"BeaconInformation", (FARPROC)BeaconInformation},
    {"BeaconUseToken", (FARPROC)BeaconUseToken},
    {"BeaconInjectProcess", (FARPROC)BeaconInjectProcess},
    {"BeaconInjectTemporaryProcess", (FARPROC)BeaconInjectTemporaryProcess},
    {"BeaconSpawnTemporaryProcess", (FARPROC)BeaconSpawnTemporaryProcess},
    {"BeaconCleanupProcess", (FARPROC)BeaconCleanupProcess},
    {NULL, NULL},
};

static FARPROC beacon_address(const char *name) {
    int i;
    for (i = 0; beacon_imports[i].name; i++) {
        if (strcmp(beacon_imports[i].name, name) == 0)
            return beacon_imports[i].addr;
    }
    return NULL;
}

/* --- COFF parsing --- */

typedef struct {
    unsigned off;
    unsigned sym;
    unsigned short type;
} reloc_t;

typedef struct {
    char name[64];
    const unsigned char *data;
    size_t datalen;
    unsigned flags;
    reloc_t *relocs;
    size_t nrelocs;
    int mapped;
} section_t;

typedef struct {
    char name[128];
    unsigned value;
    int section; /* 1-based, 0 = undefined import */
} symbol_t;

static unsigned rd16(const unsigned char *p) {
    return (unsigned)p[0] | ((unsigned)p[1] << 8);
}

static unsigned rd32(const unsigned char *p) {
    return (unsigned)p[0] | ((unsigned)p[1] << 8) | ((unsigned)p[2] << 16) |
           ((unsigned)p[3] << 24);
}

static void wr32(unsigned char *p, unsigned v) {
    p[0] = (unsigned char)v;
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

static void wr64(unsigned char *p, unsigned long long v) {
    wr32(p, (unsigned)v);
    wr32(p + 4, (unsigned)(v >> 32));
}

static int coff_skip_section(const char *name) {
    static const char *skip[] = {".pdata", ".xdata", ".drectve",
                                 ".llvm_addrsig", ".sxdata", ".reloc",
                                 ".rsrc", ".edata", ".idata", ".tls", NULL};
    int i;
    if (strncmp(name, ".debug", 6) == 0)
        return 1;
    for (i = 0; skip[i]; i++) {
        if (strcmp(name, skip[i]) == 0)
            return 1;
    }
    return 0;
}

/* Copy a string-table entry (offsets count from the table base, whose
 * first 4 bytes are the size) into name. */
static int table_string(const unsigned char *obj, size_t objlen,
                        unsigned symptr, unsigned nsym, unsigned off,
                        char *name, size_t namecap) {
    unsigned strtab, tabsize, start, end;
    if (namecap == 0)
        return -1;
    name[0] = 0;
    strtab = symptr + nsym * 18;
    if (strtab + 4 > objlen)
        return -1;
    tabsize = rd32(obj + strtab);
    if (strtab + tabsize > objlen)
        return -1;
    start = strtab + off;
    if (off < 4 || start >= strtab + tabsize)
        return -1;
    end = start;
    while (end < strtab + tabsize && obj[end])
        end++;
    if (end >= strtab + tabsize)
        return -1;
    if (end - start >= namecap)
        return -1;
    memcpy(name, obj + start, end - start);
    name[end - start] = 0;
    return 0;
}

static int section_name(const unsigned char *raw, const unsigned char *obj,
                        size_t objlen, unsigned symptr, unsigned nsym,
                        char *name, size_t namecap) {
    unsigned off = 0;
    int i;
    if (namecap == 0)
        return -1;
    name[0] = 0;
    if (raw[0] == '/') {
        for (i = 1; i < 8 && raw[i]; i++) {
            if (raw[i] < '0' || raw[i] > '9')
                return -1;
            off = off * 10 + (unsigned)(raw[i] - '0');
        }
        return table_string(obj, objlen, symptr, nsym, off, name, namecap);
    }
    for (i = 0; i < 8 && raw[i]; i++) {
        if ((size_t)i + 1 >= namecap)
            return -1;
        name[i] = (char)raw[i];
    }
    name[i] = 0;
    return 0;
}

static int symbol_name(const unsigned char *raw, const unsigned char *obj,
                       size_t objlen, unsigned symptr, unsigned nsym,
                       char *name, size_t namecap) {
    int i;
    if (namecap == 0)
        return -1;
    name[0] = 0;
    if (raw[0] == 0 && raw[1] == 0 && raw[2] == 0 && raw[3] == 0)
        return table_string(obj, objlen, symptr, nsym, rd32(raw + 4), name,
                            namecap);
    for (i = 0; i < 8 && raw[i]; i++) {
        if ((size_t)i + 1 >= namecap)
            return -1;
        name[i] = (char)raw[i];
    }
    name[i] = 0;
    return 0;
}

static void free_sections(section_t *secs, size_t nsec) {
    size_t i;
    if (!secs)
        return;
    for (i = 0; i < nsec; i++)
        free(secs[i].relocs);
    free(secs);
}

static char *failf(const char *fmt, ...) {
    char buf[512];
    va_list ap;
    char *out;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    out = _strdup(buf);
    return out ? out : _strdup("error: out of memory");
}

/* One import thunk: jmp [rip+0] plus the absolute target. */
#define THUNK_SIZE 14

static void write_thunk(unsigned char *dst, unsigned long long target) {
    dst[0] = 0xFF;
    dst[1] = 0x25;
    dst[2] = dst[3] = dst[4] = dst[5] = 0;
    wr64(dst + 6, target);
}

typedef void(__cdecl *bof_entry_t)(char *args, int len);

typedef struct {
    bof_entry_t entry;
    unsigned char *args;
    int argslen;
} bof_thread_param_t;

static DWORD WINAPI bof_thread_proc(LPVOID p) {
    bof_thread_param_t *tp = (bof_thread_param_t *)p;
    tp->entry((char *)tp->args, tp->argslen);
    return 0;
}

int coff_run(const unsigned char *obj, size_t objlen, const char *entry,
             const unsigned char *args, size_t argslen, int timeout_sec,
             char **out) {
    unsigned nsec, symptr, nsym, i;
    section_t *secs = NULL;
    symbol_t *syms = NULL;
    unsigned char *mem = NULL;
    size_t *bases = NULL;
    size_t size = 0, args_off = 0, thunk_base = 0, code_end = 0;
    char **imports = NULL;
    size_t nimports = 0;
    unsigned long long *thunks = NULL;
    bof_entry_t entry_addr = NULL;
    bof_thread_param_t *tp = NULL;
    beacon_run_t *run = NULL;
    HANDLE thread = NULL;
    DWORD wait;
    char *result = NULL;
    int rc = -1;

    *out = NULL;
    if (!obj || objlen < 20) {
        *out = failf("error: bad coff: truncated header");
        return -1;
    }
    if (rd16(obj) != COFF_MACHINE_AMD64) {
        *out = failf("error: bad coff: machine 0x%04x (x64 only)", rd16(obj));
        return -1;
    }
    nsec = rd16(obj + 2);
    symptr = rd32(obj + 8);
    nsym = rd32(obj + 12);
    if (rd16(obj + 16) != 0) {
        *out = failf("error: bad coff: optional header present (not an object)");
        return -1;
    }
    if (nsec == 0 || nsec > MAX_SECTIONS || nsym > MAX_SYMBOLS) {
        *out = failf("error: bad coff: %u sections %u symbols", nsec, nsym);
        return -1;
    }
    secs = (section_t *)calloc(nsec, sizeof(*secs));
    syms = (symbol_t *)calloc(nsym ? nsym : 1, sizeof(*syms));
    if (!secs || !syms) {
        *out = failf("error: out of memory");
        goto done;
    }
    for (i = 0; i < nsec; i++) {
        size_t off = 20 + (size_t)i * 40;
        const unsigned char *hdr;
        unsigned rawsize, rawptr, relptr, nrel, r;
        if (off + 40 > objlen) {
            *out = failf("error: bad coff: truncated section header %u", i);
            goto done;
        }
        hdr = obj + off;
        if (section_name(hdr, obj, objlen, symptr, nsym, secs[i].name,
                         sizeof(secs[i].name)) != 0 ||
            secs[i].name[0] == 0) {
            *out = failf("error: bad coff: bad section name %u", i);
            goto done;
        }
        rawsize = rd32(hdr + 16);
        rawptr = rd32(hdr + 20);
        relptr = rd32(hdr + 24);
        nrel = rd16(hdr + 32);
        secs[i].flags = rd32(hdr + 36);
        secs[i].mapped = (secs[i].flags & (SCN_CNT_CODE | SCN_CNT_IDATA | SCN_CNT_UDATA)) != 0 &&
                         !coff_skip_section(secs[i].name);
        if (rawsize > 0) {
            if ((size_t)rawptr + rawsize > objlen) {
                *out = failf("error: bad coff: section %s raw data out of range", secs[i].name);
                goto done;
            }
            secs[i].data = obj + rawptr;
            secs[i].datalen = rawsize;
        } else if (secs[i].flags & SCN_CNT_UDATA) {
            /* .bss carries no raw bytes; loader zeroes it at map time. */
            secs[i].data = NULL;
            secs[i].datalen = rd32(hdr + 8);
            if (secs[i].datalen > MAX_COFF_BYTES) {
                *out = failf("error: bad coff: section %s bss too large", secs[i].name);
                goto done;
            }
        }
        if (nrel > 0) {
            secs[i].relocs = (reloc_t *)calloc(nrel, sizeof(reloc_t));
            if (!secs[i].relocs) {
                *out = failf("error: out of memory");
                goto done;
            }
            for (r = 0; r < nrel; r++) {
                size_t roff = (size_t)relptr + (size_t)r * 10;
                if (roff + 10 > objlen) {
                    *out = failf("error: bad coff: section %s truncated relocations", secs[i].name);
                    goto done;
                }
                secs[i].relocs[r].off = rd32(obj + roff);
                secs[i].relocs[r].sym = rd32(obj + roff + 4);
                secs[i].relocs[r].type = (unsigned short)rd16(obj + roff + 8);
            }
            secs[i].nrelocs = nrel;
        }
    }
    /* Symbols keep aux placeholders so indices match relocations. */
    for (i = 0; i < nsym;) {
        size_t off = (size_t)symptr + (size_t)i * 18;
        const unsigned char *rec;
        unsigned aux, a;
        if (off + 18 > objlen) {
            *out = failf("error: bad coff: truncated symbol %u", i);
            goto done;
        }
        rec = obj + off;
        if (symbol_name(rec, obj, objlen, symptr, nsym, syms[i].name,
                        sizeof(syms[i].name)) != 0 ||
            syms[i].name[0] == 0) {
            *out = failf("error: bad coff: bad symbol name %u", i);
            goto done;
        }
        syms[i].value = rd32(rec + 8);
        syms[i].section = (int)(short)rd16(rec + 12);
        aux = rec[17];
        for (a = 0; a < aux && i + 1 + a < nsym; a++)
            syms[i + 1 + a].name[0] = 0;
        i += 1 + aux;
    }
    /* Distinct undefined imports referenced by mapped relocations. */
    for (i = 0; i < nsec; i++) {
        size_t r;
        if (!secs[i].mapped)
            continue;
        for (r = 0; r < secs[i].nrelocs; r++) {
            unsigned s = secs[i].relocs[r].sym;
            size_t k;
            int seen = 0;
            if (s >= nsym) {
                *out = failf("error: bad coff: section %s bad reloc symbol %u", secs[i].name, s);
                goto done;
            }
            if (syms[s].section != 0 || syms[s].name[0] == 0)
                continue;
            for (k = 0; k < nimports; k++) {
                if (strcmp(imports[k], syms[s].name) == 0) {
                    seen = 1;
                    break;
                }
            }
            if (!seen) {
                char **grown = (char **)realloc(imports, (nimports + 1) * sizeof(*grown));
                if (!grown) {
                    *out = failf("error: out of memory");
                    goto done;
                }
                imports = grown;
                imports[nimports] = _strdup(syms[s].name);
                if (!imports[nimports]) {
                    *out = failf("error: out of memory");
                    goto done;
                }
                nimports++;
            }
        }
    }
    thunks = (unsigned long long *)calloc(nimports ? nimports : 1, sizeof(*thunks));
    if (!thunks) {
        *out = failf("error: out of memory");
        goto done;
    }
    for (i = 0; i < nimports; i++) {
        FARPROC addr = beacon_address(imports[i]);
        if (!addr)
            addr = win32_address(imports[i]);
        if (!addr) {
            *out = failf("error: coff: unresolved import %s", imports[i]);
            goto done;
        }
        thunks[i] = (unsigned long long)(uintptr_t)addr;
    }
    bases = (size_t *)calloc(nsec, sizeof(*bases));
    if (!bases) {
        *out = failf("error: out of memory");
        goto done;
    }
    /* Code pages first, then data plus args, then the thunk tail on its
     * own pages (REL32 range + RX/Data page separation). */
    for (i = 0; i < nsec; i++) {
        if (!secs[i].mapped || !(secs[i].flags & SCN_CNT_CODE))
            continue;
        size = (size + 31) & ~(size_t)31;
        bases[i] = size;
        size += secs[i].datalen;
    }
    code_end = (size + 0xFFF) & ~(size_t)0xFFF;
    size = code_end;
    for (i = 0; i < nsec; i++) {
        if (!secs[i].mapped || (secs[i].flags & SCN_CNT_CODE))
            continue;
        size = (size + 31) & ~(size_t)31;
        bases[i] = size;
        size += secs[i].datalen;
    }
    size = (size + 7) & ~(size_t)7;
    args_off = size;
    size += argslen;
    thunk_base = (size + 0xFFF) & ~(size_t)0xFFF;
    size = thunk_base + nimports * THUNK_SIZE;
    if (size == 0) {
        *out = failf("error: coff: nothing to map");
        goto done;
    }
    mem = (unsigned char *)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        *out = failf("error: coff: VirtualAlloc failed");
        goto done;
    }
    for (i = 0; i < nsec; i++) {
        if (!secs[i].mapped || secs[i].datalen == 0)
            continue;
        if (secs[i].data)
            memcpy(mem + bases[i], secs[i].data, secs[i].datalen);
        else
            memset(mem + bases[i], 0, secs[i].datalen);
    }
    if (argslen > 0)
        memcpy(mem + args_off, args, argslen);
    for (i = 0; i < nimports; i++)
        write_thunk(mem + thunk_base + i * THUNK_SIZE, thunks[i]);
    /* Relocate. */
    for (i = 0; i < nsec; i++) {
        size_t r;
        if (!secs[i].mapped)
            continue;
        for (r = 0; r < secs[i].nrelocs; r++) {
            unsigned s = secs[i].relocs[r].sym;
            unsigned off = secs[i].relocs[r].off;
            unsigned type = secs[i].relocs[r].type;
            unsigned long long target = 0, addend = 0;
            unsigned char *slot;
            size_t k;
            int found = 0;
            if (s >= nsym) {
                *out = failf("error: bad coff: section %s bad reloc symbol %u", secs[i].name, s);
                goto done;
            }
            if (syms[s].section > 0) {
                int sec = syms[s].section;
                if (sec > (int)nsec) {
                    *out = failf("error: coff: symbol %s bad section %d", syms[s].name, sec);
                    goto done;
                }
                if (!secs[sec - 1].mapped) {
                    *out = failf("error: coff: symbol %s in unmapped section %s", syms[s].name,
                                 secs[sec - 1].name);
                    goto done;
                }
                target = (unsigned long long)(uintptr_t)(mem + bases[sec - 1] + syms[s].value);
            } else {
                for (k = 0; k < nimports; k++) {
                    if (strcmp(imports[k], syms[s].name) == 0) {
                        target = (unsigned long long)(uintptr_t)(mem + thunk_base + k * THUNK_SIZE);
                        found = 1;
                        break;
                    }
                }
                if (!found) {
                    *out = failf("error: coff: unresolved import %s", syms[s].name);
                    goto done;
                }
            }
            slot = mem + bases[i] + off;
            switch (type) {
            case REL_AMD64_ADDR64:
                if ((size_t)off + 8 > secs[i].datalen) {
                    *out = failf("error: coff: section %s reloc out of range", secs[i].name);
                    goto done;
                }
                addend = ((unsigned long long)rd32(slot + 4) << 32) | rd32(slot);
                wr64(slot, target + addend);
                break;
            case REL_AMD64_ADDR32NB:
                if ((size_t)off + 4 > secs[i].datalen) {
                    *out = failf("error: coff: section %s reloc out of range", secs[i].name);
                    goto done;
                }
                addend = rd32(slot);
                wr32(slot, (unsigned)((target - (unsigned long long)(uintptr_t)mem) + addend));
                break;
            case REL_AMD64_REL32:
                if ((size_t)off + 4 > secs[i].datalen) {
                    *out = failf("error: coff: section %s reloc out of range", secs[i].name);
                    goto done;
                }
                addend = rd32(slot);
                wr32(slot, (unsigned)(target + addend - (unsigned long long)(uintptr_t)(slot + 4)));
                break;
            default:
                *out = failf("error: coff: section %s unsupported reloc type %u", secs[i].name, type);
                goto done;
            }
        }
    }
    {
        DWORD old;
        if (code_end > 0 &&
            !VirtualProtect(mem, code_end, PAGE_EXECUTE_READ, &old)) {
            *out = failf("error: coff: VirtualProtect failed");
            goto done;
        }
        if (size > thunk_base &&
            !VirtualProtect(mem + thunk_base, size - thunk_base, PAGE_EXECUTE_READ, &old)) {
            *out = failf("error: coff: VirtualProtect failed");
            goto done;
        }
    }
    for (i = 0; i < nsym; i++) {
        if (syms[i].name[0] && strcmp(syms[i].name, entry) == 0 && syms[i].section > 0) {
            int sec = syms[i].section;
            if (sec > (int)nsec || !secs[sec - 1].mapped) {
                *out = failf("error: coff: entrypoint %s in unmapped section", entry);
                goto done;
            }
            entry_addr = (bof_entry_t)(mem + bases[sec - 1] + syms[i].value);
            break;
        }
    }
    if (!entry_addr) {
        *out = failf("error: coff: entrypoint \"%s\" not found", entry);
        goto done;
    }
    run = (beacon_run_t *)calloc(1, sizeof(*run));
    tp = (bof_thread_param_t *)malloc(sizeof(*tp));
    if (!run || !tp) {
        *out = failf("error: out of memory");
        goto done;
    }
    InitializeCriticalSection(&run->lock);
    run->out = _strdup("");
    if (!run->out) {
        *out = failf("error: out of memory");
        goto done;
    }
    tp->entry = entry_addr;
    tp->args = mem + args_off;
    tp->argslen = (int)argslen;
    g_run = run;
    thread = CreateThread(NULL, 0, bof_thread_proc, tp, 0, NULL);
    if (!thread) {
        g_run = NULL;
        *out = failf("error: coff: CreateThread failed");
        goto done;
    }
    if (timeout_sec < 1)
        timeout_sec = 1;
    wait = WaitForSingleObject(thread, (DWORD)timeout_sec * 1000);
    CloseHandle(thread);
    thread = NULL;
    g_run = NULL;
    if (wait == WAIT_TIMEOUT) {
        /* The BOF thread keeps running detached; freeing the image,
         * run or params underneath it would crash the agent, so leak
         * them instead. */
        mem = NULL;
        run = NULL;
        tp = NULL;
        *out = failf("error: bof timed out after %ds", timeout_sec);
        goto done;
    }
    if (wait != WAIT_OBJECT_0) {
        *out = failf("error: coff: thread wait failed (%lu)", (unsigned long)wait);
        goto done;
    }
    result = run->out ? run->out : _strdup("");
    run->out = NULL;
    *out = result ? result : _strdup("");
    if (!*out)
        *out = failf("error: out of memory");
    else
        rc = 0;

done:
    if (thread)
        CloseHandle(thread);
    if (run) {
        size_t k;
        for (k = 0; k < run->nformats; k++) {
            format_free_owned(run->formats[k]);
            free(run->formats[k]->data);
            free(run->formats[k]);
        }
        free(run->formats);
        free(run->out);
        DeleteCriticalSection(&run->lock);
        free(run);
    }
    free(tp);
    if (mem)
        VirtualFree(mem, 0, MEM_RELEASE);
    free(bases);
    free(thunks);
    if (imports) {
        for (i = 0; i < nimports; i++)
            free(imports[i]);
        free(imports);
    }
    free_sections(secs, nsec);
    free(syms);
    return rc;
}
