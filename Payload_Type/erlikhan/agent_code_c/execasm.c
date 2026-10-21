/* In-process .NET execution via CLR hosting. The assembly is staged to
 * a temp path by the caller, loaded through mscoree into the default
 * AppDomain, and executed with stdout/stderr redirected to pipes that
 * drain on worker threads. COM hosting interfaces are declared manually
 * (mingw lacks mscoree.h); SAFEARRAY/BSTR/VARIANT come from oleauto.h.
 *
 * Known limit (same as the Go agent): .NET caches the Console writer
 * per process, so output capture is reliable for the first execution in
 * a callback; later runs may lose Console output.
 */
#include "execasm.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <windows.h>
#include <objbase.h>
#include <oleauto.h>
#include <shellapi.h>

#define MAX_ASM_OUTPUT (4u * 1024u * 1024u)

/* --- Hosting interfaces (only the vtable prefix each use needs) --- */

typedef struct {
    HRESULT(STDMETHODCALLTYPE *QueryInterface)
    (void *self, REFIID riid, void **out);
    ULONG(STDMETHODCALLTYPE *AddRef)(void *self);
    ULONG(STDMETHODCALLTYPE *Release)(void *self);
    HRESULT(STDMETHODCALLTYPE *GetRuntime)
    (void *self, LPCWSTR version, REFIID riid, LPVOID *out);
} ICLRMetaHostVtbl;

typedef struct {
    const ICLRMetaHostVtbl *lpVtbl;
} ICLRMetaHost;

typedef struct {
    HRESULT(STDMETHODCALLTYPE *QueryInterface)
    (void *self, REFIID riid, void **out);
    ULONG(STDMETHODCALLTYPE *AddRef)(void *self);
    ULONG(STDMETHODCALLTYPE *Release)(void *self);
    void *m3, *m4, *m5, *m6, *m7, *m8; /* version/dir/load* helpers */
    HRESULT(STDMETHODCALLTYPE *GetInterface)
    (void *self, REFCLSID clsid, REFIID riid, LPVOID *out);
} ICLRRuntimeInfoVtbl;

typedef struct {
    const ICLRRuntimeInfoVtbl *lpVtbl;
} ICLRRuntimeInfo;

typedef struct {
    HRESULT(STDMETHODCALLTYPE *QueryInterface)
    (void *self, REFIID riid, void **out);
    ULONG(STDMETHODCALLTYPE *AddRef)(void *self);
    ULONG(STDMETHODCALLTYPE *Release)(void *self);
    void *m3, *m4, *m5, *m6, *m7, *m8, *m9; /* thread-state/config */
    HRESULT(STDMETHODCALLTYPE *Start)(void *self);
    void *m11, *m12; /* Stop, CreateDomain */
    HRESULT(STDMETHODCALLTYPE *GetDefaultDomain)
    (void *self, IUnknown **domain);
} ICorRuntimeHostVtbl;

typedef struct {
    const ICorRuntimeHostVtbl *lpVtbl;
} ICorRuntimeHost;

typedef HRESULT(STDAPICALLTYPE *CLRCreateInstance_t)(REFCLSID clsid,
                                                     REFIID riid,
                                                     LPVOID *out);

static const GUID CLSID_CLRMetaHost = {
    0x9280188D, 0x0E8E, 0x4867, {0xB3, 0x0C, 0x7F, 0x86, 0xA9, 0xE8, 0x94, 0x6E}};
static const GUID IID_ICLRMetaHost = {
    0xD332DB9E, 0xB9B3, 0x4125, {0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x96}};
static const GUID IID_ICLRRuntimeInfo = {
    0xBD39D1D2, 0xBA2F, 0x486A, {0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x62, 0x91}};
static const GUID CLSID_CorRuntimeHost = {
    0xCB2F6723, 0xAB3A, 0x11D2, {0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E}};
static const GUID IID_ICorRuntimeHost = {
    0xCB2F6722, 0xAB3A, 0x11D2, {0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E}};

static void com_release(void *obj) {
    if (obj) {
        IUnknown *u = (IUnknown *)obj;
        u->lpVtbl->Release(u);
    }
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

static char *failh(const char *stage, HRESULT hr) {
    return failf("error: clr: %s: HRESULT 0x%08lx", stage, (unsigned long)hr);
}

/* --- Pipe capture: one drain thread per redirected handle --- */

typedef struct {
    HANDLE read;
    char *buf;
    size_t len;
    size_t cap;
} drain_t;

static DWORD WINAPI drain_proc(LPVOID p) {
    drain_t *d = (drain_t *)p;
    char chunk[8192];
    DWORD n;
    while (ReadFile(d->read, chunk, sizeof(chunk), &n, NULL) && n > 0) {
        size_t room;
        char *grown;
        if (d->len >= MAX_ASM_OUTPUT)
            continue;
        room = MAX_ASM_OUTPUT - d->len;
        if (n > room)
            n = (DWORD)room;
        if (d->len + n + 1 > d->cap) {
            grown = (char *)realloc(d->buf, d->len + n + 1);
            if (!grown)
                continue;
            d->buf = grown;
            d->cap = d->len + n + 1;
        }
        memcpy(d->buf + d->len, chunk, n);
        d->len += n;
        d->buf[d->len] = 0;
    }
    return 0;
}

/* --- IDispatch invoke helper --- */

static HRESULT disp_invoke(IDispatch *disp, DISPID id, VARIANTARG *args,
                           unsigned nargs) {
    VARIANTARG *rev;
    DISPPARAMS dp;
    VARIANT result;
    HRESULT hr;
    unsigned i;
    rev = (VARIANTARG *)malloc(nargs * sizeof(*rev));
    if (nargs > 0 && !rev)
        return E_OUTOFMEMORY;
    for (i = 0; i < nargs; i++)
        rev[i] = args[nargs - 1 - i]; /* COM takes args last-to-first */
    dp.rgvarg = rev;
    dp.rgdispidNamedArgs = NULL;
    dp.cArgs = nargs;
    dp.cNamedArgs = 0;
    VariantInit(&result);
    hr = disp->lpVtbl->Invoke(disp, id, &GUID_NULL, LOCALE_USER_DEFAULT,
                              DISPATCH_METHOD, &dp, &result, NULL, NULL);
    VariantClear(&result);
    free(rev);
    return hr;
}

int execasm_run(const char *path, const char *argstring, char **out) {
    HMODULE mscoree = NULL;
    CLRCreateInstance_t create_instance = NULL;
    ICLRMetaHost *meta = NULL;
    ICLRRuntimeInfo *rtinfo = NULL;
    ICorRuntimeHost *host = NULL;
    IUnknown *domain = NULL;
    IDispatch *disp = NULL;
    HRESULT hr;
    int initialized = 0;
    wchar_t *wide_args = NULL;
    wchar_t **argv = NULL;
    int argc = 0;
    BSTR path_bstr = NULL;
    SAFEARRAY *arg_array = NULL;
    DISPID dispid = 0;
    HANDLE old_out = NULL, old_err = NULL;
    HANDLE out_read = NULL, out_write = NULL, err_read = NULL, err_write = NULL;
    HANDLE out_thread = NULL, err_thread = NULL;
    int redirected = 0;
    drain_t out_cap = {0}, err_cap = {0};
    VARIANTARG vpath, vempty, vargs, callargs[3];
    char *result = NULL;
    int rc = -1;

    *out = NULL;
    if (!path || !*path) {
        *out = failf("error: no assembly path");
        return -1;
    }
    mscoree = LoadLibraryA("mscoree.dll");
    if (!mscoree) {
        *out = failf("error: clr: mscoree.dll unavailable");
        return -1;
    }
    create_instance =
        (CLRCreateInstance_t)(void *)GetProcAddress(mscoree, "CLRCreateInstance");
    if (!create_instance) {
        *out = failf("error: clr: CLRCreateInstance missing");
        goto done;
    }
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (SUCCEEDED(hr)) {
        initialized = 1;
    } else if (hr != RPC_E_CHANGED_MODE) {
        *out = failh("CoInitializeEx", hr);
        goto done;
    }
    hr = create_instance(&CLSID_CLRMetaHost, &IID_ICLRMetaHost, (LPVOID *)&meta);
    if (FAILED(hr)) {
        *out = failh("CLRCreateInstance", hr);
        goto done;
    }
    hr = meta->lpVtbl->GetRuntime(meta, L"v4.0.30319", &IID_ICLRRuntimeInfo,
                                  (LPVOID *)&rtinfo);
    if (FAILED(hr)) {
        *out = failh("GetRuntime(v4.0.30319)", hr);
        goto done;
    }
    hr = rtinfo->lpVtbl->GetInterface(rtinfo, &CLSID_CorRuntimeHost,
                                      &IID_ICorRuntimeHost, (LPVOID *)&host);
    if (FAILED(hr)) {
        *out = failh("GetInterface(CorRuntimeHost)", hr);
        goto done;
    }
    hr = host->lpVtbl->Start(host);
    if (FAILED(hr)) {
        *out = failh("CorRuntimeHost.Start", hr);
        goto done;
    }
    hr = host->lpVtbl->GetDefaultDomain(host, &domain);
    if (FAILED(hr)) {
        *out = failh("GetDefaultDomain", hr);
        goto done;
    }
    hr = domain->lpVtbl->QueryInterface(domain, &IID_IDispatch, (void **)&disp);
    if (FAILED(hr)) {
        *out = failh("AppDomain IDispatch", hr);
        goto done;
    }
    {
        LPOLESTR names[1] = {L"ExecuteAssembly"};
        hr = disp->lpVtbl->GetIDsOfNames(disp, &GUID_NULL, names, 1,
                                         LOCALE_USER_DEFAULT, &dispid);
        if (FAILED(hr)) {
            *out = failh("ExecuteAssembly dispid", hr);
            goto done;
        }
    }
    {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, path, -1, NULL, 0);
        wchar_t *wpath = (wchar_t *)malloc((size_t)wlen * sizeof(*wpath));
        if (!wpath) {
            *out = failf("error: out of memory");
            goto done;
        }
        MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, wlen);
        path_bstr = SysAllocString(wpath);
        free(wpath);
        if (!path_bstr) {
            *out = failf("error: clr: SysAllocString failed");
            goto done;
        }
    }
    if (argstring && *argstring) {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, argstring, -1, NULL, 0);
        int i;
        wide_args = (wchar_t *)malloc((size_t)wlen * sizeof(*wide_args));
        if (!wide_args) {
            *out = failf("error: out of memory");
            goto done;
        }
        MultiByteToWideChar(CP_UTF8, 0, argstring, -1, wide_args, wlen);
        argv = CommandLineToArgvW(wide_args, &argc);
        if (!argv) {
            *out = failf("error: clr: CommandLineToArgvW failed");
            goto done;
        }
        arg_array = SafeArrayCreateVector(VT_BSTR, 0, (ULONG)argc);
        if (!arg_array) {
            *out = failf("error: clr: SafeArrayCreateVector failed");
            goto done;
        }
        for (i = 0; i < argc; i++) {
            BSTR element = SysAllocString(argv[i]);
            LONG idx = i;
            if (!element) {
                *out = failf("error: clr: SysAllocString failed");
                goto done;
            }
            hr = SafeArrayPutElement(arg_array, &idx, element);
            SysFreeString(element); /* PutElement copies BSTRs. */
            if (FAILED(hr)) {
                *out = failh("SafeArrayPutElement", hr);
                goto done;
            }
        }
    }
    old_out = GetStdHandle(STD_OUTPUT_HANDLE);
    old_err = GetStdHandle(STD_ERROR_HANDLE);
    if (!CreatePipe(&out_read, &out_write, NULL, 0) ||
        !CreatePipe(&err_read, &err_write, NULL, 0)) {
        *out = failf("error: clr: CreatePipe failed");
        goto done;
    }
    if (!SetStdHandle(STD_OUTPUT_HANDLE, out_write) ||
        !SetStdHandle(STD_ERROR_HANDLE, err_write)) {
        *out = failf("error: clr: SetStdHandle failed");
        goto done;
    }
    redirected = 1;
    out_cap.buf = _strdup("");
    err_cap.buf = _strdup("");
    if (!out_cap.buf || !err_cap.buf) {
        *out = failf("error: out of memory");
        goto done;
    }
    out_cap.read = out_read;
    err_cap.read = err_read;
    out_thread = CreateThread(NULL, 0, drain_proc, &out_cap, 0, NULL);
    err_thread = CreateThread(NULL, 0, drain_proc, &err_cap, 0, NULL);
    if (!out_thread || !err_thread) {
        *out = failf("error: clr: drain thread failed");
        goto done;
    }
    VariantInit(&vpath);
    VariantInit(&vempty);
    VariantInit(&vargs);
    vpath.vt = VT_BSTR;
    vpath.bstrVal = path_bstr;
    vargs.vt = VT_ARRAY | VT_BSTR;
    vargs.parray = arg_array;
    /* ExecuteAssembly is overloaded and IDispatch resolves one dispid for
     * the name, so probe arities from most to least specific. A failed
     * Invoke has no side effects, so the first success wins. */
    if (arg_array) {
        callargs[0] = vpath;
        callargs[1] = vempty;
        callargs[2] = vargs;
        hr = disp_invoke(disp, dispid, callargs, 3);
        if (FAILED(hr)) {
            callargs[0] = vpath;
            callargs[1] = vempty;
            hr = disp_invoke(disp, dispid, callargs, 2);
        }
        if (FAILED(hr)) {
            callargs[0] = vpath;
            hr = disp_invoke(disp, dispid, callargs, 1);
        }
    } else {
        callargs[0] = vpath;
        hr = disp_invoke(disp, dispid, callargs, 1);
    }
    CloseHandle(out_write);
    out_write = NULL;
    CloseHandle(err_write);
    err_write = NULL;
    {
        HANDLE threads[2] = {out_thread, err_thread};
        WaitForMultipleObjects(2, threads, TRUE, INFINITE);
    }
    SetStdHandle(STD_OUTPUT_HANDLE, old_out);
    SetStdHandle(STD_ERROR_HANDLE, old_err);
    CloseHandle(out_read);
    out_read = NULL;
    CloseHandle(err_read);
    err_read = NULL;
    if (FAILED(hr)) {
        *out = failh("ExecuteAssembly invoke", hr);
        goto done;
    }
    if (err_cap.len > 0 && out_cap.len > 0) {
        size_t total = out_cap.len + 1 + err_cap.len + 1;
        result = (char *)malloc(total);
        if (!result) {
            *out = failf("error: out of memory");
            goto done;
        }
        memcpy(result, out_cap.buf, out_cap.len);
        result[out_cap.len] = '\n';
        memcpy(result + out_cap.len + 1, err_cap.buf, err_cap.len);
        result[total - 1] = 0;
    } else if (err_cap.len > 0) {
        result = _strdup(err_cap.buf);
    } else {
        result = _strdup(out_cap.buf ? out_cap.buf : "");
    }
    if (!result) {
        *out = failf("error: out of memory");
        goto done;
    }
    *out = result;
    rc = 0;

done:
    if (out_write)
        CloseHandle(out_write);
    if (err_write)
        CloseHandle(err_write);
    if (out_thread) {
        WaitForSingleObject(out_thread, INFINITE);
        CloseHandle(out_thread);
    }
    if (err_thread) {
        WaitForSingleObject(err_thread, INFINITE);
        CloseHandle(err_thread);
    }
    if (out_read)
        CloseHandle(out_read);
    if (err_read)
        CloseHandle(err_read);
    /* Restoring twice on the success path is harmless (same values). */
    if (redirected) {
        SetStdHandle(STD_OUTPUT_HANDLE, old_out);
        SetStdHandle(STD_ERROR_HANDLE, old_err);
    }
    free(out_cap.buf);
    free(err_cap.buf);
    if (argv)
        LocalFree(argv);
    free(wide_args);
    if (arg_array)
        SafeArrayDestroy(arg_array);
    if (path_bstr)
        SysFreeString(path_bstr);
    com_release(disp);
    com_release(domain);
    com_release(host);
    com_release(rtinfo);
    com_release(meta);
    if (initialized)
        CoUninitialize();
    if (mscoree)
        FreeLibrary(mscoree);
    return rc;
}
