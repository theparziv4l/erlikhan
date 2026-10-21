/* Task dispatch tests. Test-only; never linked into the agent.
 *
 * Both builds must exit 0 under wine (the second exercises the
 * build-time command list exclusion path):
 *
 *   zig cc -target x86_64-windows-gnu tasks_test.c tasks.c mythic.c
 *     config.c crypto.c cJSON.c sock.c mqtt.c dns.c http.c teams.c
 *     sysinfo.c -lbcrypt -lwinhttp -lws2_32 -liphlpapi
 *     -o tasks.exe && wine tasks.exe
 *   zig cc -target x86_64-windows-gnu tasks_test.c tasks.c mythic.c
 *     config.c crypto.c cJSON.c sock.c mqtt.c dns.c http.c teams.c
 *     sysinfo.c -DCFG_COMMANDS="shell,exit" -lbcrypt -lwinhttp -lws2_32
 *     -liphlpapi -o tasks_restricted.exe && wine tasks_restricted.exe
 */
#include "common.h"
#include "config.h"
#include "mythic.h"
#include "tasks.h"
#include <stdio.h>

static int failures = 0;

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        printf("FAIL %s:%d: ", __FILE__, __LINE__); \
        printf(__VA_ARGS__); \
        printf("\n"); \
        failures++; \
    } \
} while (0)

static void test_command_in_list(void) {
    CHECK(command_in_list("", "shell") == 1, "empty list allows all");
    CHECK(command_in_list("shell,exit", "shell") == 1, "first");
    CHECK(command_in_list("shell,exit", "exit") == 1, "last");
    CHECK(command_in_list("shell,exit", "ls") == 0, "missing");
    CHECK(command_in_list("shell,exit", "shel") == 0, "prefix must not match");
    CHECK(command_in_list("shell,exit", "shellx") == 0, "superstring must not match");
    CHECK(command_in_list("shell,exit", "hell") == 0, "substring must not match");
    CHECK(command_in_list("shell, exit", "exit") == 1, "spaces tolerated");
}

static void run_task(agent_t *a, const char *command, const char *parameters,
                     response_t *resp, char **output, int *exit_now) {
    task_t t;
    t.command = (char *)command;
    t.parameters = (char *)parameters;
    t.id = "1";
    memset(resp, 0, sizeof(*resp));
    *output = NULL;
    *exit_now = 0;
    CHECK(task_dispatch(a, &t, resp, output, exit_now) == 0, "dispatch %s returns 0", command);
}

static void test_exit_unknown(agent_t *a) {
    response_t resp;
    char *output = NULL;
    int exit_now = 0;
    run_task(a, "exit", "", &resp, &output, &exit_now);
    CHECK(exit_now == 1, "exit sets exit_now");
    CHECK(resp.user_output && strcmp(resp.user_output, "exiting") == 0, "exit output");
    free(output);
    run_task(a, "rm-rf", "", &resp, &output, &exit_now);
    CHECK(exit_now == 0, "unknown sets no exit");
    CHECK(resp.status && strstr(resp.status, "unknown command") != NULL, "unknown status, got %s",
          resp.status ? resp.status : "(null)");
    free(output);
}

static void test_sleep(agent_t *a) {
    response_t resp;
    char *output = NULL;
    int exit_now = 0;
    run_task(a, "sleep", "5 10", &resp, &output, &exit_now);
    if (command_in_list(CFG_COMMANDS, "sleep")) {
        CHECK(a->interval == 5 && a->jitter == 10, "sleep sets %d/%d", a->interval, a->jitter);
    } else {
        CHECK(resp.status && strstr(resp.status, "not included") != NULL, "sleep excluded");
    }
    free(output);
}

static void test_shell(agent_t *a) {
    response_t resp;
    char *output = NULL;
    int exit_now = 0;
    run_task(a, "shell", "echo hi", &resp, &output, &exit_now);
    CHECK(strcmp(resp.status, "success") == 0, "shell status %s", resp.status);
    CHECK(resp.user_output && strstr(resp.user_output, "hi") != NULL, "shell output");
    free(output);
}

static void test_ls(agent_t *a) {
    response_t resp;
    char *output = NULL;
    int exit_now = 0;
    if (!command_in_list(CFG_COMMANDS, "ls")) {
        run_task(a, "ls", ".", &resp, &output, &exit_now);
        CHECK(resp.status && strstr(resp.status, "not included") != NULL,
              "excluded ls, got %s", resp.status ? resp.status : "(null)");
        free(output);
        return;
    }
    {
        char tmp[MAX_PATH], dir[MAX_PATH], file[MAX_PATH], params[MAX_PATH + 32];
        HANDLE h;
        DWORD n = GetTempPathA(sizeof(tmp), tmp);
        CHECK(n > 0 && n < sizeof(tmp), "temp path");
        snprintf(dir, sizeof(dir), "%serlikhan-ls-test", tmp);
        CreateDirectoryA(dir, NULL);
        snprintf(file, sizeof(file), "%s\\probe.txt", dir);
        h = CreateFileA(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        CHECK(h != INVALID_HANDLE_VALUE, "probe file");
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
        snprintf(params, sizeof(params), "%s", dir);
        run_task(a, "ls", params, &resp, &output, &exit_now);
        CHECK(strcmp(resp.status, "success") == 0, "ls status %s", resp.status);
        CHECK(resp.user_output && strstr(resp.user_output, "probe.txt") != NULL, "ls output");
        free(output);
        output = NULL;
        DeleteFileA(file);
        RemoveDirectoryA(dir);
    }
}

int main(void) {
    agent_t a;
    memset(&a, 0, sizeof(a));
    test_command_in_list();
    test_exit_unknown(&a);
    test_sleep(&a);
    test_shell(&a);
    test_ls(&a);
    if (failures == 0)
        printf("tasks: all pass\n");
    return failures != 0;
}
