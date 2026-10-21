#ifndef ERLIKHAN_TASKS_H
#define ERLIKHAN_TASKS_H

#include "mythic.h"

/*
 * Run one task. Fills resp (output malloc'd, caller frees) and sets *exit_now
 * when the agent must post then stop.
 */
int task_dispatch(agent_t *a, const task_t *t, response_t *resp, char **output, int *exit_now);

/* Sleep seconds with jitter percent (Thanatos shape). */
void task_sleep(int interval, int jitter);

#endif
