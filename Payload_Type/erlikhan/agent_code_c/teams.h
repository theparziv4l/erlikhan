#ifndef ERLIKHAN_TEAMS_H
#define ERLIKHAN_TEAMS_H

#include "common.h"

typedef struct {
    char token[2200];
    unsigned long long expiry; /* GetTickCount64 ms */
} teams_state_t;

/* Base URLs (server defaults); tests override. Path prefix included. */
extern char teams_graph_base[160];
extern char teams_login_base[160];

int teams_exchange(const agent_config_t *cfg, teams_state_t *st,
                   const unsigned char *sealed, size_t sealed_len,
                   unsigned char **out, size_t *out_len);

/* Exported for tests. */
char *teams_form_encode(const char *s);
char *teams_card_json(const char *body);

#endif
