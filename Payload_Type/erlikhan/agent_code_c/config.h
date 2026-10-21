#ifndef ERLIKHAN_CONFIG_H
#define ERLIKHAN_CONFIG_H

#include "common.h"

/* Build-time config blob, injected via -D defines (hex strings). */
#ifndef CFG_BLOB
#define CFG_BLOB ""
#endif
#ifndef CFG_KEY
#define CFG_KEY ""
#endif
#ifndef CFG_NONCE
#define CFG_NONCE ""
#endif
/* Comma-separated command set selected for this payload. Empty allows all. */
#ifndef CFG_COMMANDS
#define CFG_COMMANDS ""
#endif

int config_load(agent_config_t *out);

#endif
