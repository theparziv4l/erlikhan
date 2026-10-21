#ifndef ERLIK_CONFIG_H
#define ERLIK_CONFIG_H

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

int config_load(agent_config_t *out);

#endif
