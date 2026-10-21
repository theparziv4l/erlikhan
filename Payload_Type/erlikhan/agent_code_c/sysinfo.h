#ifndef ERLIKHAN_SYSINFO_H
#define ERLIKHAN_SYSINFO_H

#include "common.h"
#include "cJSON.h"

/* Attach checkin host fields to a cJSON object. Never fails. */
void sysinfo_attach(cJSON *obj);

/* Individual host fields for the whoami/ipconfig tasks. Never fail. */
void sysinfo_user(char *buf, size_t cap);
void sysinfo_host(char *buf, size_t cap);
void sysinfo_ips(char *buf, size_t cap);

#endif
