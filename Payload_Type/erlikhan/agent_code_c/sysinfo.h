#ifndef ERLIKHAN_SYSINFO_H
#define ERLIKHAN_SYSINFO_H

#include "common.h"
#include "cJSON.h"

/* Attach checkin host fields to a cJSON object. Never fails. */
void sysinfo_attach(cJSON *obj);

#endif
