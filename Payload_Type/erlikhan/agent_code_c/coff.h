#ifndef ERLIKHAN_COFF_H
#define ERLIKHAN_COFF_H

#include <stddef.h>

/*
 * Run a BOF relocatable object in-process: map sections, apply
 * relocations, resolve Beacon plus Win32 imports, and call
 * entry(args, argslen) on a worker thread with a timeout. args is the
 * packed buffer (u32LE total first), as the container sends it.
 *
 * Returns 0 with *out = malloc'd captured output (maybe empty), or -1
 * with *out = malloc'd "error: ..." text. Caller frees *out.
 */
int coff_run(const unsigned char *obj, size_t objlen, const char *entry,
             const unsigned char *args, size_t argslen, int timeout_sec,
             char **out);

#endif
