#ifndef ERLIKHAN_EXECASM_H
#define ERLIKHAN_EXECASM_H

/*
 * Execute a staged .NET assembly in-process via CLR hosting, capturing
 * stdout/stderr. Returns 0 with *out = malloc'd output (maybe empty),
 * or -1 with *out = malloc'd "error: ..." text. Caller frees *out.
 */
int execasm_run(const char *path, const char *argstring, char **out);

#endif
