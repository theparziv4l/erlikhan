#ifndef ERLIK_DNS_H
#define ERLIK_DNS_H

#include "common.h"

typedef struct {
    unsigned session;
    int idx;
    int fails;
} dns_state_t;

typedef struct {
    unsigned action, session, msgid, total, current;
    const unsigned char *data;
    size_t data_len;
} dns_pkt_t;

int dns_exchange(const agent_config_t *cfg, dns_state_t *st,
                 const unsigned char *sealed, size_t sealed_len,
                 unsigned char **out, size_t *out_len);

/* Exported for tests. */
int dns_marshal(const dns_pkt_t *p, bytebuf_t *out);
int dns_unmarshal(const unsigned char *b, size_t n, dns_pkt_t *out, bytebuf_t *data_out);
char *b32_encode(const unsigned char *in, size_t len);
int dns_build_query(const agent_config_t *cfg, const char *domain,
                    const unsigned char *pkt, size_t pkt_len,
                    char *qname, size_t cap);

#endif
