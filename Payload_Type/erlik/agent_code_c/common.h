#ifndef ERLIK_COMMON_H
#define ERLIK_COMMON_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ERLIK_UUID_LEN 36
#define ERLIK_MAX_HEADERS 8

typedef struct {
    char name[128];
    char value[512];
} http_header_t;

typedef struct {
    char payload_uuid[64];
    char callback_host[256];
    int callback_port;
    int interval;
    int jitter;
    char post_uri[128];
    http_header_t headers[ERLIK_MAX_HEADERS];
    int header_count;
    char proxy_host[256];
    char proxy_port[16];
    char proxy_user[128];
    char proxy_pass[128];
    char killdate[16];
    char crypto[16];
    char psk_b64[128];
    int retries;
    int tasking_size;
    char profile[16];
    /* mqtt */
    char mqtt_server[256];
    char mqtt_port[16];
    char mqtt_use_ssl[8];
    char mqtt_client[64];
    char mqtt_user[128];
    char mqtt_pass[128];
    char mqtt_topic[128];
    char mqtt_mythic[16];
    char mqtt_taskcheck[16];
    /* dns */
    char dns_domains[4][256];
    int dns_domain_count;
    char dns_rotation[16];
    int dns_failover;
    char dns_server[64];
    char dns_record[8];
    int dns_max_query;
    int dns_max_sub;
    /* msteams */
    char teams_tenant[64];
    char teams_client[64];
    char teams_secret[256];
    char teams_team[128];
    char teams_channel[128];
    char teams_webhook[512];
    char teams_ua[256];
} agent_config_t;

typedef struct {
    unsigned char *data;
    size_t len;
} bytebuf_t;

static void __attribute__((unused)) bytebuf_free(bytebuf_t *b) {
    if (b && b->data) {
        SecureZeroMemory(b->data, b->len);
        free(b->data);
        b->data = NULL;
        b->len = 0;
    }
}

#endif
