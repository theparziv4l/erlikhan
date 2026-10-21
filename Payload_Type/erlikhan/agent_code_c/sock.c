#include "common.h"
#include "sock.h"

static int startup(void) {
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa);
}

static int dial(const char *host, const char *port, int type, int recv_ms, int send_ms, SOCKET *out) {
    struct addrinfo hints, *list = NULL, *ai;
    SOCKET s = INVALID_SOCKET;
    int rc = -1;
    *out = INVALID_SOCKET;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = type;
    hints.ai_family = AF_UNSPEC;
    if (startup() != 0)
        return -1;
    if (getaddrinfo(host, port, &hints, &list) != 0)
        goto done;
    for (ai = list; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s == INVALID_SOCKET)
            continue;
        if (connect(s, ai->ai_addr, (int)ai->ai_addrlen) == 0)
            break;
        closesocket(s);
        s = INVALID_SOCKET;
    }
    if (s == INVALID_SOCKET)
        goto done;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&recv_ms, sizeof(recv_ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&send_ms, sizeof(send_ms));
    *out = s;
    rc = 0;
done:
    if (list)
        freeaddrinfo(list);
    if (rc != 0) {
        if (s != INVALID_SOCKET)
            closesocket(s);
        WSACleanup();
    }
    return rc;
}

int sock_tcp(const char *host, const char *port, SOCKET *out) {
    return dial(host, port, SOCK_STREAM, 30000, 15000, out);
}

int sock_udp(const char *host, const char *port, SOCKET *out) {
    return dial(host, port, SOCK_DGRAM, 5000, 5000, out);
}

int sock_send_all(SOCKET s, const unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = send(s, (const char *)buf + off, (int)(len - off), 0);
        if (n <= 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

int sock_recv_all(SOCKET s, unsigned char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = recv(s, (char *)buf + off, (int)(len - off), 0);
        if (n <= 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

void sock_close(SOCKET s) {
    if (s != INVALID_SOCKET)
        closesocket(s);
    WSACleanup();
}
