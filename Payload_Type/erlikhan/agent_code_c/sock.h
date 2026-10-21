#ifndef ERLIKHAN_SOCK_H
#define ERLIKHAN_SOCK_H

#include "common.h"
#include <winsock2.h>
#include <ws2tcpip.h>

/* TCP connect with timeouts set. Returns 0, caller closes via sock_close. */
int sock_tcp(const char *host, const char *port, SOCKET *out);

/* UDP "connect" (default remote) with 5s timeouts. */
int sock_udp(const char *host, const char *port, SOCKET *out);

int sock_send_all(SOCKET s, const unsigned char *buf, size_t len);
int sock_recv_all(SOCKET s, unsigned char *buf, size_t len);
void sock_close(SOCKET s);

#endif
